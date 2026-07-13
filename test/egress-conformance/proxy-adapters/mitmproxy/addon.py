"""Bounded Stage 1 mitmproxy adapter addon; policy and audit dependencies remain external."""

import asyncio
import json
import time
import urllib.error
import urllib.request
from mitmproxy import ctx, http

ID_KEYS = {"version", "case_id", "session_id", "authorization_origin", "routes"}
ROUTE_KEYS = {"id", "protocol", "host", "port", "methods", "pathPrefix", "credential"}
CREDENTIAL_KEYS = {"kind", "value", "header"}


class CogsPolicy:
    def __init__(self):
        self.policy = None
        self.capabilities = {}
        self.pending = {}

    def load(self, loader):
        loader.add_option("cogs_policy", str, "", "immutable Cogs policy path")

    def running(self):
        path = ctx.options.cogs_policy
        if not path:
            raise RuntimeError("cogs_policy is required")
        with open(path, "r", encoding="utf-8") as source:
            value = json.load(source)
        if set(value) != ID_KEYS or value["version"] != "cogs.mitmproxy-policy/v1alpha1":
            raise RuntimeError("policy envelope is invalid")
        for route in value["routes"]:
            if set(route) != ROUTE_KEYS or set(route["credential"]) not in (CREDENTIAL_KEYS, CREDENTIAL_KEYS - {"header"}):
                raise RuntimeError("policy route is invalid")
        self.policy = value

    async def _request(self, path, headers=None, body=None):
        origin = self.policy["authorization_origin"]
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(
            origin + path,
            data=data,
            method="POST" if body is not None else "GET",
            headers={"cache-control": "no-store", **(headers or {}), **({"content-type": "application/json"} if body is not None else {})},
        )
        def call():
            try:
                with urllib.request.urlopen(request, timeout=3) as response:
                    return response.status, dict(response.headers.items()), response.read(8193)
            except urllib.error.HTTPError as error:
                return error.code, dict(error.headers.items()), error.read(8193)
        return await asyncio.to_thread(call)

    def _deny(self, flow, status=403):
        flow.response = http.Response.make(status, b"", {"cache-control": "no-store", "content-length": "0"})

    async def http_connect(self, flow: http.HTTPFlow):
        capability = flow.request.headers.get("proxy-authorization")
        flow.request.headers.pop("proxy-authorization", None)
        if capability is None or len(capability) > 8192:
            self._deny(flow, 407)
            return
        try:
            status, _, _ = await self._request("/v1/envoy/capability", {"proxy-authorization": capability})
        except Exception:
            self._deny(flow, 503)
            return
        if status != 200:
            self._deny(flow, 407)
            return
        self.capabilities[str(flow.client_conn.id)] = (
            capability,
            flow.request.host.lower(),
            flow.request.port,
        )

    def client_disconnected(self, client):
        self.capabilities.pop(str(client.id), None)

    def _route(self, flow, connection):
        path = flow.request.path
        host = flow.request.host.lower()
        sni = (flow.client_conn.sni or "").lower()
        if (
            self.policy is None
            or flow.request.scheme != "https"
            or any(character in path for character in ("?", "#", "\\", "%"))
            or "//" in path
            or any(part in (".", "..") for part in path.split("/"))
            or connection[1] != host
            or connection[2] != flow.request.port
            or (sni and sni != host)
        ):
            return None
        for route in self.policy["routes"]:
            if (
                route["host"] == host
                and route["port"] == flow.request.port
                and flow.request.method in route["methods"]
                and flow.request.path.startswith(route["pathPrefix"])
            ):
                return route
        return None

    async def requestheaders(self, flow: http.HTTPFlow):
        if flow.request.method == "CONNECT":
            return
        connection = self.capabilities.get(str(flow.client_conn.id))
        if connection is None:
            self._deny(flow)
            return
        route = self._route(flow, connection)
        if route is None:
            self._deny(flow)
            return
        capability = connection[0]
        headers = {
            "proxy-authorization": capability,
            "x-cogs-require-capability": "true",
            "x-cogs-case-id": self.policy["case_id"],
            "x-cogs-session-id": self.policy["session_id"],
            "x-cogs-route-id": route["id"],
            "x-cogs-credential-required": "true",
        }
        try:
            status, response_headers, body = await self._request("/v1/envoy/authorize", headers)
        except Exception:
            self._deny(flow, 503)
            return
        intent = response_headers.get("x-cogs-intent-id") or response_headers.get("X-Cogs-Intent-Id")
        if status != 200 or len(body) > 8192 or not intent:
            self._deny(flow, 503 if status >= 500 else 403)
            return
        credential = route["credential"]
        flow.request.headers.pop("authorization", None)
        flow.request.headers.pop("proxy-authorization", None)
        name = "authorization" if credential["kind"] in ("bearer", "basic") else credential["header"]
        flow.request.headers[name] = credential["value"]
        self.pending[flow.id] = (intent, route["id"], time.monotonic())

    async def response(self, flow: http.HTTPFlow):
        pending = self.pending.pop(flow.id, None)
        if pending is None:
            return
        intent, route_id, started = pending
        duration = min(300000, max(0, int((time.monotonic() - started) * 1000)))
        status = flow.response.status_code
        completion = {
            "intent_id": intent,
            "outcome": "success" if 200 <= status < 400 else "failed",
            "status_class": status // 100,
            "latency_ms": duration,
        }
        try:
            completion_status, _, _ = await self._request("/v1/complete", body=completion)
        except Exception:
            completion_status = 503
        print(json.dumps({
            "event": "request-complete",
            "intent_id": intent,
            "route_id": route_id,
            "response_code": status,
            "duration_ms": duration,
            "completion_recorded": completion_status == 200,
        }, separators=(",", ":")), flush=True)


addons = [CogsPolicy()]

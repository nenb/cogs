#!/usr/bin/env python3
"""Guest-root black-box proxy probe. Emits bounded booleans and never response content."""

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

RAW_DETAIL = "none"
CLIENT_DETAIL = "none"


def emit(passed, code):
    print(json.dumps({"passed": bool(passed), "diagnosticsRedacted": code}, separators=(",", ":")))
    raise SystemExit(0)


def valid_inputs(values):
    scenario, kind, proxy_host, proxy_port, target_port, capability, expected = values
    return (
        scenario.replace("-", "").replace(".", "").isalnum()
        and kind in ("https", "redirect", "raw-http1", "raw-http2", "fault", "revocation", "confidentiality", "bypass", "client")
        and proxy_host in ("host.docker.internal", "192.0.2.1")
        and proxy_port.isdigit()
        and target_port.isdigit()
        and 1 <= int(proxy_port) <= 65535
        and 1 <= int(target_port) <= 65535
        and 0 <= len(capability) <= 256
        and re.fullmatch(r"(?:[A-Za-z0-9._-]*|Basic [A-Za-z0-9+/=]{8,})", capability) is not None
        and expected in ("allow", "deny", "safe")
    )


def curl_probe(scenario, proxy, port, capability):
    path = "/protected/header"
    host = "localhost"
    target_port = port
    method = "GET"
    follow = False
    proxy_header = capability
    extra = ["--header", "Authorization: Bearer cogs-non-secret-placeholder"]
    if scenario == "capability-missing":
        proxy_header = ""
    elif scenario in ("capability-malformed", "capability-expired", "capability-other-session"):
        proxy_header = capability
    elif scenario == "undeclared-host":
        host, target_port = "undeclared.invalid", 443
    elif scenario == "direct-destination-ip":
        host = "127.0.0.1"
    elif scenario == "alternate-port":
        target_port = port + 1 if port < 65535 else port - 1
    elif scenario == "wrong-method":
        method = "POST"
    elif scenario == "wrong-path":
        path = "/not-declared"
    elif scenario == "encoded-slash-dot":
        path = "/protected%2f..%2fheader"
    elif scenario == "traversal":
        path = "/protected/../header"
    elif scenario == "redirect-undeclared":
        path, follow = "/redirect", True
    elif scenario == "query-declared":
        path = "/protected/header?a=1&b=2"
    elif scenario == "query-missing":
        path = "/protected/header"
    elif scenario == "query-wrong":
        path = "/protected/header?a=1&b=3"
    elif scenario == "query-duplicate":
        path = "/protected/header?a=1&a=1&b=2"
    elif scenario == "query-reordered":
        path = "/protected/header?b=2&a=1"
    elif scenario == "query-encoded":
        path = "/protected/header?a=%31&b=2"
    elif scenario == "api-key":
        path = "/protected/api-key"
    elif scenario == "basic":
        path = "/protected/basic"
    elif scenario == "telemetry-outage":
        path = "/large"
    elif scenario == "long-lived-drain":
        path = "/delayed"
    elif scenario == "authorization-stripped":
        extra = [
            "--header",
            "Authorization: Bearer guest-one",
            "--header",
            "Authorization: Bearer guest-two",
        ]
    output = tempfile.NamedTemporaryFile(delete=False)
    output.close()
    command = [
        "curl", "--silent", "--show-error", "--output", output.name, "--write-out", "%{http_code}",
        "--max-time", "12", "--connect-timeout", "4", "--noproxy", "", "--proxy", proxy,
        "--cacert", os.environ["SSL_CERT_FILE"], "--request", method, "--path-as-is", *extra,
    ]
    if proxy_header:
        command += ["--proxy-header", "Proxy-Authorization: " + proxy_header]
    if follow:
        command += ["--location", "--max-redirs", "2"]
    command += [f"https://{host}:{target_port}{path}"]
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
        status = completed.stdout.decode("ascii", "ignore")[-3:]
        size = os.path.getsize(output.name)
        return completed.returncode == 0 and status == "200" and (
            size == 2 or scenario in ("telemetry-outage", "long-lived-drain")
        )
    finally:
        os.unlink(output.name)


def receive_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data and len(data) <= 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def connect_tls(
    proxy_host,
    proxy_port,
    target_port,
    capability,
    connect_host="localhost",
    connect_header_host=None,
    sni="localhost",
    alpn="http/1.1",
):
    raw = socket.create_connection((proxy_host, proxy_port), timeout=5)
    authority = f"{connect_host}:{target_port}"
    header_authority = f"{connect_header_host or connect_host}:{target_port}"
    request = (
        f"CONNECT {authority} HTTP/1.1\r\nHost: {header_authority}\r\n"
        f"Proxy-Authorization: {capability}\r\nConnection: keep-alive\r\n\r\n"
    ).encode()
    raw.sendall(request)
    response = receive_headers(raw)
    if not response.startswith(b"HTTP/1.1 200"):
        raw.close()
        return None
    context = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
    context.set_alpn_protocols([alpn])
    return context.wrap_socket(raw, server_hostname=sni)


def raw_http1(scenario, proxy_host, proxy_port, target_port, capability):
    global RAW_DETAIL
    if scenario == "origin-form-to-proxy":
        raw = socket.create_connection((proxy_host, proxy_port), timeout=5)
        raw.sendall((
            f"GET /protected/header HTTP/1.1\r\nHost: localhost:{target_port}\r\n"
            f"Proxy-Authorization: {capability}\r\n\r\n"
        ).encode())
        response = receive_headers(raw)
        raw.close()
        return b" 200 " in response.split(b"\r\n", 1)[0]
    if scenario == "duplicate-proxy-authorization":
        raw = socket.create_connection((proxy_host, proxy_port), timeout=5)
        authority = f"localhost:{target_port}"
        raw.sendall((
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
            f"Proxy-Authorization: {capability}\r\nProxy-Authorization: wrong-capability-value\r\n\r\n"
        ).encode())
        response = receive_headers(raw)
        raw.close()
        return response.startswith(b"HTTP/1.1 200")
    connect_host = "localhost"
    connect_header_host = "localhost"
    sni = "localhost"
    if scenario == "connect-host-mismatch":
        connect_header_host = "127.0.0.1"
    elif scenario == "connect-host-reverse-mismatch":
        connect_host = "127.0.0.1"
    if scenario == "sni-host-mismatch":
        sni = "undeclared.invalid"
    try:
        tls = connect_tls(
            proxy_host,
            proxy_port,
            target_port,
            capability,
            connect_host,
            connect_header_host,
            sni,
        )
    except (OSError, ssl.SSLError) as error:
        RAW_DETAIL = f"tls-{error.__class__.__name__.lower()}"
        return False
    if tls is None:
        RAW_DETAIL = "connect-denied"
        return False
    host = f"localhost:{target_port}"
    path = "/protected/header"
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer placeholder\r\nConnection: close\r\n\r\n"
    if scenario == "inner-host-mismatch":
        request = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nConnection: close\r\n\r\n"
    elif scenario == "valid":
        pass
    elif scenario == "absolute-form":
        request = f"GET https://localhost:{target_port}{path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    elif scenario == "cl-te-conflict":
        request = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    elif scenario == "duplicate-host":
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nHost: undeclared.invalid\r\n\r\n"
    elif scenario == "duplicate-authorization":
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: one\r\nAuthorization: two\r\n\r\n"
    elif scenario == "ambiguous-whitespace":
        request = f"GET  {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    elif scenario == "obs-fold":
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Fold: one\r\n two\r\n\r\n"
    elif scenario == "oversized-header":
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Large: " + ("a" * 70000) + "\r\n\r\n"
    elif scenario == "oversized-request-line":
        request = "GET /" + ("a" * 70000) + f" HTTP/1.1\r\nHost: {host}\r\n\r\n"
    elif scenario == "invalid-chunk-size":
        request = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nx\r\n0\r\n\r\n"
    elif scenario == "invalid-chunk-extension":
        request = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n1;bad=\"unterminated\r\nx\r\n0\r\n\r\n"
    elif scenario == "path-normalization":
        request = f"GET /protected/%2e%2e/header HTTP/1.1\r\nHost: {host}\r\n\r\n"
    tls.sendall(request.encode())
    try:
        response = receive_headers(tls)
    except OSError:
        response = b""
    tls.close()
    allowed = b" 200 " in response.split(b"\r\n", 1)[0]
    RAW_DETAIL = "upstream-allowed" if allowed else "inner-denied"
    return allowed


def hpack_integer(value, prefix, first):
    maximum = (1 << prefix) - 1
    if value < maximum:
        return bytes([first | value])
    output = bytearray([first | maximum])
    value -= maximum
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def hpack_string(value):
    encoded = value.encode()
    return hpack_integer(len(encoded), 7, 0) + encoded


def hpack_literal_indexed_name(index, value):
    return hpack_integer(index, 4, 0) + hpack_string(value)


def hpack_literal_name(name, value):
    return b"\x00" + hpack_string(name) + hpack_string(value)


def h2_frame(frame_type, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([frame_type, flags]) + struct.pack(">I", stream & 0x7fffffff) + payload


def raw_http2(scenario, proxy_host, proxy_port, target_port, capability):
    try:
        tls = connect_tls(proxy_host, proxy_port, target_port, capability, alpn="h2")
    except (OSError, ssl.SSLError):
        return False
    if tls is None or tls.selected_alpn_protocol() != "h2":
        if tls:
            tls.close()
        return False
    authority = f"localhost:{target_port}"
    headers = [b"\x82", b"\x87", hpack_literal_indexed_name(1, authority), hpack_literal_indexed_name(4, "/protected/header")]
    if scenario == "authority-mismatch":
        headers[2] = hpack_literal_indexed_name(1, f"127.0.0.1:{target_port}")
    elif scenario == "duplicate-pseudo":
        headers.insert(1, b"\x82")
    elif scenario == "reordered-pseudo":
        headers.insert(2, hpack_literal_name("x-before-pseudo", "one"))
    elif scenario == "invalid-pseudo":
        headers.insert(1, b"\x88")
    elif scenario == "downgrade-ambiguity":
        headers += [hpack_literal_name("content-length", "4"), hpack_literal_name("transfer-encoding", "chunked")]
    block = b"".join(headers)
    tls.settimeout(5)
    try:
        tls.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4, 0, 0) + h2_frame(1, 5, 1, block))
        allowed = False
        for _ in range(12):
            header = tls.recv(9)
            if len(header) < 9:
                break
            length = int.from_bytes(header[:3], "big")
            frame_type, stream = header[3], int.from_bytes(header[5:], "big") & 0x7fffffff
            payload = b""
            while len(payload) < length:
                chunk = tls.recv(length - len(payload))
                if not chunk:
                    break
                payload += chunk
            if frame_type == 1 and stream == 1 and b"\x88" in payload:
                allowed = True
                break
            if frame_type in (3, 7):
                break
        return allowed
    except OSError:
        return False
    finally:
        tls.close()


def bypass_probe(scenario, proxy_host, proxy_port, target_port, capability):
    # Historical absence-only observations are not enforcement evidence. Network
    # cases now require the trusted disposable controller below; never contact
    # public DNS, metadata, or a possibly absent listener from this legacy path.
    if scenario not in ("proxy-admin", "nested-connect", "websocket"):
        raise ValueError("causal network controller required")
    def tcp(host, port):
        try:
            connection = socket.create_connection((host, port), timeout=2)
            connection.close()
            return True
        except OSError:
            return False
    if scenario in ("unset-proxy", "direct-ipv4"):
        return tcp("192.0.2.1", target_port)
    if scenario == "direct-ipv6":
        return tcp("2001:db8::1", 443)
    if scenario == "arbitrary-dns":
        try:
            subprocess.run(["getent", "ahostsv4", "example.com"], timeout=3, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except (subprocess.SubprocessError, OSError):
            return False
    if scenario == "dns-over-https":
        return tcp("1.1.1.1", 443)
    if scenario == "udp-quic":
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(2)
        try:
            udp.sendto(b"cogs-denial-probe", ("192.0.2.1", 443))
            udp.recvfrom(64)
            return True
        except OSError:
            return False
        finally:
            udp.close()
    if scenario in ("alternate-tcp", "cogs-api", "openbao"):
        return tcp("192.0.2.1", {"alternate-tcp": 22, "cogs-api": 8080, "openbao": 8200}[scenario])
    if scenario == "openbao-actual":
        return tcp("192.0.2.1", target_port)
    if scenario == "cloud-metadata":
        return tcp("169.254.169.254", 80)
    if scenario == "proxy-admin":
        raw = socket.create_connection((proxy_host, proxy_port), timeout=3)
        raw.sendall(b"GET /config_dump HTTP/1.1\r\nHost: 192.0.2.1\r\nConnection: close\r\n\r\n")
        response = receive_headers(raw)
        raw.close()
        return b" 200 " in response.split(b"\r\n", 1)[0]
    if scenario in ("nested-connect", "websocket"):
        try:
            tls = connect_tls(proxy_host, proxy_port, target_port, capability)
        except (OSError, ssl.SSLError):
            return False
        if tls is None:
            return False
        host = f"localhost:{target_port}"
        if scenario == "nested-connect":
            request = f"CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n"
            forbidden_status = b" 200 "
        else:
            request = f"GET /protected/header HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            forbidden_status = b" 101 "
        tls.sendall(request.encode())
        response = receive_headers(tls)
        tls.close()
        return forbidden_status in response.split(b"\r\n", 1)[0]
    return False


def client_probe(scenario, proxy_host, proxy_port, target_port, capability):
    global CLIENT_DETAIL
    if not capability.startswith("Basic "):
        return False
    try:
        user, password = base64.b64decode(capability[6:], validate=True).decode().split(":", 1)
    except (ValueError, UnicodeError):
        return False
    proxy = f"http://{user}:{password}@{proxy_host}:{proxy_port}"
    ca = os.environ["SSL_CERT_FILE"]
    path = {
        "git-smart-http": "/clients/repo.git",
        "pip-wheel": "/clients/cogs_fixture-1.0.0-py3-none-any.whl",
        "npm-tarball": "/clients/cogs-fixture-1.0.0.tgz",
    }.get(scenario, "/clients/ok")
    target = f"https://localhost:{target_port}{path}"
    environment = {
        **os.environ,
        "HTTPS_PROXY": proxy,
        "HTTP_PROXY": proxy,
        "https_proxy": proxy,
        "http_proxy": proxy,
        "NO_PROXY": "",
        "no_proxy": "",
    }
    temporary = tempfile.mkdtemp(prefix="cogs-client-")
    npm_version = ""
    try:
        if scenario in ("curl", "http2"):
            command = ["curl", "--silent", "--show-error", "--fail", "--output", os.devnull, "--max-time", "15", "--noproxy", "", "--proxy", f"http://{proxy_host}:{proxy_port}", "--proxy-header", f"Proxy-Authorization: {capability}", "--cacert", ca]
            if scenario == "http2":
                command.append("--http2")
            command.append(target)
        elif scenario == "git-smart-http":
            command = [
                "git", "-c", f"http.proxy={proxy}", "-c", "http.proxyAuthMethod=basic",
                "-c", f"http.sslCAInfo={ca}", "ls-remote", target,
            ]
        elif scenario == "pip-wheel":
            command = ["python3", "-m", "pip", "download", "--disable-pip-version-check", "--no-deps", "--dest", temporary, "--proxy", proxy, "--cert", ca, target]
        elif scenario == "npm-tarball":
            npm_version = subprocess.run(
                ["/bin/bash", "-o", "pipefail", "-c", "/usr/bin/npm --version 2>/dev/null | /usr/bin/head -c 65"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True, text=True
            ).stdout.strip()
            if re.fullmatch(r"[0-9]{1,10}(?:\.[0-9]{1,10}){1,3}", npm_version) is None:
                return False
            environment.update({
                "HOME": temporary,
                "npm_config_cache": os.path.join(temporary, ".npm"),
                "npm_config_proxy": proxy,
                "npm_config_https_proxy": proxy,
                "npm_config_cafile": ca,
            })
            command = [
                "npm", "--proxy", proxy, "--https-proxy", proxy, "--cafile", ca,
                "--ignore-scripts", "pack", target, "--pack-destination", temporary,
            ]
        elif scenario == "python-requests":
            command = ["python3", "-c", "import requests,sys; r=requests.get(sys.argv[1],proxies={'https':sys.argv[2]},verify=sys.argv[3],timeout=12); r.raise_for_status(); assert r.content==b'ok'", target, proxy, ca]
        elif scenario == "python-httpx":
            command = ["python3", "-c", "import httpx,sys; r=httpx.get(sys.argv[1],proxy=sys.argv[2],verify=sys.argv[3],timeout=12); r.raise_for_status(); assert r.content==b'ok'", target, proxy, ca]
        elif scenario == "java-http":
            source = os.path.join(temporary, "CogsClient.java")
            with open(source, "w", encoding="utf-8") as output:
                output.write("""
import java.io.*; import java.net.*; import java.net.http.*; import java.nio.file.*; import java.security.*; import java.security.cert.*; import javax.net.ssl.*;
class CogsClient { public static void main(String[] a) throws Exception {
  var cf=CertificateFactory.getInstance("X.509"); var cert=cf.generateCertificate(Files.newInputStream(Path.of(a[4])));
  var ks=KeyStore.getInstance(KeyStore.getDefaultType()); ks.load(null); ks.setCertificateEntry("cogs",cert);
  var tmf=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); tmf.init(ks);
  var ssl=SSLContext.getInstance("TLS"); ssl.init(null,tmf.getTrustManagers(),null);
  var auth=new Authenticator(){ protected PasswordAuthentication getPasswordAuthentication(){ return new PasswordAuthentication(a[2],a[3].toCharArray()); }};
  var client=HttpClient.newBuilder().sslContext(ssl).proxy(ProxySelector.of(new InetSocketAddress(a[0],Integer.parseInt(a[1])))).authenticator(auth).build();
  var response=client.send(HttpRequest.newBuilder(URI.create(a[5])).header("Proxy-Authorization",a[6]).GET().build(),HttpResponse.BodyHandlers.ofString());
  if(response.statusCode()!=200 || !response.body().equals("ok")) throw new RuntimeException("failed"); }}
""")
            command = [
                "java", "-Djdk.http.auth.tunneling.disabledSchemes=", "-Djdk.httpclient.allowRestrictedHeaders=proxy-authorization", source,
                proxy_host, str(proxy_port), user, password, ca, target, capability,
            ]
        elif scenario in ("node-https-native", "node-fetch-native"):
            script = (
                "require('https').get(process.argv[1],r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
                if scenario == "node-https-native"
                else "fetch(process.argv[1]).then(r=>process.exit(r.status===200?0:1)).catch(()=>process.exit(1))"
            )
            command = ["node", "-e", script, target]
        else:
            return False
        log_path = os.path.join(temporary, "client.log")
        with open(log_path, "wb") as log:
            completed = subprocess.run(command, env=environment, cwd=temporary, stdout=log, stderr=log, timeout=30, check=False)
        with open(log_path, "rb") as log:
            bounded = log.read(2048).decode("utf-8", "replace")
        if scenario == "npm-tarball" and completed.returncode != 0:
            npm_logs = os.path.join(temporary, ".npm", "_logs")
            try:
                latest = sorted(os.listdir(npm_logs))[-1]
                with open(os.path.join(npm_logs, latest), "rb") as npm_log:
                    bounded += " " + npm_log.read(2048).decode("utf-8", "replace")
            except (OSError, IndexError):
                pass
        succeeded = completed.returncode == 0
        if scenario == "npm-tarball" and succeeded:
            archives = [name for name in os.listdir(temporary) if name.endswith(".tgz")]
            artifact = b""
            if len(archives) == 1:
                with open(os.path.join(temporary, archives[0]), "rb") as source:
                    artifact = source.read(152)
            succeeded = len(artifact) == 151 and hashlib.sha256(artifact).hexdigest() == "a975e4b9ef8c048914f56aaba8b7f53bdccc481ab367c6554c4d54fa7a508870"
        for sensitive in (capability, password, proxy):
            bounded = bounded.replace(sensitive, "[REDACTED]")
        CLIENT_DETAIL = f"client-{'succeeded' if succeeded else 'failed'}" + (f":npm={npm_version}" if npm_version else "")
        return succeeded
    except (OSError, subprocess.SubprocessError) as error:
        CLIENT_DETAIL = f"execution-error={type(error).__name__}"
        return False
    finally:
        import shutil
        shutil.rmtree(temporary, ignore_errors=True)


def main():
    values = sys.argv[1:]
    try:
        if len(values) == 7 and values[5].startswith("b64."):
            values[5] = base64.b64decode(values[5][4:], validate=True).decode()
    except (ValueError, UnicodeError):
        emit(False, "invalid probe input")
    if len(values) != 7 or not valid_inputs(values):
        emit(False, "invalid probe input")
    scenario, kind, proxy_host, proxy_port_text, target_port_text, capability, expected = values
    proxy_port, target_port = int(proxy_port_text), int(target_port_text)
    proxy = f"http://{proxy_host}:{proxy_port}"
    try:
        if kind == "bypass":
            allowed = bypass_probe(scenario, proxy_host, proxy_port, target_port, capability)
        elif kind == "client":
            allowed = client_probe(scenario, proxy_host, proxy_port, target_port, capability)
        elif scenario in {
            "capability-valid", "capability-missing", "capability-malformed", "capability-expired",
            "capability-other-session", "allowed-host-port", "undeclared-host", "direct-destination-ip",
            "alternate-port", "wrong-method", "wrong-path", "encoded-slash-dot", "traversal",
            "redirect-undeclared", "query-declared", "query-missing", "query-wrong", "query-duplicate",
            "query-reordered", "query-encoded", "placeholder-preflight", "authorization-stripped", "bearer", "api-key",
            "basic", "intent-before-use", "completion-correlated", "telemetry-outage", "all-sinks",
            "central-metadata-only", "replacement-capability", "long-lived-drain",
        }:
            allowed = curl_probe(scenario, proxy, target_port, capability)
        elif kind == "raw-http2":
            allowed = raw_http2(scenario, proxy_host, proxy_port, target_port, capability)
        else:
            allowed = raw_http1(scenario, proxy_host, proxy_port, target_port, capability)
    except Exception:
        emit(False, "probe setup or execution failed; no denial evidence")
    if expected == "safe" and scenario == "connect-host-mismatch":
        passed = RAW_DETAIL in ("connect-denied", "inner-denied", "upstream-allowed")
    else:
        passed = (
            allowed or (kind == "raw-http1" and RAW_DETAIL == "inner-denied")
            if expected == "safe"
            else (allowed if expected == "allow" else not allowed)
        )
    actual = "allow" if allowed else "deny"
    detail = f" ({RAW_DETAIL})" if kind == "raw-http1" else (f" ({CLIENT_DETAIL})" if kind == "client" and (not passed or scenario == "npm-tarball") else "")
    emit(passed, f"scenario {scenario} expected={expected} actual={actual}{detail}")


# Narrow diagnostic contract: TCP nonce echo and raw UDP nonce echo, NOT TLS,
# DoH or QUIC. All command execution below occurs in newly created netns only.
CAUSAL_VERSION = "cogs.causal-network-diagnostic/v1"


def causal_valid(record):
    """Fail closed on missing readiness, mismatched tuple, or non-causal denial."""
    try:
        assert set(record) == {"version", "case", "tuple", "readiness", "trials", "cleanup", "authorizing"}
        assert record["version"] == CAUSAL_VERSION and record["authorizing"] is False
        assert record["cleanup"] is True
        assert record["readiness"] == {"listener": True, "client": True, "ca": "not-applicable-raw-echo"}
        assert record["case"] in {"input-tcp", "input-udp", "input-ipv6", "forward-tcp", "relay-local", "relay-source", "relay-interface"}
        target = record["tuple"]
        assert set(target) == {"source", "interface", "destination", "protocol", "port"}
        assert target["protocol"] in ("tcp", "udp") and 1 <= target["port"] <= 65535
        trials = record["trials"]
        assert len(trials) == 4
        assert len({t["nonce"] for t in trials}) == 4
        for trial, phase in zip(trials, ("baseline", "enforced", "removed", "restored")):
            assert set(trial) == {"phase", "tuple", "nonce", "attempted", "echo", "rule", "packets"}
            assert trial["phase"] == phase and trial["tuple"] == target
            assert re.fullmatch(r"[a-f0-9]{32}", trial["nonce"])
            assert trial["attempted"] is True
            if phase in ("enforced", "restored"):
                assert trial["echo"] is False
                assert trial["rule"] in ("input-deny", "forward-deny", "relay-exclusion", "ipv6-deny")
                assert type(trial["packets"]) is int and 1 <= trial["packets"] <= 100
            else:
                assert trial["echo"] is True and trial["rule"] == "none" and trial["packets"] == 0
        return True
    except (AssertionError, KeyError, TypeError, ValueError):
        return False


def mutation_parent():
    import signal
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "unexecuted-linux-root-required", "authorizing": False}))
        return 77
    # No sudo fallback and no mutation in this namespace. Child must start with
    # only loopback and prove a different namespace inode before any ip command.
    original = os.readlink("/proc/self/ns/net")
    child = subprocess.Popen(
        ["unshare", "--net", sys.executable, __file__, "--network-mutation-child", original],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    try:
        output, _ = child.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
        print(json.dumps({"status": "timeout-cleanup-uncertain", "authorizing": False}))
        return 1
    if child.returncode != 0 or len(output) > 65536:
        print(json.dumps({"status": "fixture-failed-cleanup-not-established", "authorizing": False}))
        return 1
    try:
        result = json.loads(output)
        assert len(result) == 7 and all(causal_valid(r) for r in result)
        # No live process in the child's owned group may retain its namespace.
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise ValueError("residue")
    except (ValueError, AssertionError, OSError):
        print(json.dumps({"status": "invalid-evidence-or-cleanup", "authorizing": False}))
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


def mutation_child(original):
    import pathlib
    import threading
    import time
    import uuid
    assert sys.platform == "linux" and os.geteuid() == 0
    assert os.readlink("/proc/self/ns/net") != original
    assert os.listdir("/sys/class/net") == ["lo"]
    peers, listeners, threads, records = [], [], [], []
    stop = threading.Event()

    def run(*command, data=None):
        return subprocess.run(command, input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, check=True, timeout=8).stdout

    def peer():
        process = subprocess.Popen(["unshare", "--net", sys.executable, "-c",
            "import time; time.sleep(160)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        peers.append(process)  # ownership before readiness
        for _ in range(100):
            assert process.poll() is None
            if os.readlink(f"/proc/{process.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                return process
            time.sleep(.01)
        raise RuntimeError("namespace readiness")

    def inside(process, *command):
        assert process.poll() is None
        return run("nsenter", "--net=" + f"/proc/{process.pid}/ns/net", *command)

    def link(process, host, host_address, guest_address):
        run("ip", "link", "add", host, "type", "veth", "peer", "name", "ethfixture")
        run("ip", "link", "set", "ethfixture", "netns", str(process.pid))
        run("ip", "addr", "add", host_address, "dev", host)
        run("ip", "link", "set", host, "up")
        inside(process, "ip", "link", "set", "lo", "up")
        inside(process, "ip", "addr", "add", guest_address, "dev", "ethfixture")
        inside(process, "ip", "link", "set", "ethfixture", "up")

    def listen(address, port, udp=False):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        server = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        listeners.append(server)
        server.bind((address, port)); server.settimeout(.1)
        if not udp:
            server.listen(8)
        def serve():
            while not stop.is_set():
                try:
                    if udp:
                        payload, source = server.recvfrom(64)
                        if re.fullmatch(b"[a-f0-9]{32}", payload): server.sendto(payload, source)
                    else:
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(.5)
                            payload = connection.recv(64)
                            if re.fullmatch(b"[a-f0-9]{32}", payload): connection.sendall(payload)
                except (OSError, TimeoutError):
                    pass
        thread = threading.Thread(target=serve)
        threads.append(thread); thread.start()

    client = '''import socket,sys,json
src,dst,port,proto,nonce=sys.argv[1:]
s=socket.socket(socket.AF_INET6 if ':' in dst else socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM)
s.settimeout(.7); s.bind((src,0)); attempted=False; echo=False
try:
 attempted=True
 if proto=='udp': s.sendto(nonce.encode(),(dst,int(port))); data=s.recv(64)
 else: s.connect((dst,int(port))); s.sendall(nonce.encode()); data=s.recv(64)
 echo=data==nonce.encode()
except (TimeoutError,ConnectionRefusedError): pass
finally: s.close()
print(json.dumps({'attempted':attempted,'echo':echo}))'''
    try:
        run("ip", "link", "set", "lo", "up")
        guest, attacker = peer(), peer()
        link(guest, "cgfixture", "192.0.2.1/30", "192.0.2.2/30")
        link(attacker, "cgother", "192.0.4.1/30", "192.0.4.2/30")
        inside(guest, "ip", "addr", "add", "192.0.2.3/32", "dev", "ethfixture")
        run("ip", "route", "replace", "192.0.2.3/32", "dev", "cgfixture")
        run("ip", "-6", "addr", "add", "fd00:42::1/64", "dev", "cgfixture", "nodad")
        inside(guest, "ip", "-6", "addr", "add", "fd00:42::2/64", "dev", "ethfixture", "nodad")
        inside(guest, "ip", "route", "add", "192.0.4.0/30", "via", "192.0.2.1")
        inside(attacker, "ip", "route", "add", "192.0.2.0/24", "via", "192.0.4.1")
        run("sysctl", "-qw", "net.ipv4.ip_forward=1")
        for interface in ("all", "default", "cgfixture", "cgother"):
            run("sysctl", "-qw", f"net.ipv4.conf.{interface}.rp_filter=0")
        listen("192.0.2.1", 18080); listen("192.0.2.1", 18081)
        listen("192.0.2.1", 18082, True); listen("fd00:42::1", 18083)
        # Forward endpoint is held by an exactly-owned process in the attacker
        # namespace; no uplink, NAT, public resolver or metadata service exists.
        echo_code = '''import socket
s=socket.socket(); s.bind(('192.0.4.2',18081)); s.listen(8)
print('ready',flush=True)
while True:
 c,_=s.accept()
 with c:
  c.settimeout(1)
  try: c.sendall(c.recv(64))
  except OSError: pass'''
        endpoint = subprocess.Popen(["nsenter", "--net=" + f"/proc/{attacker.pid}/ns/net",
            sys.executable, "-c", echo_code], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        peers.append(endpoint)
        import select
        assert select.select([endpoint.stdout], [], [], 3)[0]
        assert endpoint.stdout.readline() == b"ready\n"
        driver = pathlib.Path(__file__).resolve().parents[3] / "dev/linux-kvm/driver.sh"
        policy = run("bash", str(driver), "print-network-policy").decode()

        def install(phase, controls):
            # These flushes are ONLY in this newly-created enforcement namespace.
            run("iptables", "-F"); run("iptables", "-X")
            run("ip6tables", "-F"); run("ip6tables", "-X")
            if phase != "baseline":
                selected = policy
                if phase == "removed":
                    selected = "\n".join(line for line in policy.splitlines()
                        if not any("--comment " + control + " " in line for control in controls)) + "\n"
                run("iptables-restore", data=selected.encode())
                if not (phase == "removed" and "ipv6-deny" in controls):
                    run("ip6tables", "-I", "INPUT", "1", "-i", "cgfixture", "-m", "comment", "--comment", "ipv6-deny", "-j", "DROP")
            # A broad ambient established rule must never bypass earlier guards.
            run("iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")

        def packets(ipv6, rule):
            data = run("ip6tables-save" if ipv6 else "iptables-save", "-c").decode()
            return sum(int(m.group(1)) for line in data.splitlines()
                if "--comment " + rule in line
                for m in [re.match(r"\[(\d+):\d+\]", line)] if m)

        cases = [
            ("input-tcp", guest, "192.0.2.2", "cgfixture", "192.0.2.1", "tcp", 18081, "input-deny"),
            ("input-udp", guest, "192.0.2.2", "cgfixture", "192.0.2.1", "udp", 18082, "input-deny"),
            ("input-ipv6", guest, "fd00:42::2", "cgfixture", "fd00:42::1", "tcp", 18083, "ipv6-deny"),
            ("forward-tcp", guest, "192.0.2.2", "cgfixture", "192.0.4.2", "tcp", 18081, "forward-deny"),
            ("relay-local", None, "192.0.2.1", "lo", "192.0.2.1", "tcp", 18080, "relay-exclusion"),
            ("relay-source", guest, "192.0.2.3", "cgfixture", "192.0.2.1", "tcp", 18080, "relay-exclusion"),
            ("relay-interface", attacker, "192.0.2.2", "cgother", "192.0.2.1", "tcp", 18080, "relay-exclusion"),
        ]
        for name, process, source, interface, destination, protocol, port, rule in cases:
            if name == "relay-interface":
                inside(attacker, "ip", "addr", "add", "192.0.2.2/32", "dev", "ethfixture")
                run("ip", "route", "replace", "192.0.2.2/32", "dev", "cgother")
            target = dict(source=source, interface=interface, destination=destination, protocol=protocol, port=port)
            record = dict(version=CAUSAL_VERSION, case=name, tuple=target,
                readiness=dict(listener=True, client=True, ca="not-applicable-raw-echo"),
                trials=[], cleanup=False, authorizing=False)
            # Terminal input deny redundantly also denies relay callers. Remove
            # both for the effective exclusion mutation, not just one duplicate.
            controls = [rule, "input-deny"] if rule == "relay-exclusion" else [rule]
            for phase in ("baseline", "enforced", "removed", "restored"):
                install(phase, controls)
                nonce = uuid.uuid4().hex
                before = packets(":" in destination, rule)
                command = [sys.executable, "-c", client, source, destination, str(port), protocol, nonce]
                result = json.loads(inside(process, *command) if process else run(*command))
                after = packets(":" in destination, rule)
                denied = phase in ("enforced", "restored")
                record["trials"].append(dict(phase=phase, tuple=target, nonce=nonce,
                    attempted=result["attempted"], echo=result["echo"],
                    rule=rule if denied else "none", packets=after-before if denied else 0))
            records.append(record)
    finally:
        stop.set()
        for server in listeners: server.close()
        for thread in threads:
            thread.join(2)
            assert not thread.is_alive()
        for process in reversed(peers):
            if process.poll() is None: process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
            if process.stdout: process.stdout.close()
        # Deleting owned veths before exiting proves link retirement; namespace
        # exit then destroys all rules/routes. Failure prints no successful record.
        for interface in ("cgfixture", "cgother"):
            if interface in os.listdir("/sys/class/net"):
                run("ip", "link", "delete", interface)
        assert os.listdir("/sys/class/net") == ["lo"]
    for record in records:
        record["cleanup"] = True
        assert causal_valid(record)
    print(json.dumps(records, separators=(",", ":")))


if __name__ == "__main__":
    if sys.argv[1:] == ["--network-mutations"]:
        raise SystemExit(mutation_parent())
    if len(sys.argv) == 3 and sys.argv[1] == "--network-mutation-child":
        mutation_child(sys.argv[2])
    else:
        main()

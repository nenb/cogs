import assert from "node:assert/strict";
import { createConnection } from "node:net";
import test from "node:test";
import { Client, credentials } from "@grpc/grpc-js";
import type { FaultInjector } from "./server.ts";
import { startFaultInjector } from "./server.ts";

const originalCapability = "cogs-original-capability-value";
const replacementCapability = "cogs-replacement-capability-value";

async function post(origin: string, path: string, body: object, headers: Record<string, string> = {}) {
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

async function withInjector(run: (injector: FaultInjector) => Promise<void>, maxRecords?: number): Promise<void> {
  const injector = await startFaultInjector({
    initialCapability: originalCapability,
    ...(maxRecords ? { maxRecords } : {}),
  });
  try {
    await run(injector);
  } finally {
    await injector.stop();
  }
}

const authorization = {
  case_id: "audit.intent-before-use",
  session_id: "session-opaque",
  route_id: "route-allowed",
  credential_required: true,
};

test("authorization returns only after a correlated intent is recorded", async () => {
  await withInjector(async (injector) => {
    const authorized = await post(injector.origin, "/v1/authorize", authorization);
    assert.equal(authorized.status, 200);
    const snapshot = injector.snapshot();
    assert.equal(snapshot.intents.length, 1);
    assert.equal(snapshot.intents[0]?.intent_id, authorized.body.intent_id);
    assert.equal(snapshot.intents[0]?.completion, null);

    const completed = await post(injector.origin, "/v1/complete", {
      intent_id: authorized.body.intent_id,
      outcome: "success",
      status_class: 2,
      latency_ms: 17,
    });
    assert.equal(completed.status, 200);
    assert.deepEqual(injector.snapshot().intents[0]?.completion, {
      outcome: "success",
      status_class: 2,
      latency_ms: 17,
    });
  });
});

test("authorization and audit failures deny before creating an intent", async () => {
  await withInjector(async (injector) => {
    for (const fault of ["authorizationOutage", "auditUnwritable", "auditFull"] as const) {
      injector.setFaults({ [fault]: true });
      const denied = await post(injector.origin, "/v1/authorize", authorization);
      assert.equal(denied.status, 503);
      assert.equal(injector.snapshot().intents.length, 0);
      injector.setFaults({ [fault]: false });
    }
  });

  await withInjector(async (injector) => {
    assert.equal((await post(injector.origin, "/v1/authorize", authorization)).status, 200);
    assert.equal((await post(injector.origin, "/v1/authorize", authorization)).status, 503);
  }, 1);
});

test("completion failures remain correlated and recoverable", async () => {
  await withInjector(async (injector) => {
    const authorized = await post(injector.origin, "/v1/authorize", authorization);
    injector.setFaults({ completionFailure: true });
    assert.equal(
      (
        await post(injector.origin, "/v1/complete", {
          intent_id: authorized.body.intent_id,
          outcome: "failed",
          status_class: 5,
          latency_ms: 10,
        })
      ).status,
      503,
    );
    assert.equal(injector.snapshot().intents[0]?.completion, null);
  });
});

test("telemetry outage does not block an uncredentialed authorization intent", async () => {
  await withInjector(async (injector) => {
    injector.setFaults({ telemetryOutage: true });
    const authorized = await post(injector.origin, "/v1/authorize", {
      ...authorization,
      credential_required: false,
    });
    assert.equal(authorized.status, 200);
    assert.equal(authorized.body.telemetry_available, false);
    assert.equal(injector.snapshot().intents.length, 1);
  });
});

test("capability validation, deny-new, rotation, and drain never expose values", async () => {
  await withInjector(async (injector) => {
    const validate = (capability: string) =>
      post(injector.origin, "/v1/capability/validate", {}, { "proxy-authorization": capability });

    assert.equal((await validate(originalCapability)).status, 200);
    assert.equal((await validate("cogs-wrong-capability-value")).status, 403);
    injector.denyNew();
    assert.equal((await validate(originalCapability)).status, 403);

    injector.rotateCapability(replacementCapability);
    assert.equal((await validate(originalCapability)).status, 403);
    const replacement = await validate(replacementCapability);
    assert.equal(replacement.status, 200);
    assert.equal(replacement.body.action, "drain");
    assert.ok(Number(replacement.body.epoch) >= 3);

    const serialized = JSON.stringify({ snapshot: injector.snapshot(), response: replacement });
    for (const value of [originalCapability, replacementCapability, "cogs-wrong-capability-value"]) {
      assert.equal(serialized.includes(value), false);
    }
  });
});

test("Envoy HTTP authorization hooks validate capabilities and append redacted intents", async () => {
  await withInjector(async (injector) => {
    const origin = new URL(injector.origin);
    const connectResponse = await new Promise<string>((resolve, reject) => {
      const socket = createConnection(Number(origin.port), origin.hostname);
      let response = "";
      socket.setEncoding("utf8");
      socket.once("error", reject);
      socket.on("data", (chunk: string) => {
        response += chunk;
      });
      socket.once("end", () => resolve(response));
      socket.once("connect", () => {
        socket.write(
          `CONNECT /v1/envoy/capability HTTP/1.1\r\nHost: ${origin.host}\r\nProxy-Authorization: ${originalCapability}\r\nConnection: close\r\n\r\n`,
        );
      });
    });
    assert.match(connectResponse, /^HTTP\/1\.1 200 OK/);

    const denied = await fetch(`${injector.origin}/v1/envoy/capability`, {
      headers: { "proxy-authorization": "cogs-wrong-capability-value" },
    });
    assert.equal(denied.status, 403);

    const authorized = await fetch(`${injector.origin}/v1/envoy/authorize`, {
      headers: {
        "x-cogs-case-id": authorization.case_id,
        "x-cogs-session-id": authorization.session_id,
        "x-cogs-route-id": authorization.route_id,
        "x-cogs-credential-required": "true",
        "x-cogs-require-capability": "false",
        authorization: "must-not-be-retained",
      },
    });
    assert.equal(authorized.status, 200);
    const intentId = authorized.headers.get("x-cogs-intent-id");
    assert.ok(intentId);
    assert.equal(injector.snapshot().intents[0]?.intent_id, intentId);
    assert.equal(JSON.stringify(injector.snapshot()).includes("must-not-be-retained"), false);

    injector.denyNew();
    assert.equal(
      (
        await fetch(`${injector.origin}/v1/envoy/authorize`, {
          headers: {
            "x-cogs-case-id": authorization.case_id,
            "x-cogs-session-id": authorization.session_id,
            "x-cogs-route-id": authorization.route_id,
            "x-cogs-credential-required": "true",
            "x-cogs-require-capability": "false",
          },
        })
      ).status,
      403,
    );
  });
});

test("Envoy gRPC ext-authz validates capability context and returns opaque intent metadata", async () => {
  await withInjector(async (injector) => {
    const varint = (value: number) => {
      const bytes: number[] = [];
      let remaining = value;
      do {
        let byte = remaining & 0x7f;
        remaining >>>= 7;
        if (remaining > 0) byte |= 0x80;
        bytes.push(byte);
      } while (remaining > 0);
      return Buffer.from(bytes);
    };
    const message = (number: number, value: Buffer) =>
      Buffer.concat([varint((number << 3) | 2), varint(value.length), value]);
    const string = (number: number, value: string) => message(number, Buffer.from(value));
    const map = (number: number, values: Record<string, string>) =>
      Buffer.concat(
        Object.entries(values).map(([key, value]) =>
          message(number, Buffer.concat([string(1, key), string(2, value)])),
        ),
      );
    const request = (headers: Record<string, string>, context: Record<string, string>) => {
      const http = map(3, headers);
      const requestAttributes = message(2, http);
      const attributes = Buffer.concat([message(4, requestAttributes), map(10, context)]);
      return message(1, attributes);
    };
    const client = new Client(injector.grpcTarget, credentials.createInsecure());
    const check = (payload: Buffer) =>
      new Promise<Buffer>((resolve, reject) => {
        client.makeUnaryRequest(
          "/envoy.service.auth.v3.Authorization/Check",
          (value: Buffer) => value,
          (value: Buffer) => value,
          payload,
          (error, response) => {
            if (error) reject(error);
            else if (response === undefined) reject(new Error("gRPC check returned no response"));
            else resolve(response);
          },
        );
      });
    try {
      const denied = await check(
        request(
          { "proxy-authorization": "cogs-wrong-capability-value" },
          { "cogs.mode": "capability", "cogs.case_id": "case-grpc", "cogs.session_id": "session-grpc" },
        ),
      );
      const allowed = await check(
        request(
          { "proxy-authorization": originalCapability },
          { "cogs.mode": "capability", "cogs.case_id": "case-grpc", "cogs.session_id": "session-grpc" },
        ),
      );
      assert.notDeepEqual(denied, allowed);

      const authorized = await check(
        request(
          {},
          {
            "cogs.mode": "authorize",
            "cogs.case_id": authorization.case_id,
            "cogs.session_id": authorization.session_id,
            "cogs.route_id": authorization.route_id,
            "cogs.require_capability": "false",
            "cogs.credential_required": "true",
          },
        ),
      );
      assert.ok(authorized.includes(Buffer.from("x-cogs-intent-id")));
      assert.equal(injector.snapshot().intents.length, 1);
    } finally {
      client.close();
    }
  });
});

test("unknown fields, queries, duplicate completion, and oversized bodies fail closed", async () => {
  await withInjector(async (injector) => {
    const unknown = await post(injector.origin, "/v1/authorize", { ...authorization, credential: "not-accepted" });
    assert.equal(unknown.status, 400);
    const query = await post(injector.origin, "/v1/authorize?credential=not-logged", authorization);
    assert.equal(query.status, 400);

    const authorized = await post(injector.origin, "/v1/authorize", authorization);
    const completion = {
      intent_id: authorized.body.intent_id,
      outcome: "success",
      status_class: 2,
      latency_ms: 1,
    };
    assert.equal((await post(injector.origin, "/v1/complete", completion)).status, 200);
    assert.equal((await post(injector.origin, "/v1/complete", completion)).status, 400);

    const response = await fetch(`${injector.origin}/v1/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(40 * 1024) }),
    });
    assert.equal(response.status, 400);
  });
});

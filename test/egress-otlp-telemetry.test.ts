import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import {
  CogsEgressTelemetryError,
  type CogsEgressTelemetryEvent,
  createCogsEgressTelemetrySink,
} from "../src/egress/otlp-telemetry.ts";

const secret = "secret-token users/u/handle /path?query=secret";
const event = (patch: Partial<CogsEgressTelemetryEvent> = {}): CogsEgressTelemetryEvent =>
  Object.freeze({
    intent: Object.freeze({
      sequence: 7,
      intent_id: "intent-7",
      timestamp_ms: 10,
      session_id: "session",
      integration_id: "npm",
      route_id: "npm:npm-registry-metadata:GET:0",
      method: "GET",
      credential_required: true,
    }),
    completion: Object.freeze({
      intentId: "intent-7",
      sequence: 7,
      routeId: "npm:npm-registry-metadata:GET:0",
      responseCode: 200,
      durationMs: 12,
      completedAtMs: 30,
    }),
    ...patch,
  });

test("OTLP telemetry sink emits exact metadata-only batch envelope and counters", async () => {
  const bodies: unknown[] = [];
  const server = createServer((request, response) => {
    readBody(request, 65_536).then((body) => {
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/v1/logs");
      assert.equal(request.headers.authorization, undefined);
      bodies.push(JSON.parse(body));
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"partialSuccess":{"rejectedLogRecords":"0","errorMessage":""}}');
    });
  });
  await listen(server);
  const sink = sinkFor(server, { capacity: 20 });
  for (let index = 0; index < 17; index++)
    sink.enqueue(
      event({
        intent: { ...event().intent, sequence: index, intent_id: `intent-${index}` },
        completion: { ...event().completion, sequence: index, intentId: `intent-${index}` },
      }),
    );
  await eventually(() => assert.equal(sink.snapshot().exported, 17));
  assert.deepEqual(
    bodies.map((body) => logRecords(body).length),
    [16, 1],
  );
  const first = logRecords(bodies[0])[0] ?? assert.fail("missing log record");
  assert.equal(first.timeUnixNano, "30000000");
  assert.deepEqual(attributes(first), {
    "cogs.completed_lag_ms": "20",
    "cogs.credential_required": true,
    "cogs.duration_ms": "12",
    "cogs.event": "egress.complete",
    "cogs.integration_id": "npm",
    "cogs.intent_id": "intent-0",
    "cogs.intent_sequence": "0",
    "cogs.method": "GET",
    "cogs.route_id": "npm:npm-registry-metadata:GET:0",
    "cogs.session_id": "session",
    "cogs.status_class": "2",
  });
  assert.equal(JSON.stringify(bodies).includes(secret), false);
  assert.equal(JSON.stringify(sink.snapshot()).includes(secret), false);
  await sink.close();
  await close(server);
});

test("OTLP telemetry retry race, drop-newest, close, and stub lifecycle are bounded", async () => {
  let firstResponse: (() => void) | undefined;
  const seen: number[] = [];
  const server = createServer((request, response) => {
    readBody(request, 65_536).then((body) => {
      const count = logRecords(JSON.parse(body)).length;
      if (firstResponse === undefined) {
        firstResponse = () => {
          response.writeHead(503, { "content-type": "application/json" });
          response.end("{}");
        };
        return;
      }
      seen.push(count);
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    });
  });
  await listen(server);
  const sink = sinkFor(server, { capacity: 2, timeoutMs: 100 });
  sink.enqueue(event());
  await eventually(() => assert.equal(typeof firstResponse, "function"));
  sink.enqueue(
    event({
      intent: { ...event().intent, sequence: 8, intent_id: "intent-8" },
      completion: { ...event().completion, sequence: 8, intentId: "intent-8" },
    }),
  );
  firstResponse?.();
  await eventually(() => assert.deepEqual(seen, [2]));
  sink.enqueue(event({ completion: { ...event().completion, intentId: "other" } }));
  assert.equal(sink.snapshot().dropped, 1);
  await sink.close();
  await sink.close();
  assert.deepEqual(sink.snapshot(), { queued: 0, exported: 2, dropped: 1, failed: 1, depth: 0 });
  const stub = createCogsEgressTelemetrySink({ mode: "injected-stub-evidence" });
  assert.equal(stub.ready, true);
  stub.enqueue(event());
  assert.equal(stub.snapshot().dropped, 1);
  await stub.close();
  assert.equal(stub.ready, false);
  await close(server);
});

test("OTLP telemetry recovers preserved full-queue head after dropped enqueue activity", async () => {
  let fail = true;
  let exported = 0;
  const server = createServer((request, response) => {
    request.resume();
    if (fail) {
      response.writeHead(503, { "content-type": "application/json" });
      response.end("{}");
      return;
    }
    exported++;
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  await listen(server);
  const sink = sinkFor(server, { capacity: 1, timeoutMs: 100 });
  sink.enqueue(event());
  await eventually(() => assert.equal(sink.snapshot().failed, 1));
  fail = false;
  sink.enqueue(
    event({
      intent: { ...event().intent, intent_id: "intent-8", sequence: 8 },
      completion: { ...event().completion, intentId: "intent-8", sequence: 8 },
    }),
  );
  await eventually(() => assert.equal(exported, 1));
  assert.deepEqual(sink.snapshot(), { queued: 0, exported: 1, dropped: 1, failed: 1, depth: 0 });
  await sink.close();
  await close(server);
});

test("OTLP telemetry close aborts hanging response and is idempotent", async () => {
  let closed = false;
  const sockets = new Set<unknown>();
  const server = createServer((request, response) => {
    request.resume();
    response.writeHead(200, { "content-type": "application/json" });
    response.flushHeaders();
    response.on("close", () => {
      closed = true;
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await listen(server);
  const sink = sinkFor(server, { timeoutMs: 50 });
  sink.enqueue(event());
  await new Promise((resolve) => setTimeout(resolve, 25));
  const started = Date.now();
  await Promise.all([sink.close(), sink.close()]);
  assert.ok(Date.now() - started < 250);
  await eventually(() => assert.equal(closed, true));
  assert.equal(sink.ready, false);
  assert.equal(sink.snapshot().depth, 0);
  server.closeIdleConnections();
  await close(server);
  await eventually(() => assert.equal(sockets.size, 0));
});

test("OTLP telemetry rejects hostile endpoints, options, events, and responses generically", async () => {
  for (const config of [
    { mode: "otlp", endpoint: "http://example.com/v1/logs" },
    { mode: "otlp", endpoint: "http://127.0.0.1:0/v1/logs", allowLoopbackHttpDevelopment: true },
    { mode: "otlp", endpoint: "http://127.0.0.1:1/v1/logs?x=1", allowLoopbackHttpDevelopment: true },
    { mode: "otlp", endpoint: "http://u@127.0.0.1:1/v1/logs", allowLoopbackHttpDevelopment: true },
    { mode: "otlp", endpoint: "http://127.0.0.1:1/v1/logs", allowLoopbackHttpDevelopment: "true" },
    { mode: "otlp", endpoint: "http://127.0.0.1:1/v1/logs", allowLoopbackHttpDevelopment: true, capacity: "1" },
    { mode: "otlp", endpoint: "http://127.0.0.1:1/v1/logs", allowLoopbackHttpDevelopment: true, timeoutMs: "50" },
    { mode: "injected-stub-evidence", endpoint: "http://127.0.0.1:1/v1/logs" },
    accessor({ mode: "otlp", endpoint: "http://127.0.0.1:1/v1/logs" }, "mode"),
    hidden({ mode: "otlp", endpoint: "http://127.0.0.1:1/v1/logs" }),
    symbol({ mode: "otlp", endpoint: "http://127.0.0.1:1/v1/logs" }),
  ])
    assert.throws(() => createCogsEgressTelemetrySink(config as never), CogsEgressTelemetryError);

  const server = createServer((request, response) => {
    request.resume();
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  await listen(server);
  const sink = sinkFor(server);
  for (const bad of [
    { ...event(), extra: true },
    symbol(event()),
    accessor(event(), "intent"),
    event({ intent: { ...event().intent, method: "DELETE" as never } }),
    event({ completion: { ...event().completion, routeId: "other" } }),
    event({ completion: { ...event().completion, completedAtMs: 9 } }),
    event({ completion: { ...event().completion, completedAtMs: Number.MAX_SAFE_INTEGER + 1 } }),
    { intent: symbol(event().intent), completion: event().completion },
    { intent: accessor(event().intent, "intent_id"), completion: event().completion },
    { intent: { ...event().intent, extra: true }, completion: event().completion },
    { intent: event().intent, completion: symbol(event().completion) },
    { intent: event().intent, completion: accessor(event().completion, "intentId") },
    { intent: event().intent, completion: { ...event().completion, extra: true } },
  ])
    sink.enqueue(bad as never);
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.deepEqual(sink.snapshot(), { queued: 0, exported: 0, dropped: 13, failed: 0, depth: 0 });
  await sink.close();
  await close(server);

  for (const bad of [
    { status: 302, headers: { location: "/v1/logs", "content-type": "application/json" }, body: "{}" },
    { status: 200, headers: { "content-type": "text/plain" }, body: "{}" },
    { status: 200, headers: { "content-type": "application/json", "content-length": "999999" }, body: "{}" },
    { status: 200, headers: { "content-type": "application/json", "content-length": "nope" }, body: "{}" },
    { status: 200, headers: { "content-type": "application/json" }, body: `${"x".repeat(9000)}` },
    { status: 200, headers: { "content-type": "application/json" }, body: "{" },
    { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ extra: true }) },
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ partialSuccess: { extra: true } }),
    },
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ partialSuccess: { rejectedLogRecords: 1 } }),
    },
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ partialSuccess: { rejectedLogRecords: "1" } }),
    },
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ partialSuccess: { errorMessage: "x" } }),
    },
  ])
    await rejectsResponse(bad);
});

async function rejectsResponse(reply: {
  status: number;
  headers: Record<string, string>;
  body: string;
}): Promise<void> {
  const server = createServer((request, response) => {
    request.resume();
    response.writeHead(reply.status, reply.headers);
    response.end(reply.body);
  });
  await listen(server);
  const sink = sinkFor(server, { timeoutMs: 100 });
  sink.enqueue(event());
  await eventually(() => assert.equal(sink.snapshot().failed, 1));
  await sink.close();
  await close(server);
}

function sinkFor(
  server: ReturnType<typeof createServer>,
  patch: Partial<Parameters<typeof createCogsEgressTelemetrySink>[0]> = {},
) {
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return createCogsEgressTelemetrySink({
    mode: "otlp",
    endpoint: `http://127.0.0.1:${address.port}/v1/logs`,
    allowLoopbackHttpDevelopment: true,
    ...patch,
  });
}
function logRecords(value: unknown): Record<string, unknown>[] {
  const root = object(value);
  assert.deepEqual(Object.keys(root).sort(), ["resourceLogs"]);
  const resource = object(array(root.resourceLogs)[0]);
  assert.deepEqual(resource.resource, { attributes: [{ key: "service.name", value: { stringValue: "cogs-egress" } }] });
  const scope = object(array(resource.scopeLogs)[0]);
  assert.deepEqual(scope.scope, { name: "cogs.egress.telemetry", version: "v1alpha1" });
  return array(scope.logRecords).map(object);
}
function attributes(log: Record<string, unknown>): Record<string, unknown> {
  assert.equal(log.severityText, "INFO");
  assert.deepEqual(log.body, { stringValue: "cogs.egress.complete" });
  const attrs = array(log.attributes).map((item) => {
    const attribute = object(item);
    return [String(attribute.key), Object.values(object(attribute.value))[0]];
  });
  assert.equal(new Set(attrs.map(([key]) => key)).size, 11);
  return Object.fromEntries(attrs);
}
function object(value: unknown): Record<string, unknown> {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as Record<string, unknown>;
}
function array(value: unknown): unknown[] {
  assert.ok(Array.isArray(value));
  return value;
}
function accessor<T extends object>(value: T, key: keyof T): T {
  return Object.defineProperty({ ...value }, key, { enumerable: true, get: () => value[key] });
}
function hidden<T extends object>(value: T): T {
  return Object.defineProperty({ ...value }, "hidden", { value: true, enumerable: false });
}
function symbol<T extends object>(value: T): T {
  return Object.assign({ ...value }, { [Symbol("x")]: true });
}
async function readBody(request: NodeJS.ReadableStream, max: number): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk as Buffer);
    total += buffer.byteLength;
    if (total > max) throw new Error("too large");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}
async function listen(server: ReturnType<typeof createServer>): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}
async function close(server: ReturnType<typeof createServer>): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}
async function eventually(assertion: () => void): Promise<void> {
  const deadline = Date.now() + 1000;
  for (;;) {
    try {
      assertion();
      return;
    } catch (error) {
      if (Date.now() > deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

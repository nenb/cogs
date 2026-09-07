import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { otlpEndpoint, otlpPostRetirement, postOtlpJson, validateOtlpResponse } from "../src/telemetry/otlp-http.ts";

test("shared OTLP endpoint validation is path-specific and rejects noncanonical authority", () => {
  assert.equal(otlpEndpoint("http://127.0.0.1:4318/v1/logs", "logs", true), "http://127.0.0.1:4318/v1/logs");
  assert.equal(
    otlpEndpoint("https://collector.example/v1/traces", "traces", false),
    "https://collector.example/v1/traces",
  );
  for (const [url, kind] of [
    ["http://127.0.0.1:4318/v1/traces", "logs"],
    ["http://127.0.0.1:4318/v1/metrics?x=1", "metrics"],
    ["http://user@127.0.0.1:4318/v1/logs", "logs"],
    ["http://example.com/v1/logs", "logs"],
    ["ftp://127.0.0.1/v1/logs", "logs"],
  ] as const) {
    assert.throws(() => otlpEndpoint(url, kind, true));
  }
});

test("shared OTLP response validator accepts empty and zero partial success only", () => {
  validateOtlpResponse("logs", "");
  validateOtlpResponse("logs", "{}");
  validateOtlpResponse("logs", '{"partialSuccess":{"rejectedLogRecords":"0","errorMessage":""}}');
  assert.throws(() => validateOtlpResponse("logs", '{"partialSuccess":{"rejectedSpans":0}}'));
  for (const body of [
    '{"partialSuccess":{"rejectedLogRecords":"1"}}',
    '{"partialSuccess":{"rejectedSpans":1}}',
    '{"partialSuccess":{"errorMessage":"SECRET_VALUE"}}',
    '{"partialSuccess":{"extra":0}}',
  ])
    assert.throws(() => validateOtlpResponse("logs", body));
});

test("shared OTLP post sets content length and bounds fetch/abort failures", async () => {
  let length = "";
  await postOtlpJson({
    url: "http://127.0.0.1:9/v1/logs",
    kind: "logs",
    body: { resourceLogs: [] },
    timeoutMs: 50,
    maxRequestBytes: 65_536,
    maxResponseBytes: 1024,
    fetch: Object.freeze(async (_url, init) => {
      length = (init.headers as Record<string, string>)["content-length"] ?? "";
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }),
  });
  assert.equal(length, String(Buffer.byteLength(JSON.stringify({ resourceLogs: [] }))));
  await assert.rejects(() =>
    postOtlpJson({
      url: "http://127.0.0.1:9/v1/logs",
      kind: "logs",
      body: {},
      timeoutMs: 50,
      maxRequestBytes: 65_536,
      maxResponseBytes: 1024,
      fetch: Object.freeze(() => new Response("{}")) as never,
    }),
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(() =>
    postOtlpJson({
      url: "http://127.0.0.1:9/v1/logs",
      kind: "logs",
      body: {},
      timeoutMs: 50,
      maxRequestBytes: 65_536,
      maxResponseBytes: 1024,
      fetch: Object.freeze(() => new Promise<Response>(() => undefined)),
      parent: controller.signal,
    }),
  );
});

test("shared OTLP oversize real streaming response cancels connection without hanging", async () => {
  let closed = false;
  const server = createServer((_request: IncomingMessage, response: ServerResponse) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.on("close", () => {
      closed = true;
    });
    const interval = setInterval(() => {
      response.write("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }, 5);
    response.on("close", () => clearInterval(interval));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  try {
    await assert.rejects(() =>
      postOtlpJson({
        url: `http://127.0.0.1:${address.port}/v1/logs`,
        kind: "logs",
        body: {},
        timeoutMs: 200,
        maxRequestBytes: 65_536,
        maxResponseBytes: 8,
      }),
    );
    await eventually(() => assert.equal(closed, true));
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
});

test("shared OTLP declared oversized response is cancelled", async () => {
  let cancelled = false;
  const response = new Response("{}", {
    status: 200,
    headers: { "content-type": "application/json", "content-length": "9" },
  });
  Object.defineProperty(response, "body", {
    value: {
      cancel: () => {
        cancelled = true;
        return Promise.resolve();
      },
    },
  });
  await assert.rejects(() =>
    postOtlpJson({
      url: "http://127.0.0.1:9/v1/logs",
      kind: "logs",
      body: {},
      timeoutMs: 100,
      maxRequestBytes: 65_536,
      maxResponseBytes: 8,
      fetch: Object.freeze(async () => response),
    }),
  );
  await eventually(() => assert.equal(cancelled, true));
});

test("shared OTLP request byte cap is enforced", async () => {
  let calls = 0;
  await assert.rejects(() =>
    postOtlpJson({
      url: "http://127.0.0.1:9/v1/logs",
      kind: "logs",
      body: { value: "x".repeat(65_536) },
      timeoutMs: 100,
      maxRequestBytes: 65_536,
      maxResponseBytes: 8,
      fetch: Object.freeze(async () => {
        calls += 1;
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      }),
    }),
  );
  assert.equal(calls, 0);
});

test("shared OTLP hostile body cancel cannot hang", async () => {
  let cancelCalled = false;
  const response = {
    status: 200,
    headers: new Headers({ "content-type": "application/json" }),
    body: {
      getReader: () => ({
        read: async () => ({ done: false, value: new Uint8Array(16) }),
        cancel: () => {
          cancelCalled = true;
          return new Promise<never>(() => undefined);
        },
        releaseLock: () => undefined,
      }),
    },
  } as unknown as Response;
  await assert.rejects(() =>
    postOtlpJson({
      url: "http://127.0.0.1:9/v1/logs",
      kind: "logs",
      body: {},
      timeoutMs: 100,
      maxRequestBytes: 65_536,
      maxResponseBytes: 8,
      fetch: Object.freeze(async () => response),
    }),
  );
  assert.equal(cancelCalled, true);
});

test("OTLP observations never retire held fetch, original read, or original cancellation", async () => {
  for (const mode of ["fetch", "invalid", "reader", "cancel-reject", "headers", "reader-throw"] as const) {
    const holdFetch = Promise.withResolvers<void>();
    const holdRead = Promise.withResolvers<{ done: true; value: undefined }>();
    const holdCancel = Promise.withResolvers<void>();
    const entered = Promise.withResolvers<void>();
    const cancelling = Promise.withResolvers<void>();
    const controller = new AbortController();
    let cancellations = 0;
    let retired = false;
    let retirement: Promise<void> | undefined;
    const observation = postOtlpJson({
      url: "https://synthetic.invalid/v1/logs",
      kind: "logs",
      body: {},
      timeoutMs: 1000,
      maxRequestBytes: 1024,
      maxResponseBytes: 1024,
      parent: controller.signal,
      fetch: Object.freeze(async () => {
        retirement = otlpPostRetirement(observation).then(() => {
          retired = true;
        });
        entered.resolve();
        if (mode === "fetch") await holdFetch.promise;
        const response = new Response(
          new ReadableStream({
            cancel() {
              cancellations++;
              cancelling.resolve();
              return holdCancel.promise;
            },
          }),
          { status: mode === "invalid" ? 503 : 200, headers: { "content-type": "application/json" } },
        );
        const fail = () => {
          Object.defineProperty(response, "body", { value: null });
          throw new Error("synthetic-secret");
        };
        if (mode === "headers") Object.defineProperty(response, "headers", { get: fail });
        if (mode === "reader-throw") Object.defineProperty(response.body, "getReader", { value: fail });
        if (mode === "reader")
          Object.defineProperty(response, "body", {
            value: {
              getReader: () => ({
                read: () => holdRead.promise,
                cancel: () => {
                  cancellations++;
                  cancelling.resolve();
                  controller.abort();
                  return holdCancel.promise;
                },
                releaseLock: () => undefined,
              }),
            },
          });
        return response;
      }),
    });
    const rejected = assert.rejects(observation);
    assert.throws(() => otlpPostRetirement(rejected), /unowned OTLP observation/);
    await entered.promise;
    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();
    await rejected;
    assert.equal(retired, false);
    holdFetch.resolve();
    if (mode === "headers" || mode === "reader-throw") assert.equal(cancellations, 1);
    await cancelling.promise;
    if (mode === "cancel-reject") holdCancel.reject(new Error("synthetic-cancel-secret"));
    else holdCancel.resolve();
    if (mode === "reader") {
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(retired, false, "cancel settlement is not original read settlement");
      holdRead.resolve({ done: true, value: undefined });
    }
    await retirement;
    assert.equal(retired, true);
    assert.equal(cancellations, 1);
  }
});

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

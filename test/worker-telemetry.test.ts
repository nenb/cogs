import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { createCogsWorkerTelemetrySink } from "../src/telemetry/worker-telemetry.ts";

test("worker telemetry disabled default is zero I/O and closes immediately", async () => {
  const sink = createCogsWorkerTelemetrySink();
  assert.equal(sink.ready, true);
  assert.equal(sink.span(goodSpan()), false);
  assert.equal(sink.metric(goodMetric()), false);
  assert.deepEqual(sink.snapshot(), { ready: true, queued: 0, exported: 0, dropped: 0, failed: 0, lag_ms: 0 });
  await sink.close();
  assert.equal(sink.ready, false);
});

test("worker telemetry emits exact trace and metric OTLP envelopes without forbidden sentinels", async () => {
  const collector = await startCollector();
  try {
    const sink = createCogsWorkerTelemetrySink({
      mode: "otlp",
      tracesEndpoint: collector.url("/v1/traces"),
      metricsEndpoint: collector.url("/v1/metrics"),
      allowLoopbackHttpDevelopment: true,
      batchSize: 8,
      fetch: Object.freeze(fetch),
      clock: Object.freeze({ nowMs: Object.freeze(() => 1234) }),
      random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(0xab)) }),
    });
    assert.equal(sink.span(goodSpan()), true);
    assert.equal(sink.metric(goodMetric()), true);
    await collector.waitFor(2);
    await sink.close();
    assert.equal(sink.snapshot().exported, 2);
    const trace = collector.jsonFor("/v1/traces") as {
      resourceSpans: [
        {
          resource: { attributes: unknown };
          scopeSpans: [{ spans: [{ traceId: string; spanId: string; name: string; startTimeUnixNano: string }] }];
        },
      ];
    };
    const metric = collector.jsonFor("/v1/metrics") as {
      resourceMetrics: [{ scopeMetrics: [{ metrics: [{ name: string }] }] }];
    };
    assert.deepEqual(trace.resourceSpans[0].resource.attributes, [
      { key: "service.name", value: { stringValue: "cogs-worker" } },
    ]);
    const span = trace.resourceSpans[0].scopeSpans[0].spans[0];
    assert.equal(span.traceId, "ab".repeat(16));
    assert.equal(span.spanId, "ab".repeat(8));
    assert.equal(span.name, "tool.dispatch");
    assert.equal(span.startTimeUnixNano, "1227000000");
    assert.equal(metric.resourceMetrics[0].scopeMetrics[0].metrics[0].name, "tool.count");
    const serialized = JSON.stringify(collector.records());
    for (const sentinel of [
      "SECRET_VALUE",
      "sk-ant-api-key",
      "/Users/nenb/workspace/file.txt",
      "rm -rf /",
      "prompt text",
      "query=secret",
      "account-123",
      "req_123",
      "corr_123",
      "anthropic",
      "claude-sonnet",
      "placeholder",
    ]) {
      assert.equal(serialized.includes(sentinel), false, sentinel);
    }
  } finally {
    await collector.close();
  }
});

test("worker telemetry groups repeated metric names into one descriptor with ordered points", async () => {
  const collector = await startCollector();
  try {
    let now = 100;
    const sink = createCogsWorkerTelemetrySink({
      mode: "otlp",
      tracesEndpoint: collector.url("/v1/traces"),
      metricsEndpoint: collector.url("/v1/metrics"),
      allowLoopbackHttpDevelopment: true,
      batchSize: 4,
      fetch: Object.freeze(fetch),
      clock: Object.freeze({
        nowMs: Object.freeze(() => {
          now += 1;
          return now;
        }),
      }),
      random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(0xac)) }),
    });
    assert.equal(
      sink.metric({ ...goodMetric(), attributes: { ...goodMetric().attributes, value: 3, count: 99 } }),
      true,
    );
    assert.equal(
      sink.metric({ ...goodMetric(), attributes: { ...goodMetric().attributes, value: 4, count: 100 } }),
      true,
    );
    await collector.waitFor(1);
    await sink.close();
    const metrics = (
      collector.jsonFor("/v1/metrics") as {
        resourceMetrics: [
          {
            scopeMetrics: [
              {
                metrics: [
                  {
                    name: string;
                    sum: {
                      aggregationTemporality: number;
                      dataPoints: Array<{ asInt: string; attributes: unknown[] }>;
                    };
                  },
                ];
              },
            ];
          },
        ];
      }
    ).resourceMetrics[0].scopeMetrics[0].metrics;
    assert.equal(metrics.length, 1);
    assert.equal(metrics[0].name, "tool.count");
    assert.deepEqual(
      metrics[0].sum.dataPoints.map((point) => point.asInt),
      ["3", "4"],
    );
    assert.equal(metrics[0].sum.aggregationTemporality, 1);
    const firstPoint = metrics[0].sum.dataPoints[0];
    assert.ok(firstPoint);
    const serializedAttrs = JSON.stringify(firstPoint.attributes);
    assert.equal(serializedAttrs.includes("cogs.value"), false);
    assert.equal(serializedAttrs.includes("cogs.count"), false);
  } finally {
    await collector.close();
  }
});

test("worker telemetry emits gauge only for fixed gauge metric names", async () => {
  const collector = await startCollector();
  try {
    const sink = createCogsWorkerTelemetrySink({
      mode: "otlp",
      tracesEndpoint: collector.url("/v1/traces"),
      metricsEndpoint: collector.url("/v1/metrics"),
      allowLoopbackHttpDevelopment: true,
      batchSize: 4,
      fetch: Object.freeze(fetch),
      clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
      random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(0xad)) }),
    });
    assert.equal(sink.metric({ ...goodMetric(), name: "session.active" }), true);
    assert.equal(sink.metric({ ...goodMetric(), name: "tool.errors" }), true);
    await collector.waitFor(1);
    await sink.close();
    const metrics = (
      collector.jsonFor("/v1/metrics") as {
        resourceMetrics: [{ scopeMetrics: [{ metrics: Array<Record<string, unknown>> }] }];
      }
    ).resourceMetrics[0].scopeMetrics[0].metrics;
    assert.ok(metrics.find((metric) => metric.name === "session.active")?.gauge);
    assert.ok(metrics.find((metric) => metric.name === "tool.errors")?.sum);
  } finally {
    await collector.close();
  }
});

test("worker telemetry integer attribute bounds are key-specific", async () => {
  const sink = createCogsWorkerTelemetrySink({ mode: "disabled" });
  assert.equal(sink.metric({ ...goodMetric(), name: "token.input", attributes: { value: 86_400_001 } }), false);
  const otlpSink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: Object.freeze(
      async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    ) as typeof fetch,
    clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(0xae)) }),
  });
  assert.equal(otlpSink.metric({ ...goodMetric(), name: "token.input", attributes: { value: 86_400_001 } }), true);
  assert.equal(
    otlpSink.metric({ ...goodMetric(), name: "cost.microunits", attributes: { value: Number.MAX_SAFE_INTEGER } }),
    true,
  );
  assert.equal(otlpSink.metric({ ...goodMetric(), attributes: { value: -1 } }), false);
  assert.equal(otlpSink.metric({ ...goodMetric(), attributes: { value: Number.MAX_SAFE_INTEGER + 1 } }), false);
  assert.equal(
    otlpSink.span({ ...goodSpan(), attributes: { ...goodSpan().attributes, duration_ms: 86_400_001 } }),
    false,
  );
  await otlpSink.close();
});

test("worker telemetry batches FIFO, drops newest on overflow, and isolates late mutation", async () => {
  const collector = await startCollector();
  try {
    const sink = createCogsWorkerTelemetrySink({
      mode: "otlp",
      tracesEndpoint: collector.url("/v1/traces"),
      metricsEndpoint: collector.url("/v1/metrics"),
      allowLoopbackHttpDevelopment: true,
      capacity: 2,
      batchSize: 2,
      fetch: Object.freeze(fetch),
      clock: Object.freeze({ nowMs: Object.freeze(() => 10) }),
      random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(1)) }),
    });
    const first = goodSpan("pi.run");
    const second = goodSpan("ssh.connect");
    assert.equal(sink.span(first), true);
    assert.equal(sink.span(second), true);
    assert.equal(sink.span(goodSpan("shutdown.prepare")), false);
    first.name = "shutdown.prepare";
    await collector.waitFor(1);
    await sink.close();
    const spans = (
      collector.jsonFor("/v1/traces") as {
        resourceSpans: [{ scopeSpans: [{ spans: Array<{ name: string }> }] }];
      }
    ).resourceSpans[0].scopeSpans[0].spans;
    assert.deepEqual(
      spans.map((span: { name: string }) => span.name),
      ["pi.run", "ssh.connect"],
    );
    assert.equal(sink.snapshot().dropped, 1);
  } finally {
    await collector.close();
  }
});

test("worker telemetry outage, non2xx, redirect, malformed and throwing fetch are nonfatal to producers", async () => {
  const cases: Array<[string, typeof fetch]> = [
    [
      "throw",
      Object.freeze(async () => {
        throw new Error("SECRET_VALUE");
      }) as typeof fetch,
    ],
    [
      "non2xx",
      Object.freeze(
        async () => new Response("{}", { status: 503, headers: { "content-type": "application/json" } }),
      ) as typeof fetch,
    ],
    ["redirect", Object.freeze(async () => Response.redirect("http://127.0.0.1/elsewhere", 302)) as typeof fetch],
    ["malformed", Object.freeze(async () => undefined as never) as typeof fetch],
  ];
  for (const [, fetchFn] of cases) {
    const sink = createCogsWorkerTelemetrySink({
      mode: "otlp",
      tracesEndpoint: "http://127.0.0.1:9/v1/traces",
      metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
      allowLoopbackHttpDevelopment: true,
      fetch: fetchFn,
      clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
      random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(2)) }),
      timeoutMs: 50,
    });
    assert.equal(sink.span(goodSpan()), true);
    await eventually(() => assert.equal(sink.snapshot().failed, 1));
    assert.equal(sink.ready, true);
    await sink.close();
  }
});

test("worker telemetry close aborts hanging fetch and prevents late writes", async () => {
  let aborted = false;
  const fetchFn = Object.freeze(
    (_url: string, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => {
          aborted = true;
          reject(new DOMException("aborted", "AbortError"));
        });
      }),
  ) as typeof fetch;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: fetchFn,
    clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(3)) }),
    timeoutMs: 50,
  });
  assert.equal(sink.span(goodSpan()), true);
  await eventually(() => assert.equal(sink.snapshot().failed, 1));
  await Promise.all([sink.close(), sink.close()]);
  assert.equal(aborted, true);
  assert.equal(sink.span(goodSpan()), false);
  assert.equal(sink.ready, false);
});

test("worker telemetry mixed batches count once and never duplicate successful trace groups", async () => {
  const calls: Array<{ url: string; body: string }> = [];
  const fetchFn = Object.freeze(async (url: string, init: RequestInit) => {
    calls.push({ url, body: String(init.body) });
    assert.equal(
      (init.headers as Record<string, string>)["content-length"],
      String(Buffer.byteLength(String(init.body))),
    );
    if (url.endsWith("/v1/metrics"))
      return new Response("{}", { status: 503, headers: { "content-type": "application/json" } });
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  let now = 1;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: fetchFn,
    batchSize: 2,
    clock: Object.freeze({ nowMs: Object.freeze(() => now) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(4)) }),
    timeoutMs: 50,
  });
  assert.equal(sink.span(goodSpan("pi.run")), true);
  assert.equal(sink.metric(goodMetric()), true);
  await eventually(() => assert.equal(sink.snapshot().failed, 1));
  assert.equal(sink.span(goodSpan("shutdown.ready")), false);
  now = 100;
  assert.equal(sink.span(goodSpan("shutdown.ready")), true);
  await eventually(() => assert.equal(sink.snapshot().exported, 2));
  await sink.close();
  assert.equal(calls.filter((call) => call.url.endsWith("/v1/metrics")).length, 1);
  assert.equal(calls.filter((call) => call.url.endsWith("/v1/traces")).length, 2);
  assert.equal(JSON.stringify(calls).match(/pi\.run/g)?.length, 1);
  assert.deepEqual(sink.snapshot(), { ready: false, queued: 0, exported: 2, dropped: 2, failed: 1, lag_ms: 0 });
});

test("worker telemetry repeated outage does not poison or starve later batches", async () => {
  let traceCalls = 0;
  let now = 1;
  const fetchFn = Object.freeze(async () => {
    traceCalls += 1;
    if (traceCalls <= 2) return new Response("{}", { status: 503, headers: { "content-type": "application/json" } });
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: fetchFn,
    batchSize: 1,
    clock: Object.freeze({ nowMs: Object.freeze(() => now) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(7)) }),
    timeoutMs: 50,
  });
  assert.equal(sink.span(goodSpan("pi.run")), true);
  await eventually(() => assert.equal(sink.snapshot().failed, 1));
  assert.equal(sink.span(goodSpan("shutdown.ready")), false);
  now = 100;
  assert.equal(sink.span(goodSpan("shutdown.ready")), true);
  await eventually(() => assert.equal(sink.snapshot().failed, 2));
  now = 200;
  assert.equal(sink.span(goodSpan("egress.complete")), true);
  await eventually(() => assert.equal(sink.snapshot().exported, 1));
  await sink.close();
  assert.equal(traceCalls, 3);
  assert.deepEqual(sink.snapshot(), { ready: false, queued: 0, exported: 1, dropped: 3, failed: 2, lag_ms: 0 });
});

test("worker telemetry detects non-Promise fetch and rejects nonzero partial-success responses", async () => {
  for (const fetchFn of [
    Object.freeze(() => new Response("{}")) as unknown as typeof fetch,
    Object.freeze(
      async () =>
        new Response('{"partialSuccess":{"rejectedDataPoints":1}}', {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    ) as typeof fetch,
  ]) {
    const sink = createCogsWorkerTelemetrySink({
      mode: "otlp",
      tracesEndpoint: "http://127.0.0.1:9/v1/traces",
      metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
      allowLoopbackHttpDevelopment: true,
      fetch: fetchFn,
      clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
      random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(5)) }),
      timeoutMs: 50,
    });
    assert.equal(sink.span(goodSpan()), true);
    await eventually(() => assert.equal(sink.snapshot().failed, 1));
    await sink.close();
  }
});

test("worker telemetry aborted close partitions active accepted item exactly once", async () => {
  const fetchFn = Object.freeze(() => new Promise<Response>(() => undefined)) as unknown as typeof fetch;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: fetchFn,
    clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(13)) }),
    timeoutMs: 100,
  });
  assert.equal(sink.span(goodSpan("pi.run")), true);
  await eventually(() => assert.equal(sink.snapshot().queued, 1));
  const controller = new AbortController();
  controller.abort();
  await sink.close(controller.signal);
  assert.deepEqual(sink.snapshot(), { ready: false, queued: 0, exported: 0, dropped: 1, failed: 1, lag_ms: 0 });
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.deepEqual(sink.snapshot(), { ready: false, queued: 0, exported: 0, dropped: 1, failed: 1, lag_ms: 0 });
});

test("worker telemetry close uses one total deadline for hostile mixed queued batches", async () => {
  const calls: string[] = [];
  const fetchFn = Object.freeze((url: string) => {
    calls.push(url);
    return new Promise<Response>(() => undefined);
  }) as unknown as typeof fetch;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: fetchFn,
    batchSize: 2,
    capacity: 4,
    clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(10)) }),
    timeoutMs: 50,
  });
  assert.equal(sink.span(goodSpan("pi.run")), true);
  assert.equal(sink.metric(goodMetric()), true);
  assert.equal(sink.span(goodSpan("shutdown.ready")), true);
  assert.equal(sink.metric({ ...goodMetric(), name: "otlp.failed" }), true);
  await new Promise((resolve) => setTimeout(resolve, 5));
  const startedBeforeClose = calls.length;
  const start = Date.now();
  await sink.close();
  assert.ok(Date.now() - start < 250);
  const afterClose = calls.length;
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(calls.length, afterClose);
  assert.equal(startedBeforeClose, 1);
  assert.equal(sink.ready, false);
});

test("worker telemetry active mixed batch does not start metric after close timeout", async () => {
  const calls: string[] = [];
  const fetchFn = Object.freeze((url: string) => {
    calls.push(url);
    return new Promise<Response>(() => undefined);
  }) as unknown as typeof fetch;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: fetchFn,
    batchSize: 2,
    clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(11)) }),
    timeoutMs: 50,
  });
  assert.equal(sink.span(goodSpan("pi.run")), true);
  assert.equal(sink.metric(goodMetric()), true);
  await eventually(() => assert.equal(calls.length, 1));
  await sink.close();
  const snapshot = sink.snapshot();
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.deepEqual(sink.snapshot(), snapshot);
  assert.deepEqual(
    calls.map((url) => (url.endsWith("/v1/traces") ? "trace" : "metric")),
    ["trace"],
  );
});

test("worker telemetry stale pump finalizer cannot clear newer close-owned batch", async () => {
  let now = 1;
  let firstResolve: ((response: Response) => void) | undefined;
  const calls: string[] = [];
  const fetchFn = Object.freeze((url: string) => {
    calls.push(url);
    if (calls.length === 1)
      return new Promise<Response>((resolve) => {
        firstResolve = resolve;
      });
    return new Promise<Response>(() => undefined);
  }) as typeof fetch;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: fetchFn,
    batchSize: 1,
    capacity: 2,
    clock: Object.freeze({ nowMs: Object.freeze(() => now) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(14)) }),
    timeoutMs: 50,
  });
  assert.equal(sink.span(goodSpan("pi.run")), true);
  await eventually(() => assert.equal(calls.length, 1));
  assert.equal(sink.span(goodSpan("shutdown.ready")), true);
  const closePromise = sink.close();
  await eventually(() => assert.ok(sink.snapshot().failed >= 1));
  now = 20;
  firstResolve?.(new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  await closePromise;
  const snapshot = sink.snapshot();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(sink.snapshot(), snapshot);
});

test("worker telemetry hostile clock after enqueue cannot reject pump", async () => {
  let calls = 0;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: Object.freeze(
      async () => new Response("{}", { status: 503, headers: { "content-type": "application/json" } }),
    ) as typeof fetch,
    clock: Object.freeze({
      nowMs: Object.freeze(() => {
        calls += 1;
        if (calls > 2) throw new Error("SECRET_CLOCK");
        return 1;
      }),
    }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(15)) }),
    timeoutMs: 50,
  });
  assert.equal(sink.span(goodSpan("pi.run")), true);
  await eventually(() => assert.equal(sink.snapshot().failed, 1));
  await sink.close();
});

test("worker telemetry in-flight batch counts toward capacity and lag", async () => {
  let now = 10;
  const fetchFn = Object.freeze(() => new Promise<Response>(() => undefined)) as unknown as typeof fetch;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: fetchFn,
    batchSize: 1,
    capacity: 2,
    clock: Object.freeze({ nowMs: Object.freeze(() => now) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(12)) }),
    timeoutMs: 100,
  });
  assert.equal(sink.span(goodSpan("pi.run")), true);
  await eventually(() => assert.equal(sink.snapshot().queued, 1));
  now = 40;
  assert.equal(sink.span(goodSpan("shutdown.ready")), true);
  assert.equal(sink.span(goodSpan("egress.complete")), false);
  const snapshot = sink.snapshot();
  assert.equal(snapshot.queued, 2);
  assert.equal(snapshot.lag_ms, 30);
  await sink.close();
});

test("worker telemetry hostile body reader and cancel cannot hang close", async () => {
  let cancelCalled = false;
  const response = {
    status: 200,
    headers: new Headers({ "content-type": "application/json" }),
    body: {
      getReader: () => ({
        read: () => new Promise<never>(() => undefined),
        cancel: () => {
          cancelCalled = true;
          return new Promise<never>(() => undefined);
        },
        releaseLock: () => undefined,
      }),
    },
  } as unknown as Response;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: Object.freeze(async () => response) as typeof fetch,
    clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(6)) }),
    timeoutMs: 50,
  });
  assert.equal(sink.span(goodSpan()), true);
  await eventually(() => assert.equal(sink.snapshot().queued, 1));
  await new Promise((resolve) => setTimeout(resolve, 5));
  await Promise.all([sink.close(), sink.close()]);
  await eventually(() => assert.equal(cancelCalled, true));
  assert.equal(sink.ready, false);
});

test("worker telemetry accepts required issue 69 span and metric names", async () => {
  const accepted: string[] = [];
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: Object.freeze(async (url: string) => {
      accepted.push(url);
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch,
    batchSize: 128,
    clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(8)) }),
    timeoutMs: 50,
  });
  for (const name of [
    "lifecycle.start",
    "lifecycle.ready",
    "dependency.start",
    "dependency.ready",
    "dependency.lost",
    "api.request",
    "pi.model_call",
    "pi.event",
    "pi.turn",
    "ssh.channel",
    "egress.complete",
    "wal.complete",
    "shutdown.ready",
    "export.failure",
    "checkpoint.failure",
  ]) {
    assert.equal(sink.span(goodSpan(name)), true);
  }
  for (const name of [
    "token.input",
    "token.output",
    "token.cache",
    "cost.microunits",
    "session.active",
    "tool.errors",
    "tool.timeouts",
    "tool.truncated",
    "egress.requests",
    "egress.bytes",
    "egress.denials",
    "wal.depth",
    "wal.bytes",
    "wal.failures",
    "otlp.queue.depth",
    "otlp.dropped",
    "otlp.failed",
    "otlp.export.lag",
    "checkpoint.failures",
    "export.failures",
  ]) {
    assert.equal(sink.metric({ ...goodMetric(), name }), true);
  }
  await eventually(() => assert.equal(sink.snapshot().exported, 35));
  await sink.close();
  assert.ok(accepted.some((url) => url.endsWith("/v1/traces")));
  assert.ok(accepted.some((url) => url.endsWith("/v1/metrics")));
});

test("worker telemetry rejects zero trace and span identifiers without I/O", async () => {
  let calls = 0;
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: Object.freeze(async () => {
      calls += 1;
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch,
    clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(0)) }),
    timeoutMs: 50,
  });
  assert.equal(sink.span(goodSpan()), false);
  assert.equal(
    sink.span({
      ...goodSpan(),
      trace_id: "0".repeat(32),
      span_id: "1".repeat(16),
    }),
    false,
  );
  assert.equal(
    sink.span({
      ...goodSpan(),
      trace_id: "1".repeat(32),
      span_id: "0".repeat(16),
    }),
    false,
  );
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(calls, 0);
  assert.equal(sink.snapshot().dropped, 3);
  await sink.close();
});

test("worker telemetry rejects hostile input, URLs, seams, and forbidden fields without invoking accessors", async () => {
  assert.throws(
    () =>
      createCogsWorkerTelemetrySink({
        mode: "otlp",
        tracesEndpoint: "http://example.com/v1/traces",
        metricsEndpoint: "http://example.com/v1/metrics",
      }),
    /invalid worker telemetry/,
  );
  assert.throws(
    () =>
      createCogsWorkerTelemetrySink({
        mode: "otlp",
        tracesEndpoint: "http://user@127.0.0.1:1/v1/traces?secret=1",
        metricsEndpoint: "http://127.0.0.1:1/v1/metrics#hash",
        allowLoopbackHttpDevelopment: true,
      }),
    /invalid worker telemetry/,
  );
  assert.throws(
    () =>
      createCogsWorkerTelemetrySink({
        mode: "otlp",
        tracesEndpoint: "http://127.0.0.1:1/v1/traces",
        metricsEndpoint: "http://127.0.0.1:1/v1/metrics",
        allowLoopbackHttpDevelopment: true,
        fetch: async () => new Response("{}") as never,
      }),
    /invalid worker telemetry/,
  );
  const sink = createCogsWorkerTelemetrySink({
    mode: "otlp",
    tracesEndpoint: "http://127.0.0.1:9/v1/traces",
    metricsEndpoint: "http://127.0.0.1:9/v1/metrics",
    allowLoopbackHttpDevelopment: true,
    fetch: Object.freeze(
      async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }),
    ) as typeof fetch,
    clock: Object.freeze({ nowMs: Object.freeze(() => 1) }),
    random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(9)) }),
    timeoutMs: 50,
  });
  let getter = 0;
  const hostile = Object.create(null, {
    name: {
      enumerable: true,
      get: () => {
        getter++;
        return "tool.dispatch";
      },
    },
    attributes: { enumerable: true, value: {} },
  });
  assert.equal(sink.span(hostile), false);
  assert.equal(getter, 0);
  assert.equal(
    sink.span({
      name: "tool.dispatch",
      attributes: { ...goodSpan().attributes, path: "/Users/nenb/workspace/file.txt" },
    }),
    false,
  );
  assert.equal(
    sink.span(
      new Proxy(goodSpan(), {
        get: () => {
          throw new Error("SECRET_VALUE");
        },
      }),
    ),
    false,
  );
  await sink.close();
});

function goodSpan(name = "tool.dispatch"): { name: string; attributes: Record<string, unknown> } {
  return {
    name,
    attributes: {
      outcome: "ok",
      tool: "bash",
      operation: "run",
      duration_ms: 7,
      credential_required: false,
      timed_out: false,
      cancelled: false,
    },
  };
}
function goodMetric(): { name: string; attributes: Record<string, unknown> } {
  return { name: "tool.count", attributes: { tool: "bash", count: 1, value: 1, outcome: "ok" } };
}

async function startCollector(): Promise<{
  url: (path: string) => string;
  waitFor: (count: number) => Promise<void>;
  records: () => Array<{ path: string; body: string }>;
  jsonFor: (path: string) => Record<string, unknown>;
  close: () => Promise<void>;
}> {
  const records: Array<{ path: string; body: string }> = [];
  const waiters: Array<() => void> = [];
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      records.push({ path: request.url ?? "", body: Buffer.concat(chunks).toString("utf8") });
      for (const waiter of waiters.splice(0)) waiter();
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}\n");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.equal(typeof address, "object");
  assert.ok(address);
  const port = (address as AddressInfo).port;
  return {
    url: (path: string) => `http://127.0.0.1:${port}${path}`,
    records: () => records.slice(),
    jsonFor: (path: string) => JSON.parse(records.find((record) => record.path === path)?.body ?? "null"),
    waitFor: async (count: number) => eventually(() => assert.equal(records.length, count)),
    close: async () =>
      new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
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

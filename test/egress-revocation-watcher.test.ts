import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type CogsEgressRevocationActions,
  CogsEgressRevocationError,
  type CogsEgressRevocationSnapshot,
  type CogsEgressRevocationSource,
  type CogsEgressRevocationTimers,
  createCogsEgressRevocationWatcher,
} from "../src/egress/revocation-watcher.ts";

const raw = "host.example/path?token=secret credential handle workspace";
const baseline = Object.freeze({
  presetRevision: "p1",
  credentialVersion: "c1",
  revoked: false,
  pkiExpiresAtMs: 10_000,
});
const generic = (error: unknown) => {
  assert.ok(error instanceof CogsEgressRevocationError);
  assert.equal(error.code, "COGS_EGRESS_REVOCATION_FAILED");
  assert.equal(error.message, "egress revocation unavailable");
  assert.equal(String(error.stack ?? "").includes(raw), false);
  assert.equal(String(error).includes("secret"), false);
  return true;
};

test("unchanged snapshots poll on a deterministic serialized cadence and expose a frozen ready handle", async () => {
  const timers = new ManualTimers();
  let reads = 0;
  let release: (() => void) | undefined;
  const source: CogsEgressRevocationSource = {
    async read() {
      reads++;
      if (reads === 2) await new Promise<void>((resolve) => (release = resolve));
      return snap();
    },
  };
  const actions = actionLog();
  const watcher = await createCogsEgressRevocationWatcher(source, actions.sink, opts(timers));
  assert.equal(watcher.ready, true);
  assert.throws(() => ((watcher as { ready: boolean }).ready = false), TypeError);
  timers.tick(50);
  await Promise.resolve();
  assert.equal(reads, 2);
  release?.();
  await flush();
  assert.equal(watcher.ready, true);
  timers.tick(50);
  await flush();
  assert.equal(reads, 3);
  assert.deepEqual(actions.calls, []);
  await watcher.close();
  assert.equal(timers.live, 0);
});

test("each stable public reason triggers once with precedence and ordered all-attempted actions", async () => {
  for (const [snapshot, reason] of [
    [snap({ revoked: true, presetRevision: "p2" }), "revoked"],
    [snap({ presetRevision: "p2", credentialVersion: "c2" }), "preset_changed"],
    [snap({ credentialVersion: "c2", pkiExpiresAtMs: 9000 }), "credential_changed"],
    [snap({ pkiExpiresAtMs: 9000 }), "pki_changed"],
    [snap({ pkiExpiresAtMs: 10_000 }), "pki_expiring"],
  ] as const) {
    const timers = new ManualTimers();
    let next = snap();
    let now = 0;
    const source = { read: async () => next };
    const actions = actionLog();
    const watcher = await createCogsEgressRevocationWatcher(
      source,
      actions.sink,
      opts(timers, { nowMs: () => now, minPkiRemainingMs: 1000 }),
    );
    if (reason === "pki_expiring") now = 9500;
    next = snapshot;
    timers.tick(50);
    await flush();
    await flush();
    assert.equal(watcher.ready, false, reason);
    assert.deepEqual(actions.calls, [`denyNew:${reason}`, `drain:${reason}`, `replace:${reason}`]);
    timers.tick(500);
    await flush();
    assert.deepEqual(actions.calls, [`denyNew:${reason}`, `drain:${reason}`, `replace:${reason}`]);
  }
});

test("poll throw, timeout, malformed snapshots, extra keys, unsafe clock, and unsafe expiry are source_unavailable", async () => {
  const badReads: Array<(signal: AbortSignal) => Promise<CogsEgressRevocationSnapshot>> = [
    async () => {
      throw new Error(raw);
    },
    () => new Promise<CogsEgressRevocationSnapshot>(() => undefined),
    async () => ({ ...snap(), extra: raw }) as CogsEgressRevocationSnapshot,
    async () => ({ ...snap(), presetRevision: "bad space" }),
    async () => ({ ...snap(), presetRevision: 1 }) as unknown as CogsEgressRevocationSnapshot,
    async () => ({ ...snap(), credentialVersion: "" }),
    async () => hiddenExtra(),
    async () => symbolExtra(),
    async () => ({ ...snap(), revoked: "false" }) as unknown as CogsEgressRevocationSnapshot,
    async () => ({ ...snap(), pkiExpiresAtMs: Number.MAX_SAFE_INTEGER + 1 }),
  ];
  for (const bad of badReads) {
    const timers = new ManualTimers();
    let first = true;
    const source = {
      read: (signal: AbortSignal) => {
        if (first) {
          first = false;
          return Promise.resolve(snap());
        }
        return bad(signal);
      },
    };
    const actions = actionLog();
    const watcher = await createCogsEgressRevocationWatcher(source, actions.sink, opts(timers));
    timers.tick(50);
    await flush();
    timers.tick(50);
    await flush();
    await flush();
    assert.equal(watcher.ready, false);
    assert.deepEqual(actions.calls, [
      "denyNew:source_unavailable",
      "drain:source_unavailable",
      "replace:source_unavailable",
    ]);
  }

  const timers = new ManualTimers();
  const actions = actionLog();
  const watcher = await createCogsEgressRevocationWatcher(
    { read: async () => snap() },
    actions.sink,
    opts(timers, { nowMs: () => 1 }),
  );
  await watcher.close();
  await assert.rejects(
    createCogsEgressRevocationWatcher(
      { read: async () => snap() },
      actions.sink,
      opts(new ManualTimers(), { nowMs: () => Number.NaN }),
    ),
    generic,
  );
});

test("initial source failure and changed snapshots run transition actions before create rejects", async () => {
  for (const [read, reason] of [
    [
      async () => {
        throw new Error(raw);
      },
      "source_unavailable",
    ],
    [async () => snap({ revoked: true }), "revoked"],
    [async () => snap({ presetRevision: "p2" }), "preset_changed"],
  ] as const) {
    const actions = actionLog();
    await assert.rejects(createCogsEgressRevocationWatcher({ read }, actions.sink, opts(new ManualTimers())), generic);
    assert.deepEqual(actions.calls, [`denyNew:${reason}`, `drain:${reason}`, `replace:${reason}`]);
  }
});

test("caller cancellation before start rejects without actions; after ready revokes", async () => {
  const before = new AbortController();
  before.abort();
  const early = actionLog();
  await assert.rejects(
    createCogsEgressRevocationWatcher(
      { read: async () => snap() },
      early.sink,
      opts(new ManualTimers(), { signal: before.signal }),
    ),
    generic,
  );
  assert.deepEqual(early.calls, []);

  const after = new AbortController();
  const actions = actionLog();
  const watcher = await createCogsEgressRevocationWatcher(
    { read: async () => snap() },
    actions.sink,
    opts(new ManualTimers(), { signal: after.signal }),
  );
  after.abort(raw);
  await flush();
  await flush();
  assert.equal(watcher.ready, false);
  assert.deepEqual(actions.calls, ["denyNew:cancelled", "drain:cancelled", "replace:cancelled"]);
});

test("caller cancellation during initial read aborts promptly and runs cancelled transition", async () => {
  const controller = new AbortController();
  const actions = actionLog();
  let readAborted = false;
  const create = createCogsEgressRevocationWatcher(
    {
      read: (signal) =>
        new Promise<CogsEgressRevocationSnapshot>((_, reject) => {
          signal.addEventListener("abort", () => {
            readAborted = true;
            reject(new Error(raw));
          });
        }),
    },
    actions.sink,
    opts(new ManualTimers(), { signal: controller.signal }),
  );
  controller.abort(raw);
  await assert.rejects(create, generic);
  assert.equal(readAborted, true);
  assert.deepEqual(actions.calls, ["denyNew:cancelled", "drain:cancelled", "replace:cancelled"]);
});

test("actions are bounded and later actions still run after throw or hang", async () => {
  const timers = new ManualTimers();
  let current = snap();
  const calls: string[] = [];
  const actions: CogsEgressRevocationActions = {
    async denyNew(reason) {
      calls.push(`denyNew:${reason}`);
      throw new Error(raw);
    },
    drain(reason, signal) {
      calls.push(`drain:${reason}:${signal.aborted}`);
      signal.addEventListener("abort", () => calls.push("drain-aborted"));
      return new Promise(() => undefined);
    },
    async replace(reason) {
      calls.push(`replace:${reason}`);
    },
  };
  const watcher = await createCogsEgressRevocationWatcher({ read: async () => current }, actions, opts(timers));
  current = snap({ revoked: true });
  timers.tick(50);
  await flush();
  timers.tick(50);
  await flush();
  timers.tick(50);
  await flush();
  assert.equal(watcher.ready, false);
  assert.deepEqual(calls, ["denyNew:revoked", "drain:revoked:false", "drain-aborted", "replace:revoked"]);
  await assert.rejects(watcher.close(), generic);
});

test("alternating valid-to-NaN clock and timer set failure trigger source_unavailable", async () => {
  const cases = [
    {
      timers: new ManualTimers(),
      nowMs: (() => {
        let calls = 0;
        return () => (++calls <= 2 ? 5000 : Number.NaN);
      })(),
    },
    { timers: new ManualTimers({ failOnSet: 2 }), nowMs: () => 5000 },
  ];
  for (const item of cases) {
    const actions = actionLog();
    const watcher = await createCogsEgressRevocationWatcher(
      { read: async () => snap() },
      actions.sink,
      opts(item.timers, { nowMs: item.nowMs }),
    );
    item.timers.tick(50);
    await flush();
    assert.equal(watcher.ready, false);
    assert.deepEqual(actions.calls, [
      "denyNew:source_unavailable",
      "drain:source_unavailable",
      "replace:source_unavailable",
    ]);
  }
});

test("close is concurrent/idempotent, cancels active work and timers, and prevents post-close transitions", async () => {
  const timers = new ManualTimers();
  let aborted = false;
  let finish!: (value: CogsEgressRevocationSnapshot) => void;
  let first = true;
  const actions = actionLog();
  const source = {
    read(signal: AbortSignal) {
      if (first) {
        first = false;
        return Promise.resolve(snap());
      }
      signal.addEventListener("abort", () => (aborted = true));
      return new Promise<CogsEgressRevocationSnapshot>((resolve) => (finish = resolve));
    },
  };
  const watcher = await createCogsEgressRevocationWatcher(source, actions.sink, opts(timers));
  timers.tick(50);
  await flush();
  const a = watcher.close();
  const b = watcher.close();
  assert.equal(a, b);
  timers.tick(50);
  await Promise.all([a, b]);
  assert.equal(aborted, true);
  assert.equal(watcher.ready, false);
  assert.equal(timers.live, 0);
  finish(snap({ revoked: true }));
  await flush();
  timers.tick(500);
  await flush();
  assert.deepEqual(actions.calls, []);
});

test("close rejects generic when cleanup times out", async () => {
  const timers = new ManualTimers();
  let first = true;
  const watcher = await createCogsEgressRevocationWatcher(
    {
      read: () => {
        if (first) {
          first = false;
          return Promise.resolve(snap());
        }
        return new Promise<CogsEgressRevocationSnapshot>(() => undefined);
      },
    },
    actionLog().sink,
    opts(timers),
  );
  timers.tick(50);
  await flush();
  const close = watcher.close();
  timers.tick(200);
  await assert.rejects(close, generic);
});

function snap(patch: Partial<CogsEgressRevocationSnapshot> = {}): CogsEgressRevocationSnapshot {
  return Object.freeze({ ...baseline, ...patch });
}

function hiddenExtra(): CogsEgressRevocationSnapshot {
  const value = { ...baseline };
  Object.defineProperty(value, "hidden", { value: raw, enumerable: false });
  return value;
}

function symbolExtra(): CogsEgressRevocationSnapshot {
  return { ...baseline, [Symbol(raw)]: raw } as unknown as CogsEgressRevocationSnapshot;
}

function opts(timers: ManualTimers, patch: Partial<Parameters<typeof createCogsEgressRevocationWatcher>[2]> = {}) {
  return {
    baseline,
    pollIntervalMs: 50,
    minPkiRemainingMs: 1000,
    operationTimeoutMs: 50,
    nowMs: () => 5000,
    timers,
    ...patch,
  };
}

function actionLog() {
  const calls: string[] = [];
  const sink: CogsEgressRevocationActions = {
    async denyNew(reason) {
      calls.push(`denyNew:${reason}`);
    },
    async drain(reason) {
      calls.push(`drain:${reason}`);
    },
    async replace(reason) {
      calls.push(`replace:${reason}`);
    },
  };
  return { calls, sink };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 10; index++) await Promise.resolve();
}

class ManualTimers implements CogsEgressRevocationTimers {
  private now = 0;
  private id = 0;
  private setCalls = 0;
  private readonly timers = new Map<number, { at: number; callback: () => void }>();

  public constructor(private readonly options: Readonly<{ failOnSet?: number }> = {}) {}

  public get live(): number {
    return this.timers.size;
  }

  public setTimeout(callback: () => void, ms: number): number {
    this.setCalls++;
    if (this.options.failOnSet === this.setCalls) throw new Error(raw);
    const id = ++this.id;
    this.timers.set(id, { at: this.now + ms, callback });
    return id;
  }

  public clearTimeout(timer: unknown): void {
    this.timers.delete(Number(timer));
  }

  public tick(ms: number): void {
    this.now += ms;
    for (const [id, timer] of [...this.timers.entries()].sort((a, b) => a[1].at - b[1].at)) {
      if (timer.at <= this.now && this.timers.delete(id)) timer.callback();
    }
  }
}

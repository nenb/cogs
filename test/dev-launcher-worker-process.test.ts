import assert from "node:assert/strict";
import type { ChildProcess, spawn } from "node:child_process";
import type { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { canonicalJson } from "../dev/launcher/contract.ts";
import {
  beginWorkerStartup,
  bindWorkerChild,
  promoteWorkerReady,
  readWorkerDescriptor,
  type WorkerStartup,
} from "../dev/launcher/control.ts";
import { observeProcessIdentity } from "../dev/launcher/runner.ts";
import { createState, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";
import {
  runWorkerChild,
  startWorkerProcess,
  type WorkerChildChannel,
  type WorkerChildSeams,
  type WorkerProcessSeams,
  type WorkerProvisionalRuntime,
  type WorkerRuntimeFactory,
  workerProcessPaths,
} from "../dev/launcher/worker-process.ts";
import {
  createParentChallenge,
  createSupervisorAdmit,
  createSupervisorReadyAck,
  parseChildIdentityHello,
  parseChildReady,
} from "../dev/launcher/worker-protocol.ts";

const sourceRevision = "a".repeat(40);
const parentIdentity = `sha256:${"1".repeat(64)}`;
const childIdentity = `sha256:${"2".repeat(64)}`;
const parentPid = 111;
const childPid = 222;

async function sandboxReady() {
  const dir = await mkdtemp(join(tmpdir(), "cogs-worker-process-"));
  const root = join(await realpath(dir), "launcher");
  await mkdir(root, { mode: 0o700 });
  const state = await resolveLauncherState({ root, name: "s1", sourceRevision });
  const manifest = await createState(state, "linux-kvm");
  await writePhase(state, manifest, "sandbox-ready");
  return { dir, state };
}

function startupSeams(identity = parentIdentity, pid = parentPid) {
  return Object.freeze({
    randomBytes: Object.freeze((() => Buffer.alloc(32, 7)) as typeof randomBytes),
    identity: Object.freeze(() => identity),
    parentPid: pid,
  });
}

function childSeams(identity: (pid: number) => string | null | undefined = identityFor): WorkerChildSeams {
  return Object.freeze({
    identity: Object.freeze(identity),
    pid: childPid,
    now: Object.freeze(() => Date.now()),
    setTimer: Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms)),
    clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
  });
}

function identityFor(pid: number): string | null {
  if (pid === parentPid) return parentIdentity;
  if (pid === childPid) return childIdentity;
  return null;
}

class TestChannel implements WorkerChildChannel {
  public readonly sent: unknown[] = [];
  public isConnected = true;
  readonly #messages = new Set<(message: unknown) => void>();
  readonly #disconnects = new Set<() => void>();

  public connected(): boolean {
    return this.isConnected;
  }
  public send(message: unknown, callback: (error: Error | null) => void): void {
    if (!this.isConnected) throw new Error("disconnected");
    this.sent.push(message);
    queueMicrotask(() => callback(null));
  }
  public onMessage(listener: (message: unknown) => void): void {
    this.#messages.add(listener);
  }
  public offMessage(listener: (message: unknown) => void): void {
    this.#messages.delete(listener);
  }
  public onDisconnect(listener: () => void): void {
    this.#disconnects.add(listener);
  }
  public offDisconnect(listener: () => void): void {
    this.#disconnects.delete(listener);
  }
  public receive(message: unknown): void {
    for (const listener of [...this.#messages]) listener(message);
  }
  public disconnect(): void {
    if (!this.isConnected) return;
    this.isConnected = false;
    for (const listener of [...this.#disconnects]) listener();
  }
  public listenerCounts(): readonly number[] {
    return [this.#messages.size, this.#disconnects.size];
  }
  public port(): WorkerChildChannel {
    return Object.freeze({
      connected: Object.freeze(() => this.connected()),
      send: Object.freeze((message: unknown, callback: (error: Error | null) => void) => this.send(message, callback)),
      onMessage: Object.freeze((listener: (message: unknown) => void) => this.onMessage(listener)),
      offMessage: Object.freeze((listener: (message: unknown) => void) => this.offMessage(listener)),
      onDisconnect: Object.freeze((listener: () => void) => this.onDisconnect(listener)),
      offDisconnect: Object.freeze((listener: () => void) => this.offDisconnect(listener)),
    });
  }
}

function runtime(close: () => Promise<void>, apiPort = 4321): WorkerProvisionalRuntime {
  return Object.freeze({ apiPort, close: Object.freeze(close) });
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("test wait timed out");
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}

async function startChild(
  startup: WorkerStartup,
  channel: TestChannel,
  state: Awaited<ReturnType<typeof sandboxReady>>["state"],
  factory: WorkerRuntimeFactory,
) {
  const pending = runWorkerChild(
    ["--cogs-launcher-worker-v1", state.root, state.name, state.sourceRevision],
    channel.port(),
    Object.freeze(factory),
    Object.freeze({ timeoutMs: 2_000, seams: childSeams() }),
  );
  await waitFor(() => channel.listenerCounts()[0] === 1);
  channel.receive(createParentChallenge(startup.startup));
  await waitFor(() => channel.sent.length === 1);
  return { pending };
}

async function bindFromHello(
  state: Awaited<ReturnType<typeof sandboxReady>>["state"],
  channel: TestChannel,
): Promise<void> {
  const hello = parseChildIdentityHello(channel.sent[0]);
  await bindWorkerChild(state, hello, Object.freeze({ identity: Object.freeze(identityFor) }));
  channel.receive(createSupervisorAdmit(hello.startupDigest));
}

test("worker child blocks before admission and removes every IPC listener on parent loss", async () => {
  const { dir, state } = await sandboxReady();
  try {
    await beginWorkerStartup(state, startupSeams());
    const channel = new TestChannel();
    let starts = 0;
    const pending = runWorkerChild(
      ["--cogs-launcher-worker-v1", state.root, state.name, state.sourceRevision],
      channel.port(),
      Object.freeze(async () => {
        starts += 1;
        return runtime(async () => undefined);
      }),
      Object.freeze({ timeoutMs: 2_000, seams: childSeams() }),
    );
    await waitFor(() => channel.listenerCounts()[0] === 1);
    channel.disconnect();
    await assert.rejects(() => pending, /^Error: launcher worker process failed$/u);
    assert.equal(starts, 0);
    assert.deepEqual(channel.listenerCounts(), [0, 0]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("worker child closes provisional runtime exactly once when parent is lost after admit", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(state, startupSeams());
    const channel = new TestChannel();
    let starts = 0;
    let closes = 0;
    const { pending } = await startChild(startup, channel, state, async () => {
      starts += 1;
      assert.equal((await readWorkerDescriptor(state)).stage, "child-bound");
      return runtime(async () => {
        closes += 1;
      });
    });
    await bindFromHello(state, channel);
    await waitFor(() => channel.sent.length === 2);
    assert.equal(parseChildReady(channel.sent[1]).apiPort, 4321);
    channel.disconnect();
    await assert.rejects(() => pending, /recovery required/u);
    assert.equal(starts, 1);
    assert.equal(closes, 1);
    assert.deepEqual(channel.listenerCounts(), [0, 0]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("worker child survives supervisor disconnect only after durable joint ready acknowledgement", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(state, startupSeams());
    const channel = new TestChannel();
    let closes = 0;
    const { pending } = await startChild(startup, channel, state, async () =>
      runtime(async () => {
        closes += 1;
      }),
    );
    await bindFromHello(state, channel);
    await waitFor(() => channel.sent.length === 2);
    const ready = parseChildReady(channel.sent[1]);
    await promoteWorkerReady(state, ready, Object.freeze({ identity: Object.freeze(identityFor) }));
    channel.receive(createSupervisorReadyAck(ready.startupDigest));
    const handle = await pending;
    assert.deepEqual(channel.listenerCounts(), [0, 0]);
    channel.disconnect();
    assert.equal(closes, 0);
    await Promise.all([handle.close(), handle.close()]);
    assert.equal(closes, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("worker child rejects malformed out-of-order duplicate and hostile messages without runtime", async () => {
  for (const message of [
    createSupervisorAdmit(parentIdentity),
    Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "parent-challenge",
      startupNonce: "x",
    }),
    Object.defineProperty({}, "type", {
      enumerable: true,
      get() {
        throw new Error("SECRET");
      },
    }),
  ]) {
    const { dir, state } = await sandboxReady();
    try {
      await beginWorkerStartup(state, startupSeams());
      const channel = new TestChannel();
      let starts = 0;
      const pending = runWorkerChild(
        ["--cogs-launcher-worker-v1", state.root, state.name, state.sourceRevision],
        channel.port(),
        Object.freeze(async () => {
          starts += 1;
          return runtime(async () => undefined);
        }),
        Object.freeze({ timeoutMs: 2_000, seams: childSeams() }),
      );
      await waitFor(() => channel.listenerCounts()[0] === 1);
      channel.receive(message);
      await assert.rejects(() => pending, /^Error: launcher worker process failed$/u);
      assert.equal(starts, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("worker child rejects descriptor replacement after admission before invoking factory", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(state, startupSeams());
    const channel = new TestChannel();
    let starts = 0;
    const { pending } = await startChild(startup, channel, state, async () => {
      starts += 1;
      return runtime(async () => undefined);
    });
    const hello = parseChildIdentityHello(channel.sent[0]);
    await bindWorkerChild(state, hello, Object.freeze({ identity: Object.freeze(identityFor) }));
    const bound = await readWorkerDescriptor(state);
    await writeFile(
      join(state.controlDir, "worker.json"),
      canonicalJson(Object.freeze({ ...bound, childPid: childPid + 1 })),
    );
    channel.receive(createSupervisorAdmit(hello.startupDigest));
    await assert.rejects(() => pending, /recovery required/u);
    assert.equal(starts, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("worker child bounds a hanging cleanup and reports close failure generically", async () => {
  for (const close of [
    Object.freeze(async () => {
      throw new Error("SECRET close");
    }),
    Object.freeze(async () => await new Promise<void>(() => undefined)),
  ]) {
    const { dir, state } = await sandboxReady();
    try {
      const startup = await beginWorkerStartup(state, startupSeams());
      const channel = new TestChannel();
      const { pending } = await startChild(startup, channel, state, async () => runtime(close));
      void pending.catch(() => undefined);
      await bindFromHello(state, channel);
      await waitFor(() => channel.sent.length === 2);
      channel.disconnect();
      await assert.rejects(
        () => pending,
        (error: unknown) => error instanceof Error && error.message === "launcher worker process recovery required",
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("worker child aborts a hanging factory and closes one late runtime without sending ready", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(state, startupSeams());
    const channel = new TestChannel();
    let resolveFactory: ((value: WorkerProvisionalRuntime) => void) | undefined;
    let factorySignal: AbortSignal | undefined;
    let factoryState: unknown;
    let closes = 0;
    const { pending } = await startChild(startup, channel, state, async (loadedState, signal) => {
      factoryState = loadedState;
      factorySignal = signal;
      return await new Promise<WorkerProvisionalRuntime>((resolve) => {
        resolveFactory = resolve;
      });
    });
    void pending.catch(() => undefined);
    await bindFromHello(state, channel);
    await waitFor(() => factorySignal !== undefined);
    assert.deepEqual(factoryState, state);
    channel.disconnect();
    await assert.rejects(() => pending, /recovery required/u);
    assert.equal(factorySignal?.aborted, true);
    assert.equal(channel.sent.length, 1);
    resolveFactory?.(
      runtime(async () => {
        closes += 1;
      }),
    );
    await waitFor(() => closes === 1);
    assert.equal(channel.sent.length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("worker child uses durable joint readiness when disconnect precedes ready ack processing", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(state, startupSeams());
    const channel = new TestChannel();
    let closes = 0;
    const { pending } = await startChild(startup, channel, state, async () =>
      runtime(async () => {
        closes += 1;
      }),
    );
    await bindFromHello(state, channel);
    await waitFor(() => channel.sent.length === 2);
    const ready = parseChildReady(channel.sent[1]);
    await promoteWorkerReady(state, ready, Object.freeze({ identity: Object.freeze(identityFor) }));
    channel.disconnect();
    const handle = await pending;
    assert.equal(closes, 0);
    await handle.close();
    assert.equal(closes, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("worker child rejects synchronous timers and timer cleanup failure before runtime start", async () => {
  for (const mode of ["synchronous", "clear-throw"] as const) {
    const { dir, state } = await sandboxReady();
    try {
      await beginWorkerStartup(state, startupSeams());
      const channel = new TestChannel();
      let starts = 0;
      const seams: WorkerChildSeams = Object.freeze({
        identity: Object.freeze(identityFor),
        pid: childPid,
        now: Object.freeze(() => Date.now()),
        setTimer: Object.freeze((callback: () => void) => {
          if (mode === "synchronous") callback();
          return {};
        }),
        clearTimer: Object.freeze(() => {
          if (mode === "clear-throw") throw new Error("SECRET clear");
        }),
      });
      const pending = runWorkerChild(
        ["--cogs-launcher-worker-v1", state.root, state.name, state.sourceRevision],
        channel.port(),
        Object.freeze(async () => {
          starts += 1;
          return runtime(async () => undefined);
        }),
        Object.freeze({ timeoutMs: 100, seams }),
      );
      await waitFor(() => channel.listenerCounts()[0] === 1 || mode === "synchronous");
      if (mode === "clear-throw") channel.disconnect();
      await assert.rejects(() => pending);
      assert.equal(starts, 0);
      assert.deepEqual(channel.listenerCounts(), [0, 0]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("worker process rejects stale source coordinates and unfrozen runtime factory before listeners", async () => {
  const first = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(first.state, startupSeams());
    const newer = await resolveLauncherState({
      root: first.state.root,
      name: first.state.name,
      sourceRevision: "b".repeat(40),
    });
    let spawned = false;
    const seams: WorkerProcessSeams = Object.freeze({
      spawn: Object.freeze((() => {
        spawned = true;
        throw new Error("must not spawn");
      }) as unknown as typeof spawn),
      identity: Object.freeze(identityFor),
      now: Object.freeze(() => Date.now()),
      setTimer: Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms)),
      clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    });
    await assert.rejects(() => startWorkerProcess(newer, startup, Object.freeze({ seams })));
    assert.equal(spawned, false);
  } finally {
    await rm(first.dir, { recursive: true, force: true });
  }

  const second = await sandboxReady();
  try {
    await beginWorkerStartup(second.state, startupSeams());
    const channel = new TestChannel();
    const unfrozen = async (_state: unknown, _signal: AbortSignal) => runtime(async () => undefined);
    await assert.rejects(() =>
      runWorkerChild(
        ["--cogs-launcher-worker-v1", second.state.root, second.state.name, second.state.sourceRevision],
        channel.port(),
        unfrozen,
      ),
    );
    assert.deepEqual(channel.listenerCounts(), [0, 0]);
  } finally {
    await rm(second.dir, { recursive: true, force: true });
  }
});

test("supervisor handles synchronous spawn failure without changing durable pre-spawn state", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(state, startupSeams());
    const seams: WorkerProcessSeams = Object.freeze({
      spawn: Object.freeze((() => {
        throw new Error("SECRET spawn");
      }) as unknown as typeof spawn),
      identity: Object.freeze(identityFor),
      now: Object.freeze(() => Date.now()),
      setTimer: Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms)),
      clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    });
    await assert.rejects(
      () => startWorkerProcess(state, startup, Object.freeze({ seams })),
      /^Error: launcher worker process failed$/u,
    );
    assert.equal((await readWorkerDescriptor(state)).stage, "pre-spawn");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor rejects send failures duplicate processing and out-of-order messages without readiness", async () => {
  for (const mode of ["send-throw", "send-callback", "duplicate", "out-of-order"] as const) {
    const { dir, state } = await sandboxReady();
    try {
      const startup = await beginWorkerStartup(state, startupSeams());
      const child = new EventEmitter() as EventEmitter & ChildProcess;
      Object.defineProperties(child, {
        pid: { value: childPid, enumerable: true },
        connected: { value: true, enumerable: true },
      });
      let kills = 0;
      child.kill = (() => {
        kills += 1;
        return true;
      }) as ChildProcess["kill"];
      child.disconnect = (() => undefined) as ChildProcess["disconnect"];
      let unrefs = 0;
      child.unref = (() => {
        unrefs += 1;
      }) as ChildProcess["unref"];
      child.send = ((message: unknown, callback?: (error: Error | null) => void) => {
        if (mode === "send-throw") throw new Error("SECRET send");
        if (mode === "send-callback") {
          queueMicrotask(() => callback?.(new Error("SECRET callback")));
          return true;
        }
        const challenge = message as { startupNonce: string };
        const hello = {
          version: "cogs.dev-launcher-worker-protocol/v1alpha1",
          type: mode === "out-of-order" ? "child-ready" : "child-identity",
          startupDigest: startup.startup.digest(),
          pid: childPid,
          pidIdentity: childIdentity,
          ...(mode === "out-of-order" ? { apiPort: 4321 } : {}),
        };
        queueMicrotask(() => {
          child.emit("message", hello);
          if (mode === "duplicate") child.emit("message", hello);
          callback?.(null);
          assert.equal(typeof challenge.startupNonce, "string");
        });
        return true;
      }) as ChildProcess["send"];
      const seams: WorkerProcessSeams = Object.freeze({
        spawn: Object.freeze((() => child) as unknown as typeof spawn),
        identity: Object.freeze(identityFor),
        now: Object.freeze(() => Date.now()),
        setTimer: Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms)),
        clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
      });
      await assert.rejects(() => startWorkerProcess(state, startup, Object.freeze({ timeoutMs: 500, seams })));
      assert.equal((await readWorkerDescriptor(state)).stage, "pre-spawn");
      assert.equal(kills, 1);
      assert.equal(unrefs, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("supervisor handles child terminal events abort and listener failures without PID-only signal", async () => {
  for (const mode of ["exit", "error", "disconnect", "abort", "on-throw", "off-throw"] as const) {
    const { dir, state } = await sandboxReady();
    try {
      const startup = await beginWorkerStartup(state, startupSeams());
      const child = new EventEmitter() as EventEmitter & ChildProcess;
      Object.defineProperties(child, {
        pid: { value: childPid, enumerable: true },
        connected: { value: true, enumerable: true },
      });
      let kills = 0;
      child.kill = (() => {
        kills += 1;
        return true;
      }) as ChildProcess["kill"];
      child.disconnect = (() => undefined) as ChildProcess["disconnect"];
      child.unref = (() => undefined) as ChildProcess["unref"];
      child.send = ((_message: unknown, callback?: (error: Error | null) => void) => {
        queueMicrotask(() => {
          callback?.(null);
          if (mode === "exit" || mode === "error" || mode === "disconnect")
            child.emit(mode, mode === "error" ? new Error("SECRET child") : undefined);
        });
        return true;
      }) as ChildProcess["send"];
      if (mode === "on-throw")
        child.on = (() => {
          throw new Error("SECRET on");
        }) as ChildProcess["on"];
      if (mode === "off-throw")
        child.off = (() => {
          throw new Error("SECRET off");
        }) as ChildProcess["off"];
      let identityCalls = 0;
      const seams: WorkerProcessSeams = Object.freeze({
        spawn: Object.freeze((() => child) as unknown as typeof spawn),
        identity: Object.freeze(() => {
          identityCalls += 1;
          if (mode === "exit" || mode === "error" || mode === "disconnect")
            return identityCalls === 1 ? childIdentity : null;
          return childIdentity;
        }),
        now: Object.freeze(() => Date.now()),
        setTimer: Object.freeze((callback: () => void, ms: number) => {
          if (mode === "off-throw") queueMicrotask(callback);
          return setTimeout(callback, ms);
        }),
        clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
      });
      const controller = new AbortController();
      const pending = startWorkerProcess(
        state,
        startup,
        Object.freeze({ timeoutMs: 500, signal: controller.signal, seams }),
      );
      if (mode === "abort") setTimeout(() => controller.abort(), 10);
      await assert.rejects(() => pending);
      assert.equal((await readWorkerDescriptor(state)).readiness, "starting");
      if (mode === "exit" || mode === "error" || mode === "disconnect") assert.equal(kills, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("supervisor rejects PID mismatch reuse absent unavailable and malformed identity without unsafe signal", async () => {
  for (const mode of ["mismatch", "reuse", "null", "undefined", "malformed"] as const) {
    const { dir, state } = await sandboxReady();
    try {
      const startup = await beginWorkerStartup(state, startupSeams());
      const child = new EventEmitter() as EventEmitter & ChildProcess;
      Object.defineProperties(child, {
        pid: { value: childPid, enumerable: true },
        connected: { value: true, enumerable: true },
      });
      let kills = 0;
      child.kill = (() => {
        kills += 1;
        return true;
      }) as ChildProcess["kill"];
      child.disconnect = (() => undefined) as ChildProcess["disconnect"];
      child.unref = (() => undefined) as ChildProcess["unref"];
      child.send = ((_message: unknown, callback?: (error: Error | null) => void) => {
        if (mode === "mismatch" || mode === "reuse") {
          queueMicrotask(() => {
            child.emit("message", {
              version: "cogs.dev-launcher-worker-protocol/v1alpha1",
              type: "child-identity",
              startupDigest: startup.startup.digest(),
              pid: mode === "mismatch" ? childPid + 1 : childPid,
              pidIdentity: childIdentity,
            });
            callback?.(null);
          });
        }
        return true;
      }) as ChildProcess["send"];
      let calls = 0;
      const identity = Object.freeze((): string | null | undefined => {
        calls += 1;
        if (mode === "null") return null;
        if (mode === "undefined") return undefined;
        if (mode === "malformed") return "pid:bad";
        if (mode === "reuse" && calls > 1) return parentIdentity;
        return childIdentity;
      });
      const seams: WorkerProcessSeams = Object.freeze({
        spawn: Object.freeze((() => child) as unknown as typeof spawn),
        identity,
        now: Object.freeze(() => Date.now()),
        setTimer: Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms)),
        clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
      });
      await assert.rejects(() => startWorkerProcess(state, startup, Object.freeze({ timeoutMs: 100, seams })));
      assert.equal((await readWorkerDescriptor(state)).stage, "pre-spawn");
      if (mode !== "mismatch") assert.equal(kills, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("supervisor cleans listeners and timer when connected getter throws during initial send", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(state, startupSeams());
    const child = new EventEmitter() as EventEmitter & ChildProcess;
    Object.defineProperties(child, {
      pid: { value: childPid, enumerable: true },
      connected: {
        get() {
          throw new Error("SECRET connected");
        },
        enumerable: true,
      },
    });
    child.send = (() => true) as ChildProcess["send"];
    child.disconnect = (() => undefined) as ChildProcess["disconnect"];
    let unrefs = 0;
    child.unref = (() => {
      unrefs += 1;
    }) as ChildProcess["unref"];
    child.kill = (() => true) as ChildProcess["kill"];
    let clears = 0;
    const seams: WorkerProcessSeams = Object.freeze({
      spawn: Object.freeze((() => child) as unknown as typeof spawn),
      identity: Object.freeze(identityFor),
      now: Object.freeze(() => Date.now()),
      setTimer: Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms)),
      clearTimer: Object.freeze((timer: unknown) => {
        clears += 1;
        clearTimeout(timer as NodeJS.Timeout);
      }),
    });
    await assert.rejects(() => startWorkerProcess(state, startup, Object.freeze({ timeoutMs: 500, seams })));
    assert.equal(clears, 1);
    assert.equal(child.listenerCount("message"), 0);
    assert.equal(child.listenerCount("disconnect"), 0);
    assert.equal(child.listenerCount("error"), 0);
    assert.equal(child.listenerCount("exit"), 0);
    assert.equal(unrefs, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("second hostile clock read creates no parent or child listener and starts no runtime", async () => {
  const parentCase = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(parentCase.state, startupSeams());
    const child = new EventEmitter() as EventEmitter & ChildProcess;
    let connected = true;
    Object.defineProperties(child, {
      pid: { value: childPid, enumerable: true },
      connected: { get: () => connected, enumerable: true },
    });
    child.send = (() => true) as ChildProcess["send"];
    child.disconnect = (() => {
      connected = false;
    }) as ChildProcess["disconnect"];
    let unrefs = 0;
    child.unref = (() => {
      unrefs += 1;
    }) as ChildProcess["unref"];
    child.kill = (() => true) as ChildProcess["kill"];
    let nowCalls = 0;
    let timers = 0;
    const seams: WorkerProcessSeams = Object.freeze({
      spawn: Object.freeze((() => child) as unknown as typeof spawn),
      identity: Object.freeze(identityFor),
      now: Object.freeze(() => {
        nowCalls += 1;
        if (nowCalls === 2) throw new Error("SECRET clock");
        return Date.now();
      }),
      setTimer: Object.freeze((callback: () => void, ms: number) => {
        timers += 1;
        return setTimeout(callback, ms);
      }),
      clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    });
    await assert.rejects(() => startWorkerProcess(parentCase.state, startup, Object.freeze({ seams })));
    assert.equal(timers, 0);
    assert.equal(child.eventNames().length, 0);
    assert.equal(unrefs, 0);
  } finally {
    await rm(parentCase.dir, { recursive: true, force: true });
  }

  const childCase = await sandboxReady();
  try {
    await beginWorkerStartup(childCase.state, startupSeams());
    const channel = new TestChannel();
    let nowCalls = 0;
    let starts = 0;
    const seams: WorkerChildSeams = Object.freeze({
      identity: Object.freeze(identityFor),
      pid: childPid,
      now: Object.freeze(() => {
        nowCalls += 1;
        if (nowCalls === 2) throw new Error("SECRET clock");
        return Date.now();
      }),
      setTimer: Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms)),
      clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    });
    await assert.rejects(() =>
      runWorkerChild(
        ["--cogs-launcher-worker-v1", childCase.state.root, childCase.state.name, childCase.state.sourceRevision],
        channel.port(),
        Object.freeze(async () => {
          starts += 1;
          return runtime(async () => undefined);
        }),
        Object.freeze({ seams }),
      ),
    );
    assert.deepEqual(channel.listenerCounts(), [0, 0]);
    assert.equal(starts, 0);
  } finally {
    await rm(childCase.dir, { recursive: true, force: true });
  }
});

test("supervisor uses one fixed shell-free Node/tsx argv and completes durable ordering", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(state, startupSeams());
    const events: string[] = ["descriptor"];
    let childRun: Promise<WorkerProvisionalRuntime> | undefined;
    let capturedArgv: readonly string[] = [];
    let capturedOptions: Record<string, unknown> = {};
    const child = new EventEmitter() as EventEmitter & ChildProcess;
    let connected = true;
    Object.defineProperties(child, {
      pid: { value: childPid, enumerable: true },
      connected: { get: () => connected, enumerable: true },
    });
    child.send = ((message: unknown, callback?: (error: Error | null) => void) => {
      events.push((message as { type: string }).type);
      void waitFor(() => childChannel.listenerCounts()[0] === 1).then(() => {
        childChannel.receive(message);
        if ((message as { type: string }).type === "supervisor-ready-ack") events.push("ready-ack-delivered");
        callback?.(null);
      });
      return true;
    }) as ChildProcess["send"];
    child.disconnect = (() => {
      events.push("disconnect");
      connected = false;
      childChannel.disconnect();
    }) as ChildProcess["disconnect"];
    let unrefs = 0;
    child.unref = (() => {
      events.push("unref");
      unrefs += 1;
    }) as ChildProcess["unref"];
    child.kill = (() => true) as ChildProcess["kill"];
    const childChannel = new TestChannel();
    childChannel.send = ((message: unknown, callback: (error: Error | null) => void) => {
      childChannel.sent.push(message);
      events.push((message as { type: string }).type);
      queueMicrotask(() => {
        child.emit("message", message);
        callback(null);
      });
    }) as never;
    const spawnSeam = Object.freeze(((executable: string, args: readonly string[], options: unknown) => {
      assert.equal(executable, workerProcessPaths.executable);
      capturedArgv = [...args];
      capturedOptions = options as Record<string, unknown>;
      queueMicrotask(() => {
        childRun = runWorkerChild(
          args.slice(3),
          childChannel.port(),
          Object.freeze(async () => {
            events.push("runtime-start");
            assert.equal((await readWorkerDescriptor(state)).stage, "child-bound");
            return runtime(async () => undefined, 4567);
          }),
          Object.freeze({ timeoutMs: 2_000, seams: childSeams() }),
        );
      });
      return child;
    }) as unknown as typeof spawn);
    const seams: WorkerProcessSeams = Object.freeze({
      spawn: spawnSeam,
      identity: Object.freeze(identityFor),
      now: Object.freeze(() => Date.now()),
      setTimer: Object.freeze((callback: () => void, ms: number) => setTimeout(callback, ms)),
      clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    });
    const descriptor = await startWorkerProcess(state, startup, Object.freeze({ timeoutMs: 2_000, seams }));
    assert.equal(descriptor.apiPort, 4567);
    assert.equal(capturedArgv[0], "--import");
    assert.deepEqual(capturedArgv.slice(1, 3), [workerProcessPaths.loader, workerProcessPaths.entry]);
    assert.equal(
      capturedArgv.some((item) => item.includes(Buffer.alloc(32, 7).toString("base64url"))),
      false,
    );
    assert.equal(capturedOptions.shell, false);
    assert.deepEqual(capturedOptions.env, {});
    assert.deepEqual(capturedOptions.stdio, ["ignore", "ignore", "ignore", "ipc"]);
    assert.deepEqual(events, [
      "descriptor",
      "parent-challenge",
      "child-identity",
      "supervisor-admit",
      "runtime-start",
      "child-ready",
      "supervisor-ready-ack",
      "ready-ack-delivered",
      "disconnect",
      "unref",
    ]);
    assert.equal(unrefs, 1);
    await childRun;
    assert.equal((await readFile(join(state.controlDir, "worker.json"), "utf8")).includes("BwcH"), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor abort and unavailable identity preserve starting descriptor without pid-only signal", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const startup = await beginWorkerStartup(state, startupSeams());
    const child = new EventEmitter() as EventEmitter & ChildProcess;
    let connected = true;
    Object.defineProperties(child, {
      pid: { value: childPid, enumerable: true },
      connected: { get: () => connected, enumerable: true },
    });
    child.send = (() => true) as ChildProcess["send"];
    child.disconnect = (() => {
      connected = false;
    }) as ChildProcess["disconnect"];
    child.unref = (() => undefined) as ChildProcess["unref"];
    let kills = 0;
    child.kill = (() => {
      kills += 1;
      return true;
    }) as ChildProcess["kill"];
    let identityCalls = 0;
    const seams: WorkerProcessSeams = Object.freeze({
      spawn: Object.freeze((() => child) as unknown as typeof spawn),
      identity: Object.freeze(() => {
        identityCalls += 1;
        return identityCalls === 1 ? childIdentity : undefined;
      }),
      now: Object.freeze(() => Date.now()),
      setTimer: Object.freeze((callback: () => void) => {
        queueMicrotask(callback);
        return {};
      }),
      clearTimer: Object.freeze(() => undefined),
    });
    await assert.rejects(
      () => startWorkerProcess(state, startup, Object.freeze({ timeoutMs: 1, seams })),
      /recovery required/u,
    );
    assert.equal(kills, 0);
    assert.equal((await readWorkerDescriptor(state)).stage, "pre-spawn");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("worker entry statically wires trusted runtime factory only", async () => {
  const source = await readFile(new URL("../dev/launcher/worker-entry.ts", import.meta.url), "utf8");
  assert.match(source, /import \{ createTrustedWorkerRuntime \} from "\.\/trusted-compose\.ts";/u);
  assert.match(
    source,
    /const trustedRuntimeFactory = Object\.freeze\(\(state: LauncherState, signal: AbortSignal\) =>\s*createTrustedWorkerRuntime\(state, signal\),\s*\);/u,
  );
  assert.doesNotMatch(source, /unavailableWorkerRuntime/u);
});

test("real inherited IPC child validates admission then fails closed with no default runtime", async () => {
  const { dir, state } = await sandboxReady();
  try {
    const identity = observeProcessIdentity(process.pid);
    if (identity === undefined || identity === null) return;
    const startup = await beginWorkerStartup(state);
    assert.equal(startup.descriptor.parentPid, process.pid);
    assert.equal(startup.descriptor.parentPidIdentity, observeProcessIdentity(process.pid));
    await assert.rejects(
      () => startWorkerProcess(state, startup, Object.freeze({ timeoutMs: 5_000 })),
      /recovery required/u,
    );
    const descriptor = await readWorkerDescriptor(state);
    assert.equal(descriptor.readiness, "starting");
    assert.ok(descriptor.stage === "pre-spawn" || descriptor.stage === "child-bound");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

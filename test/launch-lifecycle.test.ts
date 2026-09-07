import assert from "node:assert/strict";
import test from "node:test";
import {
  beginRegisteredClose,
  CloseObservationError,
  type CloseWork,
  closeContext,
  createCloseOwner,
  joinCloseWork,
  observeClose,
  registerCloseOwner,
} from "../src/launch/close.ts";
import { LaunchConfigError, validateLaunchConfig } from "../src/launch/config.ts";
import {
  createCogsEgressRuntimeLaunchDependency,
  type LaunchDependency,
  LaunchLifecycle,
  LaunchLifecycleError,
  type Scheduler,
  type SignalSource,
  type TimerHandle,
} from "../src/launch/lifecycle.ts";

const digest = `sha256:${"a".repeat(64)}`;

function validLaunch(): unknown {
  return {
    version: "cogs.dev/v1alpha1",
    user_id: "user-1",
    session_id: "session-1",
    workspace_id: "workspace-1",
    sandbox: {
      ssh_endpoint: "sandbox.local:2222",
      ssh_host_key: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      client_key_path: "/run/cogs/ssh/session-1",
      proxy_auth_handle: "sessions/session-1/proxy",
    },
    model: { provider: "provider-1", id: "model", credential_handle: "users/user-1/model" },
    skills: {
      shared_revision: digest,
      shared_path: "/shared/skills",
      user_revision: digest,
      user_path: "/user/skills",
    },
    integrations: [],
    limits: { cpu: 1, memory_bytes: 268435456, tool_timeout_seconds: 30, max_tool_output_bytes: 4096 },
  };
}

function dependencies(overrides: Partial<Record<string, Partial<LaunchDependency>>> = {}): LaunchDependency[] {
  return (["sessionStorage", "ssh", "proxy", "auth", "auditWal", "egressRuntime"] as const).map((name) => ({
    name,
    start: async () => undefined,
    shutdown: async () => undefined,
    ...overrides[name],
  }));
}

class FakeScheduler implements Scheduler {
  public current = 1000;
  readonly #timers = new Map<number, { due: number; callback: () => void }>();
  #nextId = 1;

  public now(): number {
    return this.current;
  }

  public get pendingTimers(): number {
    return this.#timers.size;
  }

  public setTimer(milliseconds: number, callback: () => void): TimerHandle {
    const id = this.#nextId;
    this.#nextId += 1;
    this.#timers.set(id, { due: this.current + milliseconds, callback });
    return {
      cancel: () => {
        this.#timers.delete(id);
      },
    };
  }

  public advance(milliseconds: number): void {
    this.current += milliseconds;
    for (;;) {
      const next = [...this.#timers.entries()]
        .filter(([, timer]) => timer.due <= this.current)
        .sort((a, b) => a[1].due - b[1].due || a[0] - b[0])[0];
      if (next === undefined) return;
      this.#timers.delete(next[0]);
      next[1].callback();
    }
  }
}

class ManualSignals implements SignalSource {
  #handler: ((signal: "SIGINT" | "SIGTERM") => void) | undefined;
  public disposed = false;

  public onSignal(handler: (signal: "SIGINT" | "SIGTERM") => void) {
    assert.equal(this.#handler, undefined);
    this.#handler = handler;
    return {
      dispose: () => {
        this.disposed = true;
        this.#handler = undefined;
      },
    };
  }

  public emit(signal: "SIGINT" | "SIGTERM"): void {
    this.#handler?.(signal);
  }
}

function abortableBlock(signal: AbortSignal, onAbort: () => void): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      onAbort();
      resolve();
      return;
    }
    signal.addEventListener(
      "abort",
      () => {
        onAbort();
        resolve();
      },
      { once: true },
    );
  });
}

test("close owners publish before seal/body reentry and reject unknown or failed ownership", async () => {
  let calls = 0;
  let nested: CloseWork | undefined;
  let sealed: CloseWork | undefined;
  const begin = createCloseOwner(
    () => {
      calls++;
      nested = begin();
      return Promise.resolve();
    },
    () => {
      sealed = begin();
    },
  );
  const handle = registerCloseOwner(Object.freeze({ close: () => observeClose(begin(), closeContext(1000)) }), begin);
  const work = beginRegisteredClose(handle);
  assert.equal(work, nested);
  assert.equal(work, sealed);
  assert.equal(calls, 1);
  assert.deepEqual(Object.keys(handle), ["close"]);
  assert.throws(() => beginRegisteredClose({ close: handle.close }), CloseObservationError);
  await joinCloseWork(work);
  for (const execute of [
    () => {
      throw new Error("synthetic secret");
    },
    () => ({}) as CloseWork,
  ]) {
    const failed = createCloseOwner(execute);
    await assert.rejects(observeClose(failed(), closeContext(1000)), /cleanup error/);
    await assert.rejects(observeClose(failed(), closeContext(1000)), /cleanup error/);
    await assert.rejects(failed().retired);
  }
});

test("close observers have independent reversed deadlines, aborts, and no actual cancellation", async () => {
  for (const reversed of [false, true]) {
    const clock = new FakeScheduler();
    const actual = Promise.withResolvers<void>();
    const begin = createCloseOwner(() => actual.promise);
    const short = closeContext(5, clock),
      long = closeContext(20, clock);
    const contexts = reversed ? [long, short] : [short, long];
    const observers = contexts.map((context) => observeClose(begin(), context, clock));
    const shortObserver = observers[reversed ? 1 : 0];
    assert.ok(shortObserver);
    const expires = assert.rejects(shortObserver, /cleanup deadline/);
    clock.advance(5);
    await expires;
    assert.equal(short.signal.aborted, false);
    assert.equal(long.signal.aborted, false);
    assert.equal(clock.pendingTimers, 1);
    actual.resolve();
    await observers[reversed ? 0 : 1];
    assert.equal(clock.pendingTimers, 0);
    await assert.rejects(observeClose(begin(), { ...long, signal: AbortSignal.abort() }, clock), /cancelled/);
    await assert.rejects(observeClose(begin(), short, clock), /deadline/);
    await observeClose(begin(), long, clock);
  }
  const clock = new FakeScheduler(),
    controller = new AbortController();
  let getterCalls = 0;
  for (const key of ["aborted", "addEventListener", "removeEventListener"])
    Object.defineProperty(controller.signal, key, {
      get: () => {
        getterCalls++;
        throw new Error("shadow");
      },
    });
  const actual = Promise.withResolvers<void>(),
    work = { done: actual.promise, retired: actual.promise };
  const a = observeClose(work, { ...closeContext(10, clock), signal: controller.signal }, clock);
  const failed = assert.rejects(a, /cancelled/);
  const b = observeClose(work, closeContext(10, clock), clock);
  controller.abort();
  await failed;
  actual.resolve();
  await b;
  assert.equal(getterCalls, 0);
  assert.equal(clock.pendingTimers, 0);
});

test("close deadline wins exact-time completion in either order; timer failure never poisons actual work", async () => {
  for (const timerFirst of [false, true]) {
    const clock = new FakeScheduler(),
      actual = Promise.withResolvers<void>();
    const work = { done: actual.promise, retired: actual.promise };
    const failed = assert.rejects(observeClose(work, closeContext(5, clock), clock), /deadline/);
    if (timerFirst) clock.advance(5);
    else clock.current += 5;
    actual.resolve();
    await failed;
    assert.equal(clock.pendingTimers, 0);
    await observeClose(work, closeContext(5, clock), clock);
  }
  for (const sync of [false, true]) {
    let cancelled = 0;
    const clock = {
      now: () => 0,
      setTimer: (_ms: number, cb: () => void) => {
        if (!sync) throw new Error("timer setup");
        cb();
        return {
          cancel: () => {
            cancelled++;
          },
        };
      },
    };
    const work = { done: Promise.resolve(), retired: Promise.resolve() };
    await assert.rejects(observeClose(work, closeContext(10, clock), clock), sync ? /deadline/ : /error/);
    assert.equal(cancelled, sync ? 1 : 0);
    await observeClose(work, closeContext(1000));
  }
  for (const field of ["done", "retired"] as const) {
    const pending = Promise.withResolvers<void>();
    const work = { done: pending.promise, retired: pending.promise, [field]: Promise.reject(new Error("secret")) };
    await assert.rejects(observeClose(work, closeContext(1000)), /cleanup error/);
    pending.resolve();
    await assert.rejects(observeClose(work, closeContext(1000)), /cleanup error/);
  }
});

test("launch validation is strict, redacted, clone-safe, and immutable", () => {
  const source = validLaunch() as Record<string, unknown>;
  const config = validateLaunchConfig(source);
  assert.notEqual(config, source);
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(config.sandbox), true);
  assert.throws(() => {
    (config.sandbox as { ssh_endpoint: string }).ssh_endpoint = "evil.local:1";
  }, TypeError);

  for (const malformed of [
    { ...(validLaunch() as Record<string, unknown>), extra: true },
    {
      ...(validLaunch() as Record<string, unknown>),
      limits: { ...(validLaunch() as { limits: Record<string, unknown> }).limits, cpu: "1" },
    },
    {
      ...(validLaunch() as Record<string, unknown>),
      sandbox: { ...(validLaunch() as { sandbox: Record<string, unknown> }).sandbox, ssh_endpoint: "sandbox.local" },
    },
    { ...(validLaunch() as Record<string, unknown>), uncloneable: () => "users/user-1/model" },
  ]) {
    assert.throws(
      () => validateLaunchConfig(malformed),
      (error: unknown) => {
        assert.ok(error instanceof LaunchConfigError);
        assert.match(error.message, /invalid launch document/);
        assert.doesNotMatch(JSON.stringify(error), /evil|sandbox\.local:2222|users\/user-1\/model/);
        return true;
      },
    );
  }
});

test("readiness is false until all fixed dependencies are ready and ready config resists mutation", async () => {
  const events: string[] = [];
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies(),
    onEvent: (event) => events.push(`${event.state}:${event.ready}`),
  });
  assert.equal(lifecycle.ready, false);
  await lifecycle.start();
  assert.equal(lifecycle.state, "ready");
  assert.equal(lifecycle.ready, true);
  assert.ok(lifecycle.readyConfig);
  assert.throws(() => {
    (lifecycle.readyConfig as { user_id: string }).user_id = "changed";
  }, TypeError);
  assert.deepEqual(events, ["starting:false", "ready:true"]);
});

test("normal recycle waits for settled turn, emits one notice, and leaves no timer", async () => {
  const scheduler = new FakeScheduler();
  const notices: string[] = [];
  const order: string[] = [];
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      auditWal: {
        shutdown: async () => {
          order.push("auditWal");
        },
      },
    }),
    scheduler,
    recycleAfterMs: 20,
    emergencyHardDeadlineMs: 50,
    onRecycleNotice: (notice) => notices.push(`${notice.reason}:${notice.deadlineMs}`),
  });
  await lifecycle.start();
  scheduler.advance(20);
  scheduler.advance(20);
  assert.equal(lifecycle.ready, true);
  assert.equal(lifecycle.recyclePending, true);
  assert.deepEqual(notices, ["normal-recycle-deadline:1070"]);
  await lifecycle.turnSettled();
  assert.equal(lifecycle.state, "stopped");
  assert.deepEqual(order, ["auditWal"]);
  assert.equal(scheduler.pendingTimers, 0);
});

test("emergency recycle deadline forces shutdown when no settled turn arrives", async () => {
  const scheduler = new FakeScheduler();
  let auditAborted = false;
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      auditWal: {
        shutdown: (signal) =>
          abortableBlock(signal, () => {
            auditAborted = true;
          }),
      },
    }),
    scheduler,
    recycleAfterMs: 10,
    emergencyHardDeadlineMs: 30,
    shutdownTimeoutMs: 5,
  });
  await lifecycle.start();
  scheduler.advance(10);
  const shutdown = new Promise<void>((resolve) => setImmediate(resolve)).then(() => undefined);
  scheduler.advance(30);
  await shutdown;
  scheduler.advance(5);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(lifecycle.state, "failed");
  assert.equal(auditAborted, true);
  assert.equal(scheduler.pendingTimers, 0);
});

test("operator and signal shutdown are immediate and do not emit recycle notice", async () => {
  const scheduler = new FakeScheduler();
  const signals = new ManualSignals();
  const notices: string[] = [];
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies(),
    scheduler,
    signals,
    recycleAfterMs: 100,
    onRecycleNotice: (notice) => notices.push(notice.reason),
  });
  await lifecycle.start();
  signals.emit("SIGTERM");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(lifecycle.state, "stopped");
  assert.deepEqual(notices, []);
  assert.equal(signals.disposed, true);
  assert.equal(scheduler.pendingTimers, 0);
});

test("startup interruption prevents later dependencies from starting and cleans attempted dependencies in reverse order", async () => {
  const calls: string[] = [];
  let unblockSession: (() => void) | undefined;
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      sessionStorage: {
        start: async () => {
          calls.push("start:sessionStorage");
          await new Promise<void>((resolve) => {
            unblockSession = resolve;
          });
        },
        shutdown: async () => {
          calls.push("shutdown:sessionStorage");
        },
      },
      ssh: {
        start: async () => {
          calls.push("start:ssh");
        },
        shutdown: async () => {
          calls.push("shutdown:ssh");
        },
      },
    }),
  });
  const started = lifecycle.start();
  await new Promise((resolve) => setImmediate(resolve));
  const shuttingDown = lifecycle.requestShutdown("operator");
  assert.ok(unblockSession);
  unblockSession();
  await Promise.all([started, shuttingDown]);
  assert.equal(lifecycle.state, "stopped");
  assert.deepEqual(calls, ["start:sessionStorage", "shutdown:sessionStorage"]);
});

test("non-cooperative unresolved start makes bounded shutdown uncertain and cannot start later dependencies", async () => {
  const signals = new ManualSignals();
  const scheduler = new FakeScheduler();
  const calls: string[] = [];
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      sessionStorage: {
        start: async () => {
          calls.push("start:sessionStorage");
          return new Promise(() => undefined);
        },
        shutdown: async () => {
          calls.push("shutdown:sessionStorage");
        },
      },
      ssh: {
        start: async () => {
          calls.push("start:ssh");
        },
      },
    }),
    signals,
    scheduler,
    shutdownTimeoutMs: 5,
  });
  const started = lifecycle.start();
  await new Promise((resolve) => setImmediate(resolve));
  signals.emit("SIGINT");
  await new Promise((resolve) => setImmediate(resolve));
  scheduler.advance(5);
  await assert.rejects(started, /cleanup uncertain/);
  assert.equal(lifecycle.state, "failed");
  assert.equal(signals.disposed, true);
  assert.deepEqual(calls, ["start:sessionStorage"]);
  assert.ok(lifecycle.closeWork, "actual unresolved startup remains owned");
});

test("shutdown during startup aborts active dependency start and leaves no dangling operation", async () => {
  let startAborted = false;
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      sessionStorage: {
        start: (signal) =>
          abortableBlock(signal, () => {
            startAborted = true;
          }),
      },
    }),
  });
  const started = lifecycle.start();
  await new Promise((resolve) => setImmediate(resolve));
  const shutdown = lifecycle.requestShutdown("operator");
  await Promise.all([started, shutdown]);
  assert.equal(startAborted, true);
  assert.equal(lifecycle.state, "stopped");
});

test("public dispose fails closed and cannot leave a ready worker ready", async () => {
  const scheduler = new FakeScheduler();
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies(),
    scheduler,
    recycleAfterMs: 10,
  });
  await lifecycle.start();
  assert.equal(lifecycle.ready, true);
  await lifecycle.dispose();
  assert.equal(lifecycle.ready, false);
  assert.equal(lifecycle.state, "stopped");
  assert.equal(scheduler.pendingTimers, 0);
});

test("lifecycle abort, event, and dependency callbacks reenter one published shutdown owner", async () => {
  const nested: Promise<void>[] = [];
  let closes = 0,
    readyEvents = 0;
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      egressRuntime: {
        start: async (signal) => {
          signal.addEventListener("abort", () => {
            assert.ok(lifecycle.closeWork);
            nested.push(lifecycle.requestShutdown("abort-reentry"));
          });
        },
        beginClose: () => {
          closes++;
          nested.push(lifecycle.requestShutdown("dependency-reentry"));
          return { done: Promise.resolve(), retired: Promise.resolve() };
        },
      },
    }),
    onEvent: (event) => {
      if (event.state === "draining") nested.push(lifecycle.requestShutdown("event-reentry"));
      if (event.state === "stopped") readyEvents++;
    },
  });
  await lifecycle.start();
  await lifecycle.requestShutdown();
  await Promise.all(nested);
  assert.equal(closes, 1);
  assert.equal(readyEvents, 1);
  assert.equal(lifecycle.state, "stopped");
});

test("lifecycle timer setup/cancellation failures cannot suppress independent retirement", async () => {
  let failing = false,
    closes = 0;
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    scheduler: {
      now: () => 0,
      setTimer: () => {
        if (failing) throw new Error("timer setup failed");
        return {
          cancel: () => {
            if (failing) throw new Error("timer cancel failed");
          },
        };
      },
    },
    dependencies: dependencies({
      egressRuntime: {
        beginClose: () => {
          closes++;
          return { done: Promise.resolve(), retired: Promise.resolve() };
        },
      },
    }),
  });
  await lifecycle.start();
  failing = true;
  await assert.rejects(lifecycle.requestShutdown(), /cleanup uncertain/);
  assert.ok(lifecycle.closeWork);
  await assert.rejects(joinCloseWork(lifecycle.closeWork));
  assert.equal(closes, 1);
  assert.equal(lifecycle.state, "failed");
});

test("migrated close owners all initiate once and any failure is sticky without stopped success", async () => {
  const calls: string[] = [];
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies(
      Object.fromEntries(
        [...(["sessionStorage", "ssh", "proxy", "auth", "auditWal", "egressRuntime"] as const)].map((name) => [
          name,
          {
            beginClose: () => {
              calls.push(name);
              return {
                done: Promise.reject(new Error(`synthetic ${name}`)),
                retired: Promise.resolve(),
              };
            },
          },
        ]),
      ),
    ),
  });
  await lifecycle.start();
  const first = lifecycle.requestShutdown("all-fail");
  const second = lifecycle.requestShutdown("again");
  assert.notEqual(second, first);
  await assert.rejects(first, /cleanup uncertain/);
  await assert.rejects(second, /cleanup uncertain/);
  assert.equal(lifecycle.closeDependencies(closeContext(100)), lifecycle.closeDependencies(closeContext(100)));
  assert.equal(lifecycle.state, "failed");
  assert.deepEqual(new Set(calls), new Set(["sessionStorage", "ssh", "proxy", "auth", "auditWal", "egressRuntime"]));
  assert.equal(calls.length, 6);
});

test("deadline rejects observation while all independent work stays owned through late retirement", async () => {
  const scheduler = new FakeScheduler();
  const calls: string[] = [];
  let finishDone!: () => void;
  let finishRetired!: () => void;
  const heldDone = new Promise<void>((resolve) => {
    finishDone = resolve;
  });
  const heldRetired = new Promise<void>((resolve) => {
    finishRetired = resolve;
  });
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    scheduler,
    shutdownTimeoutMs: 5,
    dependencies: dependencies({
      ssh: {
        shutdown: async () => {
          calls.push("ssh.close");
        },
      },
      egressRuntime: {
        beginClose: () => {
          calls.push("egressRuntime");
          return { done: heldDone, retired: heldRetired };
        },
      },
      auditWal: {
        beginClose: () => {
          calls.push("auditWal");
          return { done: Promise.resolve(), retired: Promise.resolve() };
        },
      },
    }),
  });
  await lifecycle.start();
  const observed = lifecycle.requestShutdown("deadline");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(new Set(calls), new Set(["egressRuntime", "auditWal"]));
  scheduler.advance(5);
  await assert.rejects(observed, /cleanup uncertain/);
  assert.equal(lifecycle.state, "failed");
  assert.ok(lifecycle.closeWork);
  finishDone();
  finishRetired();
  await Promise.all([lifecycle.closeWork.done, lifecycle.closeWork.retired]);
  await lifecycle.requestShutdown("late");
  assert.equal(calls.filter((call) => call === "ssh.close").length, 1);
  assert.equal(lifecycle.state, "failed");
});

test("dependency loss fails closed and cleanup only targets attempted dependencies sequentially in reverse", async () => {
  const calls: string[] = [];
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      sessionStorage: {
        shutdown: async () => {
          calls.push("sessionStorage");
        },
      },
      ssh: {
        shutdown: async () => {
          calls.push("ssh");
        },
      },
      proxy: {
        shutdown: async () => {
          calls.push("proxy");
        },
      },
      auth: {
        shutdown: async () => {
          calls.push("auth");
        },
      },
      auditWal: {
        shutdown: async () => {
          calls.push("auditWal");
        },
      },
      egressRuntime: {
        shutdown: async () => {
          calls.push("egressRuntime");
        },
      },
    }),
  });
  await lifecycle.start();
  lifecycle.dependencyLost("proxy");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(lifecycle.ready, false);
  assert.equal(lifecycle.state, "failed");
  assert.deepEqual(calls, ["egressRuntime", "auditWal", "auth", "proxy", "ssh", "sessionStorage"]);
});

test("shutdown timeout aborts cancellable cleanup and leaves no timer", async () => {
  const scheduler = new FakeScheduler();
  let shutdownAborted = false;
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      auditWal: {
        shutdown: (signal) =>
          abortableBlock(signal, () => {
            shutdownAborted = true;
          }),
      },
    }),
    scheduler,
    shutdownTimeoutMs: 25,
  });
  await lifecycle.start();
  const shutdown = lifecycle.requestShutdown("operator");
  for (let index = 0; index < 5; index++) await Promise.resolve();
  scheduler.advance(25);
  await assert.rejects(shutdown, /cleanup uncertain/);
  assert.equal(shutdownAborted, true);
  assert.equal(lifecycle.state, "failed");
  assert.equal(scheduler.pendingTimers, 0);
});

test("throwing event observer cannot block readiness, shutdown, or leak launch data", async () => {
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies(),
    onEvent: () => {
      throw new Error("observer saw users/user-1/model");
    },
  });
  await lifecycle.start();
  assert.equal(lifecycle.ready, true);
  await lifecycle.requestShutdown("operator");
  assert.equal(lifecycle.state, "stopped");
});

test("throwing recycle observer cannot suppress emergency hard deadline", async () => {
  const scheduler = new FakeScheduler();
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies(),
    scheduler,
    recycleAfterMs: 10,
    emergencyHardDeadlineMs: 20,
    onRecycleNotice: () => {
      throw new Error("observer saw sessions/session-1/proxy");
    },
  });
  await lifecycle.start();
  scheduler.advance(10);
  assert.equal(lifecycle.recyclePending, true);
  assert.equal(lifecycle.ready, true);
  scheduler.advance(20);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(lifecycle.state, "stopped");
  assert.equal(scheduler.pendingTimers, 0);
});

test("duplicate and out-of-order dependency events do not open readiness or fallback", async () => {
  const started: string[] = [];
  let unblockSession: (() => void) | undefined;
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      sessionStorage: {
        start: async () => {
          started.push("sessionStorage");
          await new Promise<void>((resolve) => {
            unblockSession = resolve;
          });
        },
      },
      ssh: {
        start: async () => {
          started.push("ssh");
        },
      },
    }),
  });
  lifecycle.dependencyReady("proxy");
  assert.equal(lifecycle.ready, false);
  const start = lifecycle.start();
  await new Promise((resolve) => setImmediate(resolve));
  lifecycle.dependencyReady("proxy");
  assert.equal(lifecycle.ready, false);
  assert.ok(unblockSession);
  unblockSession();
  await start;
  lifecycle.dependencyReady("proxy");
  assert.equal(lifecycle.ready, true);
  assert.deepEqual(started, ["sessionStorage", "ssh"]);
});

test("dependency start failure is redacted", async () => {
  const failed = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      ssh: {
        start: async () => {
          throw new Error("secret users/user-1/model");
        },
      },
    }),
  });
  await assert.rejects(
    () => failed.start(),
    (error: unknown) => {
      assert.ok(error instanceof LaunchLifecycleError);
      assert.equal(error.code, "COGS_LAUNCH_DEPENDENCY_START_FAILED");
      assert.doesNotMatch(String(error), /users\/user-1\/model|secret/);
      return true;
    },
  );
  assert.equal(failed.ready, false);
});

test("constructor rejects missing, duplicate, or unknown dependencies without partial readiness", () => {
  assert.throws(
    () => new LaunchLifecycle({ launchDocument: validLaunch(), dependencies: dependencies().slice(1) }),
    /missing launch dependency/,
  );
  const duplicateDependencies = dependencies();
  const duplicate = duplicateDependencies[0];
  assert.ok(duplicate);
  assert.throws(
    () => new LaunchLifecycle({ launchDocument: validLaunch(), dependencies: [...duplicateDependencies, duplicate] }),
    /duplicate launch dependency/,
  );
  assert.throws(
    () =>
      new LaunchLifecycle({
        launchDocument: validLaunch(),
        dependencies: [
          ...dependencies(),
          { name: "localTool" as never, start: async () => undefined, shutdown: async () => undefined },
        ],
      }),
    /unknown launch dependency/,
  );
});

test("dependencies are canonicalized, egress starts last and shuts down first", async () => {
  const calls: string[] = [];
  const deps = dependencies();
  for (const dependency of deps) {
    const name = dependency.name;
    (dependency as { start: LaunchDependency["start"] }).start = async () => {
      calls.push(`start:${name}`);
    };
    (dependency as { shutdown: LaunchDependency["shutdown"] }).shutdown = async () => {
      calls.push(`shutdown:${name}`);
    };
  }
  const lifecycle = new LaunchLifecycle({ launchDocument: validLaunch(), dependencies: [...deps].reverse() });
  await lifecycle.start();
  await lifecycle.requestShutdown("done");
  assert.deepEqual(calls, [
    "start:sessionStorage",
    "start:ssh",
    "start:proxy",
    "start:auth",
    "start:auditWal",
    "start:egressRuntime",
    "shutdown:egressRuntime",
    "shutdown:auditWal",
    "shutdown:auth",
    "shutdown:proxy",
    "shutdown:ssh",
    "shutdown:sessionStorage",
  ]);
});

test("egress runtime adapter gates startup, maps readiness safely, and closes once", async () => {
  let closeCalls = 0;
  const manager = fakeManager(
    () => true,
    async () => {
      closeCalls++;
    },
  );
  const dependency = createCogsEgressRuntimeLaunchDependency(async () => manager);
  await dependency.start(new AbortController().signal);
  assert.equal(dependency.ready?.(), true);
  await Promise.all([
    dependency.shutdown(new AbortController().signal),
    dependency.shutdown(new AbortController().signal),
  ]);
  assert.equal(closeCalls, 1);

  await assert.rejects(
    createCogsEgressRuntimeLaunchDependency(async () =>
      fakeManager(
        () => false,
        async () => {
          closeCalls++;
        },
      ),
    ).start(new AbortController().signal),
  );
  assert.equal(closeCalls, 2);
  const throwing = createCogsEgressRuntimeLaunchDependency(async () =>
    fakeManager(() => {
      throw new Error("raw");
    }),
  );
  await assert.rejects(throwing.start(new AbortController().signal));
});

test("health poll detects egress readiness loss, cancels timers, and late callbacks are no-op", async () => {
  const scheduler = new FakeScheduler();
  let egressReady = true;
  const shutdowns: string[] = [];
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      egressRuntime: {
        ready: () => egressReady,
        shutdown: async () => {
          shutdowns.push("egress");
        },
      },
    }),
    scheduler,
    dependencyHealthIntervalMs: 50,
  });
  await lifecycle.start();
  assert.equal(lifecycle.ready, true);
  egressReady = false;
  scheduler.advance(50);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(lifecycle.state, "failed");
  assert.deepEqual(shutdowns, ["egress"]);
  const pending = scheduler.pendingTimers;
  scheduler.advance(500);
  assert.equal(scheduler.pendingTimers, pending);
});

test("health poll getter throw and scheduler throw fail closed", async () => {
  const scheduler = new FakeScheduler();
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      egressRuntime: {
        ready: () => {
          throw new Error("raw");
        },
      },
    }),
    scheduler,
    dependencyHealthIntervalMs: 50,
  });
  await lifecycle.start();
  scheduler.advance(50);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(lifecycle.state, "failed");

  const getterScheduler = new FakeScheduler();
  const deps = dependencies();
  Object.defineProperty(deps[5] as LaunchDependency, "ready", {
    get() {
      throw new Error("raw");
    },
  });
  const getterLifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: deps,
    scheduler: getterScheduler,
    dependencyHealthIntervalMs: 50,
  });
  await getterLifecycle.start();
  getterScheduler.advance(50);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(getterLifecycle.state, "failed");

  const throwingScheduler: Scheduler = {
    now: () => 0,
    setTimer(milliseconds, callback) {
      if (milliseconds === 50) throw new Error("raw timer");
      return scheduler.setTimer(milliseconds, callback);
    },
  };
  const timerFailure = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies(),
    scheduler: throwingScheduler,
    dependencyHealthIntervalMs: 50,
  });
  await timerFailure.start();
  await timerFailure.requestShutdown("join");
  assert.equal(timerFailure.ready, false);
  assert.equal(timerFailure.state, "failed");

  assert.throws(
    () =>
      new LaunchLifecycle({
        launchDocument: validLaunch(),
        dependencies: dependencies(),
        dependencyHealthIntervalMs: 49,
      }),
    LaunchLifecycleError,
  );
});

function fakeManager(ready: () => boolean, close: () => Promise<void> = async () => undefined) {
  const owner = createCloseOwner(close);
  return registerCloseOwner(
    Object.freeze({
      get ready() {
        return ready();
      },
      listenerPort: 15001,
      replacementRequired: false,
      drainCompletions: () => [],
      close: () => observeClose(owner(), closeContext(1000)),
    }),
    owner,
  );
}

test("egress runtime adapter rejects second start and redacts raw factory and close failures", async () => {
  assert.throws(() => createCogsEgressRuntimeLaunchDependency(undefined as never), LaunchLifecycleError);

  let closeCalls = 0;
  const dependency = createCogsEgressRuntimeLaunchDependency(async () =>
    fakeManager(
      () => true,
      async () => {
        closeCalls++;
      },
    ),
  );
  await dependency.start(new AbortController().signal);
  await assert.rejects(dependency.start(new AbortController().signal), (error: unknown) => {
    assert.ok(error instanceof LaunchLifecycleError);
    assert.equal(error.code, "COGS_LAUNCH_EGRESS_RUNTIME_FAILED");
    assert.doesNotMatch(String(error.stack ?? ""), /raw/);
    return true;
  });
  await dependency.shutdown(new AbortController().signal);
  assert.equal(closeCalls, 1);

  await assert.rejects(
    createCogsEgressRuntimeLaunchDependency(async () => {
      throw new Error("raw secret");
    }).start(new AbortController().signal),
    (error: unknown) => {
      assert.ok(error instanceof LaunchLifecycleError);
      assert.equal(error.message, "egress runtime unavailable");
      assert.doesNotMatch(String(error.stack ?? ""), /raw secret/);
      return true;
    },
  );

  let rejectedCloseCalls = 0;
  const closeRejecting = createCogsEgressRuntimeLaunchDependency(async () =>
    fakeManager(
      () => true,
      async () => {
        rejectedCloseCalls++;
        throw new Error("raw close");
      },
    ),
  );
  await closeRejecting.start(new AbortController().signal);
  const first = closeRejecting.shutdown(new AbortController().signal);
  const second = closeRejecting.shutdown(new AbortController().signal);
  await assert.rejects(first, LaunchLifecycleError);
  await assert.rejects(second, LaunchLifecycleError);
  assert.equal(rejectedCloseCalls, 1);
});

test("egress adapter retains not-ready manager when startup close rejects for rollback shutdown", async () => {
  let closeCalls = 0;
  const dependency = createCogsEgressRuntimeLaunchDependency(async () =>
    fakeManager(
      () => false,
      async () => {
        closeCalls++;
        throw new Error("raw close");
      },
    ),
  );
  await assert.rejects(dependency.start(new AbortController().signal), (error: unknown) => {
    assert.ok(error instanceof LaunchLifecycleError);
    assert.equal(error.code, "COGS_LAUNCH_EGRESS_RUNTIME_FAILED");
    assert.doesNotMatch(String(error.stack ?? ""), /raw close/);
    return true;
  });
  const first = dependency.shutdown(new AbortController().signal);
  const second = dependency.shutdown(new AbortController().signal);
  await assert.rejects(first, LaunchLifecycleError);
  await assert.rejects(second, LaunchLifecycleError);
  assert.equal(closeCalls, 1);
});

test("egress adapter closes deferred factory result after shutdown before resolve", async () => {
  let resolveFactory!: (manager: ReturnType<typeof fakeManager>) => void;
  let closeCalls = 0;
  const controller = new AbortController();
  const dependency = createCogsEgressRuntimeLaunchDependency(
    () =>
      new Promise((resolve) => {
        resolveFactory = resolve;
      }),
  );
  const start = dependency.start(controller.signal);
  controller.abort();
  const shutdown = dependency.shutdown(new AbortController().signal);
  resolveFactory(
    fakeManager(
      () => true,
      async () => {
        closeCalls++;
      },
    ),
  );
  await assert.rejects(start, LaunchLifecycleError);
  await shutdown;
  assert.equal(dependency.ready?.(), false);
  assert.equal(closeCalls, 1);
});

test("egress startup owner precedes reentrant factory close and retains the late manager", async () => {
  const acquired = Promise.withResolvers<ReturnType<typeof fakeManager>>();
  const closed = Promise.withResolvers<void>();
  let work: CloseWork | undefined;
  let retired = false,
    closeCalls = 0;
  const dependency = createCogsEgressRuntimeLaunchDependency(() => {
    work = dependency.beginClose?.(closeContext(1000));
    return acquired.promise;
  });
  const start = dependency.start(new AbortController().signal);
  void start.catch(() => undefined);
  assert.ok(work);
  void joinCloseWork(work).then(() => {
    retired = true;
  });
  await new Promise((resolve) => setImmediate(resolve));
  try {
    assert.equal(retired, false);
  } finally {
    acquired.resolve(
      fakeManager(
        () => true,
        async () => {
          closeCalls++;
          await closed.promise;
        },
      ),
    );
  }
  await new Promise((resolve) => setImmediate(resolve));
  try {
    assert.equal(retired, false);
    assert.equal(closeCalls, 1);
  } finally {
    closed.resolve();
  }
  await assert.rejects(start, LaunchLifecycleError);
  await joinCloseWork(work);
  assert.equal(dependency.ready?.(), false);
  assert.equal(closeCalls, 1);
  const sealed = createCogsEgressRuntimeLaunchDependency(async () => {
    assert.fail("closed admission");
  });
  await joinCloseWork(sealed.beginClose?.(closeContext(1000)) as CloseWork);
  await assert.rejects(sealed.start(new AbortController().signal), LaunchLifecycleError);
});

test("egress adapter consumes already-aborted start without invoking factory", async () => {
  let calls = 0;
  const controller = new AbortController();
  controller.abort();
  const dependency = createCogsEgressRuntimeLaunchDependency(async () => {
    calls++;
    return fakeManager(() => true);
  });
  await assert.rejects(dependency.start(controller.signal), LaunchLifecycleError);
  await assert.rejects(dependency.start(new AbortController().signal), LaunchLifecycleError);
  assert.equal(calls, 0);
});

function recordingWorkerSink(spans: unknown[], metrics: unknown[]) {
  return Object.freeze({
    get ready() {
      return true;
    },
    span: (input: unknown) => {
      spans.push(input);
      return true;
    },
    metric: (input: unknown) => {
      metrics.push(input);
      return true;
    },
    snapshot: () => Object.freeze({ ready: true, queued: 0, exported: 0, dropped: 0, failed: 0, lag_ms: 0 }),
    close: async () => undefined,
  });
}

test("lifecycle telemetry uses fixed metadata and is nonfatal", async () => {
  const spans: unknown[] = [];
  const metrics: unknown[] = [];
  const sink = recordingWorkerSink(spans, metrics);
  const scheduler = new FakeScheduler();
  let startCalls = 0;
  const deps = dependencies({
    ssh: {
      start: async () => {
        startCalls++;
      },
    },
  });
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: deps,
    scheduler,
    telemetry: sink,
  });
  await lifecycle.start();
  assert.equal(startCalls, 1);
  await lifecycle.requestShutdown("done");
  const text = JSON.stringify([...spans, ...metrics]);
  for (const forbidden of [
    "SECRET",
    "prompt",
    "source",
    "command",
    "path",
    "output",
    "query",
    "account",
    "request",
    "correlation",
    "model",
    "provider",
  ]) {
    assert.equal(text.includes(forbidden), false);
  }
  assert.ok(text.includes("lifecycle.ready"));
  assert.ok(text.includes("shutdown.ready"));
  assert.ok(text.includes("session.active"));
  const names = spans.map((span) => (span as { name?: unknown }).name);
  assert.equal(names.filter((name) => name === "dependency.start").length, 6);
  assert.equal(names.filter((name) => name === "dependency.ready").length, 6);
  assert.ok(names.indexOf("dependency.start") < names.indexOf("dependency.ready"));

  const throwing = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies(),
    scheduler: new FakeScheduler(),
    telemetry: Object.freeze({
      get ready() {
        return true;
      },
      span: () => {
        throw new Error("SECRET_TELEMETRY");
      },
      metric: () => {
        throw new Error("SECRET_TELEMETRY");
      },
      snapshot: () => Object.freeze({ ready: true, queued: 0, exported: 0, dropped: 0, failed: 0, lag_ms: 0 }),
      close: async () => undefined,
    }),
  });
  await throwing.start();
  await throwing.requestShutdown("done");
});

test("lifecycle telemetry emits one dependency start failure", async () => {
  const spans: unknown[] = [];
  const sink = recordingWorkerSink(spans, []);
  const lifecycle = new LaunchLifecycle({
    launchDocument: validLaunch(),
    dependencies: dependencies({
      ssh: {
        start: async () => {
          throw new Error("SECRET_START");
        },
      },
    }),
    scheduler: new FakeScheduler(),
    telemetry: sink,
  });
  await assert.rejects(lifecycle.start(), LaunchLifecycleError);
  const starts = spans.filter((span) => (span as { name?: unknown }).name === "dependency.start");
  assert.equal(starts.length, 2);
  assert.deepEqual((starts[1] as { attributes: unknown }).attributes, {
    dependency: "ssh",
    outcome: "error",
    duration_ms: 0,
  });
  assert.equal(JSON.stringify(spans).includes("SECRET_START"), false);
});

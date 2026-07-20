import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, realpath, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { canonicalJson } from "../dev/launcher/contract.ts";
import { beginWorkerStartup, bindWorkerChild, promoteWorkerReady, readApiToken } from "../dev/launcher/control.ts";
import {
  clearRecovery,
  createState,
  type LauncherState,
  readManifest,
  resolveLauncherState,
  writePhase,
} from "../dev/launcher/state.ts";
import {
  launcherInventory,
  type SupervisorSeams,
  startWorkerForState,
  stopWorkerForState,
} from "../dev/launcher/supervisor.ts";

const sourceRevision = "c".repeat(40);
const parentDigest = `sha256:${"1".repeat(64)}`;
const childDigest = `sha256:${"2".repeat(64)}`;
const reusedDigest = `sha256:${"3".repeat(64)}`;

async function readyState(name = "sup", profile: "linux-kvm" | "insecure-container" = "linux-kvm") {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-supervisor-"));
  const root = join(await realpath(dir), "launcher");
  await mkdir(root, { mode: 0o700 });
  const state = await resolveLauncherState({ root, name, sourceRevision });
  const manifest = await createState(state, profile);
  await writePhase(state, manifest, "sandbox-ready");
  return { dir, state };
}

async function makeReadyWorker(state: LauncherState): Promise<void> {
  const startup = await beginWorkerStartup(
    state,
    Object.freeze({
      randomBytes: Object.freeze(() => Buffer.alloc(32, 9)) as never,
      identity: Object.freeze((pid: number) => (pid === 111 ? parentDigest : childDigest)),
      parentPid: 111,
    }),
  );
  await bindWorkerChild(
    state,
    Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "child-identity",
      startupDigest: startup.startup.digest(),
      pid: 222,
      pidIdentity: childDigest,
    }),
    Object.freeze({ identity: Object.freeze(() => childDigest) }) as never,
  );
  await promoteWorkerReady(
    state,
    Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "child-ready",
      startupDigest: startup.startup.digest(),
      pid: 222,
      pidIdentity: childDigest,
      apiPort: 4321,
    }),
    Object.freeze({ identity: Object.freeze(() => childDigest) }) as never,
  );
  startup.startup.dispose();
}

function seams(overrides: Partial<SupervisorSeams> = {}): Partial<SupervisorSeams> {
  return Object.freeze({
    identity: Object.freeze((pid: number) => (pid === 222 ? childDigest : parentDigest)),
    signal: Object.freeze(() => true),
    now: Object.freeze(() => 1),
    setTimer: Object.freeze((callback: () => void) => {
      queueMicrotask(callback);
      return 1;
    }),
    clearTimer: Object.freeze(() => undefined),
    ...overrides,
  });
}

async function assertNoToken(state: LauncherState): Promise<void> {
  await assert.rejects(() => readApiToken(state));
}

test("supervisor start creates token, starts worker, proves ready, and returns metadata only", async () => {
  const { dir, state } = await readyState();
  const calls: string[] = [];
  try {
    const started = await startWorkerForState(
      state,
      undefined,
      seams({
        startWorkerProcess: Object.freeze(
          async (s: LauncherState, startup: Awaited<ReturnType<typeof beginWorkerStartup>>) => {
            calls.push("start");
            assert.equal((await readApiToken(s)).read().length, 43);
            await bindWorkerChild(
              s,
              Object.freeze({
                version: "cogs.dev-launcher-worker-protocol/v1alpha1",
                type: "child-identity",
                startupDigest: startup.startup.digest(),
                pid: 222,
                pidIdentity: childDigest,
              }),
              Object.freeze({ identity: Object.freeze(() => childDigest) }) as never,
            );
            return await promoteWorkerReady(
              s,
              Object.freeze({
                version: "cogs.dev-launcher-worker-protocol/v1alpha1",
                type: "child-ready",
                startupDigest: startup.startup.digest(),
                pid: 222,
                pidIdentity: childDigest,
                apiPort: 4321,
              }),
              Object.freeze({ identity: Object.freeze(() => childDigest) }) as never,
            );
          },
        ) as never,
      }),
    );
    assert.deepEqual(calls, ["start"]);
    assert.equal(started.phase, "worker-ready");
    assert.equal(started.apiPort, 4321);
    assert.equal(JSON.stringify(started).includes("222"), false);
    assert.equal(JSON.stringify(started).includes(childDigest), false);
    assert.equal((await readManifest(state)).phase, "worker-ready");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor start rollback removes controls when identity is absent and preserves on uncertainty", async () => {
  const absent = await readyState("absent");
  try {
    await assert.rejects(() =>
      startWorkerForState(
        absent.state,
        undefined,
        seams({
          identity: Object.freeze(() => null),
          startWorkerProcess: Object.freeze(async () => {
            throw new Error("boom pid 222 token secret");
          }) as never,
        }),
      ),
    );
    await assertNoToken(absent.state);
    assert.equal(
      (await launcherInventory(absent.state, seams({ identity: Object.freeze(() => null) }))).descriptor,
      "none",
    );
  } finally {
    await rm(absent.dir, { recursive: true, force: true });
  }

  const live = await readyState("live");
  try {
    await assert.rejects(
      () =>
        startWorkerForState(
          live.state,
          undefined,
          seams({
            startWorkerProcess: Object.freeze(async () => {
              throw new Error("boom");
            }) as never,
          }),
        ),
      /launcher supervisor failed/u,
    );
    assert.equal((await launcherInventory(live.state, seams())).recovery, "present");
    assert.equal((await launcherInventory(live.state, seams())).cleanupRequired, true);
  } finally {
    await rm(live.dir, { recursive: true, force: true });
  }
});

test("supervisor stop signals exact identity once, waits for absence, cleans controls, and demotes phase", async () => {
  const { dir, state } = await readyState();
  const signals: string[] = [];
  let live = true;
  const abort = new AbortController();
  try {
    await makeReadyWorker(state);
    const stopped = await stopWorkerForState(
      state,
      abort.signal,
      seams({
        identity: Object.freeze((pid: number) => (pid === 222 && live ? childDigest : null)),
        signal: Object.freeze((pid: number, sig: "SIGTERM") => {
          signals.push(`${pid}:${sig}`);
          abort.abort();
          live = false;
          return true;
        }),
      }),
    );
    assert.deepEqual(signals, ["222:SIGTERM"]);
    assert.equal(stopped.phase, "sandbox-ready");
    assert.equal((await readManifest(state)).phase, "sandbox-ready");
    assert.equal((await launcherInventory(state, seams({ identity: Object.freeze(() => null) }))).descriptor, "none");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor stop does not signal absent or reused workers and is idempotent", async () => {
  const { dir, state } = await readyState();
  const signals: number[] = [];
  try {
    await makeReadyWorker(state);
    await stopWorkerForState(
      state,
      undefined,
      seams({
        identity: Object.freeze((pid: number) => (pid === 222 ? reusedDigest : parentDigest)),
        signal: Object.freeze((pid: number) => {
          signals.push(pid);
          return true;
        }),
      }),
    );
    assert.deepEqual(signals, []);
    await stopWorkerForState(state, undefined, seams({ identity: Object.freeze(() => null) }));
    assert.equal((await readManifest(state)).phase, "sandbox-ready");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor stop preserves controls and marks recovery on unknown identity, changed boundary, timeout, and signal failure", async () => {
  for (const [name, override] of [
    ["unknown", seams({ identity: Object.freeze(() => undefined) })],
    [
      "changed",
      (() => {
        let count = 0;
        return seams({ identity: Object.freeze(() => (++count === 1 ? childDigest : undefined)) });
      })(),
    ],
    [
      "timeout",
      (() => {
        let now = 1;
        return seams({
          identity: Object.freeze(() => childDigest),
          now: Object.freeze(() => now++ * 10_000),
        });
      })(),
    ],
    ["signal", seams({ signal: Object.freeze(() => false) })],
  ] as const) {
    const { dir, state } = await readyState(name);
    try {
      await makeReadyWorker(state);
      await assert.rejects(() => stopWorkerForState(state, undefined, override), /launcher supervisor failed/u);
      const inventory = await launcherInventory(state, override);
      assert.equal(inventory.phase, "worker-ready");
      assert.equal(inventory.recovery, "present");
      assert.equal(inventory.cleanupRequired, true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("supervisor inventory is frozen metadata for descriptor, recovery, and driver states", async () => {
  const { dir, state } = await readyState("inventory", "insecure-container");
  try {
    let inventory = await launcherInventory(state, seams({ identity: Object.freeze(() => null) }));
    assert.equal(Object.isFrozen(inventory), true);
    assert.equal(inventory.descriptor, "none");
    assert.equal(inventory.workerLive, false);
    assert.equal(inventory.driverState, "absent");
    await mkdir(state.driverStateDir, { mode: 0o700 });
    await makeReadyWorker(state);
    inventory = await launcherInventory(state, seams());
    assert.equal(inventory.descriptor, "ready");
    assert.equal(inventory.workerLive, true);
    assert.equal(inventory.driverState, "present");
    assert.equal(JSON.stringify(inventory).includes("222"), false);
    assert.equal(JSON.stringify(inventory).includes(childDigest), false);
    await writeFile(
      state.recoveryPath,
      canonicalJson({ version: "cogs.dev-launcher-recovery/v1alpha1", stateId: state.stateId, reason: "x" }),
      {
        mode: 0o600,
      },
    );
    assert.equal((await launcherInventory(state, seams())).recovery, "present");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor inventory reports malformed controls generically and seams reject hostile shapes", async () => {
  const { dir, state } = await readyState("malformed");
  try {
    await writeFile(join(state.controlDir, "worker.json"), "not-json\n", { mode: 0o600 });
    const inventory = await launcherInventory(state, seams());
    assert.equal(inventory.descriptor, "malformed");
    assert.equal(inventory.workerLive, "unknown");
    assert.equal(inventory.cleanupRequired, true);
    await assert.rejects(() =>
      launcherInventory(state, {
        get identity() {
          throw new Error("leak");
        },
      } as never),
    );
    await assert.rejects(() => launcherInventory(state, Object.freeze({ identity: () => childDigest }) as never));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor honors pre-aborted start and stop before side effects", async () => {
  const start = await readyState("preabort-start");
  const abort = new AbortController();
  abort.abort();
  try {
    let invoked = false;
    await assert.rejects(() =>
      startWorkerForState(
        start.state,
        abort.signal,
        seams({
          startWorkerProcess: Object.freeze(async () => {
            invoked = true;
            throw new Error("unexpected");
          }) as never,
        }),
      ),
    );
    assert.equal(invoked, false);
    assert.equal((await launcherInventory(start.state, seams())).descriptor, "none");
  } finally {
    await rm(start.dir, { recursive: true, force: true });
  }

  const stop = await readyState("preabort-stop");
  try {
    await makeReadyWorker(stop.state);
    const signals: number[] = [];
    await assert.rejects(() =>
      stopWorkerForState(
        stop.state,
        abort.signal,
        seams({
          signal: Object.freeze((pid: number) => {
            signals.push(pid);
            return true;
          }),
        }),
      ),
    );
    assert.deepEqual(signals, []);
    assert.equal((await readManifest(stop.state)).phase, "worker-ready");
  } finally {
    await rm(stop.dir, { recursive: true, force: true });
  }
});

test("supervisor start demotes false ready after post-promotion proof failure", async () => {
  const { dir, state } = await readyState("false-ready");
  try {
    await assert.rejects(() =>
      startWorkerForState(
        state,
        undefined,
        seams({
          identity: Object.freeze(() => null),
          startWorkerProcess: Object.freeze(
            async (s: LauncherState, startup: Awaited<ReturnType<typeof beginWorkerStartup>>) => {
              const ready = await promoteWorkerReady(
                s,
                Object.freeze({
                  version: "cogs.dev-launcher-worker-protocol/v1alpha1",
                  type: "child-ready",
                  startupDigest: startup.startup.digest(),
                  pid: 222,
                  pidIdentity: childDigest,
                  apiPort: 4321,
                }),
                Object.freeze({ identity: Object.freeze(() => childDigest) }) as never,
              ).catch(async () => {
                await bindWorkerChild(
                  s,
                  Object.freeze({
                    version: "cogs.dev-launcher-worker-protocol/v1alpha1",
                    type: "child-identity",
                    startupDigest: startup.startup.digest(),
                    pid: 222,
                    pidIdentity: childDigest,
                  }),
                  Object.freeze({ identity: Object.freeze(() => childDigest) }) as never,
                );
                return await promoteWorkerReady(
                  s,
                  Object.freeze({
                    version: "cogs.dev-launcher-worker-protocol/v1alpha1",
                    type: "child-ready",
                    startupDigest: startup.startup.digest(),
                    pid: 222,
                    pidIdentity: childDigest,
                    apiPort: 4321,
                  }),
                  Object.freeze({ identity: Object.freeze(() => childDigest) }) as never,
                );
              });
              return { ...ready, apiPort: 4322 } as never;
            },
          ) as never,
        }),
      ),
    );
    assert.equal((await readManifest(state)).phase, "sandbox-ready");
    const inventory = await launcherInventory(state, seams({ identity: Object.freeze(() => null) }));
    assert.equal(inventory.descriptor, "none");
    assert.equal(inventory.cleanupRequired, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor inventory reports hostile recovery and driver entries as unknown", async () => {
  const { dir, state } = await readyState("hostile-inventory");
  try {
    await symlink("/tmp/nope", state.recoveryPath);
    let inventory = await launcherInventory(state, seams());
    assert.equal(inventory.recovery, "unknown");
    assert.equal(inventory.cleanupRequired, true);
    await rm(state.recoveryPath, { force: true });
    await mkdir(state.driverStateDir, { mode: 0o700 });
    await chmod(state.driverStateDir, 0o755);
    inventory = await launcherInventory(state, seams());
    assert.equal(inventory.driverState, "unknown");
    assert.equal(inventory.cleanupRequired, true);
  } finally {
    await chmod(state.driverStateDir, 0o700).catch(() => undefined);
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor stop post-signal cleanup and timer failures preserve recovery generically", async () => {
  const cleanup = await readyState("cleanup-fail");
  try {
    await makeReadyWorker(cleanup.state);
    await writeFile(join(cleanup.state.controlDir, "extra"), "x", { mode: 0o600 });
    let live = true;
    await assert.rejects(
      () =>
        stopWorkerForState(
          cleanup.state,
          undefined,
          seams({
            identity: Object.freeze((pid: number) => (pid === 222 && live ? childDigest : null)),
            signal: Object.freeze(() => {
              live = false;
              return true;
            }),
          }),
        ),
      /launcher supervisor failed/u,
    );
    const inventory = await launcherInventory(cleanup.state, seams({ identity: Object.freeze(() => null) }));
    assert.equal(inventory.recovery, "present");
    assert.equal(inventory.cleanupRequired, true);
  } finally {
    await rm(cleanup.dir, { recursive: true, force: true });
  }

  const phase = await readyState("phase-write-fail");
  try {
    await makeReadyWorker(phase.state);
    await writeFile(
      phase.state.recoveryPath,
      canonicalJson({ version: "cogs.dev-launcher-recovery/v1alpha1", stateId: phase.state.stateId, reason: "x" }),
      { mode: 0o600 },
    );
    let calls = 0;
    await assert.rejects(() =>
      stopWorkerForState(
        phase.state,
        undefined,
        seams({
          identity: Object.freeze((pid: number) => {
            calls += 1;
            if (calls >= 4) void chmod(phase.state.dir, 0o500);
            return pid === 222 && calls < 3 ? childDigest : null;
          }),
          signal: Object.freeze(() => true),
        }),
      ),
    );
    await chmod(phase.state.dir, 0o700);
    const inventory = await launcherInventory(phase.state, seams({ identity: Object.freeze(() => null) }));
    assert.equal(inventory.phase, "worker-ready");
    assert.equal(inventory.descriptor, "none");
    assert.equal(inventory.recovery, "present");
    assert.equal(inventory.cleanupRequired, true);
  } finally {
    await chmod(phase.state.dir, 0o700).catch(() => undefined);
    await rm(phase.dir, { recursive: true, force: true });
  }

  for (const [name, badSeams] of [
    [
      "timer-clear",
      seams({
        identity: Object.freeze(() => childDigest),
        clearTimer: Object.freeze(() => {
          throw new Error("clear");
        }),
      }),
    ],
    [
      "timer-sync",
      seams({
        identity: Object.freeze(() => childDigest),
        setTimer: Object.freeze((callback: () => void) => {
          callback();
          return 1;
        }),
      }),
    ],
    [
      "clock-backward",
      (() => {
        const times = [100, 90];
        return seams({
          identity: Object.freeze(() => childDigest),
          now: Object.freeze(() => times.shift() ?? 90),
        });
      })(),
    ],
  ] as const) {
    const item = await readyState(name);
    try {
      await makeReadyWorker(item.state);
      await assert.rejects(() => stopWorkerForState(item.state, undefined, badSeams), /launcher supervisor failed/u);
      assert.equal((await launcherInventory(item.state, badSeams)).recovery, "present");
    } finally {
      await rm(item.dir, { recursive: true, force: true });
    }
  }
});

test("supervisor blocks start on recovery and clears exact recovery after successful stop", async () => {
  const blocked = await readyState("recovery-blocks-start");
  try {
    await writeFile(
      blocked.state.recoveryPath,
      canonicalJson({ version: "cogs.dev-launcher-recovery/v1alpha1", stateId: blocked.state.stateId, reason: "x" }),
      { mode: 0o600 },
    );
    let started = false;
    await assert.rejects(() =>
      startWorkerForState(
        blocked.state,
        undefined,
        seams({
          startWorkerProcess: Object.freeze(async () => {
            started = true;
            throw new Error("unexpected");
          }) as never,
        }),
      ),
    );
    assert.equal(started, false);
    assert.equal((await launcherInventory(blocked.state, seams())).recovery, "present");
  } finally {
    await rm(blocked.dir, { recursive: true, force: true });
  }

  const stopped = await readyState("recovery-cleared");
  try {
    await makeReadyWorker(stopped.state);
    await writeFile(
      stopped.state.recoveryPath,
      canonicalJson({ version: "cogs.dev-launcher-recovery/v1alpha1", stateId: stopped.state.stateId, reason: "x" }),
      { mode: 0o600 },
    );
    let live = true;
    await stopWorkerForState(
      stopped.state,
      undefined,
      seams({
        identity: Object.freeze((pid: number) => (pid === 222 && live ? childDigest : null)),
        signal: Object.freeze(() => {
          live = false;
          return true;
        }),
      }),
    );
    const inventory = await launcherInventory(stopped.state, seams({ identity: Object.freeze(() => null) }));
    assert.equal(inventory.recovery, "absent");
    assert.equal(inventory.cleanupRequired, false);
    await clearRecovery(stopped.state);
  } finally {
    await rm(stopped.dir, { recursive: true, force: true });
  }
});

test("supervisor preserves replacement recovery and rejects non-boolean signal results", async () => {
  const replacement = await readyState("replacement-recovery");
  try {
    await makeReadyWorker(replacement.state);
    await symlink("/tmp/nope", replacement.state.recoveryPath);
    let live = true;
    await assert.rejects(() =>
      stopWorkerForState(
        replacement.state,
        undefined,
        seams({
          identity: Object.freeze((pid: number) => (pid === 222 && live ? childDigest : null)),
          signal: Object.freeze(() => {
            live = false;
            return true;
          }),
        }),
      ),
    );
    const inventory = await launcherInventory(replacement.state, seams({ identity: Object.freeze(() => null) }));
    assert.equal(inventory.recovery, "unknown");
    assert.equal(inventory.cleanupRequired, true);
  } finally {
    await rm(replacement.dir, { recursive: true, force: true });
  }

  const nonBoolean = await readyState("nonboolean-signal");
  try {
    await makeReadyWorker(nonBoolean.state);
    await assert.rejects(() =>
      stopWorkerForState(nonBoolean.state, undefined, seams({ signal: Object.freeze(() => ({ ok: true })) as never })),
    );
    const inventory = await launcherInventory(nonBoolean.state, seams());
    assert.equal(inventory.phase, "worker-ready");
    assert.equal(inventory.recovery, "present");
  } finally {
    await rm(nonBoolean.dir, { recursive: true, force: true });
  }
});

test("supervisor abort before signal boundary prevents SIGTERM", async () => {
  const { dir, state } = await readyState("abort-before-signal");
  const abort = new AbortController();
  const signals: number[] = [];
  try {
    await makeReadyWorker(state);
    await assert.rejects(() =>
      stopWorkerForState(
        state,
        abort.signal,
        seams({
          identity: Object.freeze(() => {
            abort.abort();
            return childDigest;
          }),
          signal: Object.freeze((pid: number) => {
            signals.push(pid);
            return true;
          }),
        }),
      ),
    );
    assert.deepEqual(signals, []);
    assert.equal((await readManifest(state)).phase, "worker-ready");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("supervisor start rejects hostile ready descriptor authority without invoking getters", async () => {
  const { dir, state } = await readyState("hostile-ready-result");
  let getterInvoked = false;
  try {
    await assert.rejects(() =>
      startWorkerForState(
        state,
        undefined,
        seams({
          identity: Object.freeze(() => null),
          startWorkerProcess: Object.freeze(
            async (s: LauncherState, startup: Awaited<ReturnType<typeof beginWorkerStartup>>) => {
              await bindWorkerChild(
                s,
                Object.freeze({
                  version: "cogs.dev-launcher-worker-protocol/v1alpha1",
                  type: "child-identity",
                  startupDigest: startup.startup.digest(),
                  pid: 222,
                  pidIdentity: childDigest,
                }),
                Object.freeze({ identity: Object.freeze(() => childDigest) }) as never,
              );
              await promoteWorkerReady(
                s,
                Object.freeze({
                  version: "cogs.dev-launcher-worker-protocol/v1alpha1",
                  type: "child-ready",
                  startupDigest: startup.startup.digest(),
                  pid: 222,
                  pidIdentity: childDigest,
                  apiPort: 4321,
                }),
                Object.freeze({ identity: Object.freeze(() => childDigest) }) as never,
              );
              return Object.freeze({
                get apiPort() {
                  getterInvoked = true;
                  return 4321;
                },
                toJSON: Object.freeze(() => {
                  getterInvoked = true;
                  return {};
                }),
              }) as never;
            },
          ) as never,
        }),
      ),
    );
    assert.equal(getterInvoked, false);
    const inventory = await launcherInventory(state, seams({ identity: Object.freeze(() => null) }));
    assert.equal(inventory.phase, "sandbox-ready");
    assert.equal(inventory.descriptor, "none");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("clearRecovery preserves same-size replacement before final revalidation", async () => {
  const { dir, state } = await readyState("clear-recovery-replace");
  const original = canonicalJson({
    version: "cogs.dev-launcher-recovery/v1alpha1",
    stateId: state.stateId,
    reason: "x",
  });
  const replacement = canonicalJson({
    version: "cogs.dev-launcher-recovery/v1alpha1",
    stateId: state.stateId,
    reason: "y",
  });
  try {
    assert.equal(Buffer.byteLength(original), Buffer.byteLength(replacement));
    await writeFile(state.recoveryPath, original, { mode: 0o600 });
    await assert.rejects(() =>
      clearRecovery(
        state,
        Object.freeze({
          beforeFinalRevalidate: Object.freeze(async () => {
            await rm(state.recoveryPath, { force: true });
            await writeFile(state.recoveryPath, replacement, { mode: 0o600 });
          }),
        }),
      ),
    );
    assert.equal(await realpath(state.recoveryPath), state.recoveryPath);
    assert.equal((await launcherInventory(state, seams())).recovery, "present");
    await assert.rejects(() =>
      clearRecovery(
        state,
        Object.freeze({
          beforeFinalRevalidate: Object.freeze(async () => {
            await rm(state.recoveryPath, { force: true });
            await symlink("/tmp/nope", state.recoveryPath);
          }),
        }),
      ),
    );
    assert.equal((await launcherInventory(state, seams())).recovery, "unknown");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("clearRecovery rejects parent replacement before unlink and preserves new recovery", async () => {
  const { dir, state } = await readyState("clear-recovery-parent-replace");
  const original = canonicalJson({
    version: "cogs.dev-launcher-recovery/v1alpha1",
    stateId: state.stateId,
    reason: "x",
  });
  const replacement = canonicalJson({
    version: "cogs.dev-launcher-recovery/v1alpha1",
    stateId: state.stateId,
    reason: "y",
  });
  const moved = join(state.root, "moved-parent");
  const manifest = await readManifest(state);
  try {
    await writeFile(state.recoveryPath, original, { mode: 0o600 });
    await assert.rejects(() =>
      clearRecovery(
        state,
        Object.freeze({
          beforeFinalRevalidate: Object.freeze(async () => {
            await rename(state.dir, moved);
            await mkdir(state.dir, { mode: 0o700 });
            await writeFile(state.sentinelPath, `${state.stateId}\n`, { mode: 0o600 });
            await mkdir(state.controlDir, { mode: 0o700 });
            await mkdir(state.sandboxDir, { mode: 0o700 });
            await writeFile(state.manifestPath, canonicalJson(manifest), { mode: 0o600 });
            await writeFile(state.recoveryPath, replacement, { mode: 0o600 });
          }),
        }),
      ),
    );
    assert.equal(await realpath(state.recoveryPath), state.recoveryPath);
    assert.equal((await launcherInventory(state, seams())).recovery, "present");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

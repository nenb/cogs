import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { type DriverResult, deepFreeze, type LauncherProfile } from "../dev/launcher/contract.ts";
import { beginWorkerStartup, createApiToken } from "../dev/launcher/control.ts";
import { acquiredSandbox, createSandbox, destroySandbox, resetSandbox, statusSandbox } from "../dev/launcher/core.ts";
import type { ProfileAdapter } from "../dev/launcher/profiles.ts";
import type { LauncherState } from "../dev/launcher/state.ts";
import { readAcquisition, readManifest, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";

const sourceRevision = "2".repeat(40);

function result(profile: LauncherProfile, operation: DriverResult["operation"], generation: string): DriverResult {
  return deepFreeze({
    generation,
    profile,
    operation,
    result: profile === "linux-kvm" ? (operation === "destroy" ? "destroyed" : "ready") : "pass",
    authority: profile === "linux-kvm" ? "authoritative-local" : "functional-only",
  });
}

function adapter(profile: LauncherProfile, log: string[], fail?: string): ProfileAdapter {
  const op = async (name: DriverResult["operation"], state: LauncherState, generation: string) => {
    log.push(name);
    if (fail === name) throw new Error("profile failed");
    if (name === "destroy") await rm(state.driverStateDir, { recursive: true, force: true });
    return result(profile, name, generation);
  };
  const create = Object.freeze((state: LauncherState, generation: string) => op("create", state, generation));
  const verify = Object.freeze((state: LauncherState, generation: string) => op("verify", state, generation));
  const reset = Object.freeze((state: LauncherState, generation: string) => op("reset", state, generation));
  const destroy = Object.freeze((state: LauncherState, generation: string) => op("destroy", state, generation));
  return Object.freeze({ profile, create, verify, reset, destroy });
}

async function temp() {
  return await realpath(await mkdtemp(join(tmpdir(), "cogs-launcher-core-")));
}

test("core create reaches sandbox-ready but never claims worker-ready", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const created = await createSandbox({
      root,
      name: "core",
      sourceRevision,
      profile: "insecure-container",
      adapter: adapter("insecure-container", log),
    });
    assert.equal(created.workerReady, false);
    assert.equal(created.manifest.phase, "sandbox-ready");
    assert.deepEqual(log, ["create", "verify"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core destroy preserves worker-ready state for future exact worker cleanup", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const profileAdapter = adapter("linux-kvm", log);
    await createSandbox({ root, name: "worker", sourceRevision, profile: "linux-kvm", adapter: profileAdapter });
    const state = await resolveLauncherState({ root, name: "worker", sourceRevision });
    await writePhase(state, await readManifest(state), "worker-ready");
    await assert.rejects(() =>
      destroySandbox({ root, name: "worker", sourceRevision, profile: "linux-kvm", adapter: profileAdapter }),
    );
    assert.deepEqual(log, ["create", "verify"]);
    assert.equal((await readManifest(state)).phase, "worker-ready");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core reset and destroy preserve pre-spawn worker admission controls", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const profileAdapter = adapter("linux-kvm", log);
    await createSandbox({ root, name: "starting", sourceRevision, profile: "linux-kvm", adapter: profileAdapter });
    const state = await resolveLauncherState({ root, name: "starting", sourceRevision });
    await beginWorkerStartup(
      state,
      Object.freeze({
        randomBytes: Object.freeze(() => Buffer.alloc(32, 8)) as never,
        identity: Object.freeze(() => `sha256:${"1".repeat(64)}`),
        parentPid: 123,
      }),
    );
    await assert.rejects(() =>
      resetSandbox({ root, name: "starting", sourceRevision, profile: "linux-kvm", adapter: profileAdapter }),
    );
    await assert.rejects(() =>
      destroySandbox({ root, name: "starting", sourceRevision, profile: "linux-kvm", adapter: profileAdapter }),
    );
    assert.deepEqual(log, ["create", "verify"]);
    assert.equal((await readManifest(state)).phase, "sandbox-ready");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core preserves api token and unknown controls before adapter actions", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const profileAdapter = adapter("insecure-container", log);
    await createSandbox({
      root,
      name: "token",
      sourceRevision,
      profile: "insecure-container",
      adapter: profileAdapter,
    });
    const state = await resolveLauncherState({ root, name: "token", sourceRevision });
    await createApiToken(
      state,
      Object.freeze({
        randomBytes: Object.freeze(() => Buffer.alloc(32, 3)) as never,
        identity: Object.freeze(() => `sha256:${"1".repeat(64)}`),
      }),
    );
    await assert.rejects(() =>
      destroySandbox({ root, name: "token", sourceRevision, profile: "insecure-container", adapter: profileAdapter }),
    );
    await writeFile(join(state.controlDir, "unknown"), "x", { mode: 0o600 });
    await assert.rejects(() =>
      resetSandbox({ root, name: "token", sourceRevision, profile: "insecure-container", adapter: profileAdapter }),
    );
    assert.deepEqual(log, ["create", "verify"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core preserves malformed worker controls and uncertain temp before adapter actions", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const profileAdapter = adapter("insecure-container", log);
    await createSandbox({
      root,
      name: "malformed",
      sourceRevision,
      profile: "insecure-container",
      adapter: profileAdapter,
    });
    const state = await resolveLauncherState({ root, name: "malformed", sourceRevision });
    await writeFile(join(state.controlDir, "worker.json"), "not-json\n", { mode: 0o600 });
    await assert.rejects(() =>
      statusSandbox({
        root,
        name: "malformed",
        sourceRevision,
        profile: "insecure-container",
        adapter: profileAdapter,
      }),
    );
    await assert.rejects(() =>
      destroySandbox({
        root,
        name: "malformed",
        sourceRevision,
        profile: "insecure-container",
        adapter: profileAdapter,
      }),
    );
    assert.deepEqual(log, ["create", "verify"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }

  const tempRoot = await temp();
  const tempLog: string[] = [];
  try {
    const profileAdapter = adapter("insecure-container", tempLog);
    await createSandbox({
      root: tempRoot,
      name: "temp",
      sourceRevision,
      profile: "insecure-container",
      adapter: profileAdapter,
    });
    const state = await resolveLauncherState({ root: tempRoot, name: "temp", sourceRevision });
    await writeFile(join(state.controlDir, `.worker-${state.stateId}-left.tmp`), "x", { mode: 0o600 });
    await assert.rejects(() =>
      resetSandbox({
        root: tempRoot,
        name: "temp",
        sourceRevision,
        profile: "insecure-container",
        adapter: profileAdapter,
      }),
    );
    assert.deepEqual(tempLog, ["create", "verify"]);
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("core reset/status require owned sandbox-ready and invoke verify", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const profileAdapter = adapter("linux-kvm", log);
    await assert.rejects(() =>
      statusSandbox({ root, name: "missing", sourceRevision, profile: "linux-kvm", adapter: profileAdapter }),
    );
    await createSandbox({ root, name: "core", sourceRevision, profile: "linux-kvm", adapter: profileAdapter });
    await resetSandbox({ root, name: "core", sourceRevision, profile: "linux-kvm", adapter: profileAdapter });
    await statusSandbox({ root, name: "core", sourceRevision, profile: "linux-kvm", adapter: profileAdapter });
    assert.deepEqual(log, ["create", "verify", "reset", "verify", "verify"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core create rolls back and removes state on exact cleanup success", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    await assert.rejects(() =>
      createSandbox({
        root,
        name: "rollback",
        sourceRevision,
        profile: "insecure-container",
        adapter: adapter("insecure-container", log, "verify"),
      }),
    );
    await assert.rejects(() =>
      statusSandbox({
        root,
        name: "rollback",
        sourceRevision,
        profile: "insecure-container",
        adapter: adapter("insecure-container", []),
      }),
    );
    assert.deepEqual(log, ["create", "verify", "destroy"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core create retains cleanup-required recovery state when rollback cleanup is uncertain", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const uncertain = Object.freeze({
      ...adapter("insecure-container", log),
      verify: Object.freeze(async () => {
        log.push("verify");
        throw new Error("profile failed");
      }),
      destroy: Object.freeze(async () => {
        log.push("destroy");
        throw new Error("cleanup failed");
      }),
    });
    await assert.rejects(() =>
      createSandbox({ root, name: "uncertain", sourceRevision, profile: "insecure-container", adapter: uncertain }),
    );
    await assert.rejects(
      () =>
        statusSandbox({
          root,
          name: "uncertain",
          sourceRevision,
          profile: "insecure-container",
          adapter: adapter("insecure-container", []),
        }),
      /not ready/,
    );
    assert.deepEqual(log, ["create", "verify", "destroy"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core rejects non-exact profile result for linux authority", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const bad = Object.freeze({
      ...adapter("linux-kvm", log),
      create: Object.freeze(async (state: LauncherState, generation: string) => {
        log.push("create");
        await rm(state.driverStateDir, { recursive: true, force: true });
        return deepFreeze({
          generation,
          profile: "linux-kvm" as const,
          operation: "create" as const,
          result: "pass" as const,
          authority: "authoritative-local" as const,
        });
      }),
    });
    await assert.rejects(() =>
      createSandbox({ root, name: "badresult", sourceRevision, profile: "linux-kvm", adapter: bad }),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core destroy preserves orphan profile state when launcher state is absent", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const stateName = "orphan";
    const { resolveLauncherState } = await import("../dev/launcher/state.ts");
    const state = await resolveLauncherState({ root, name: stateName, sourceRevision });
    await import("node:fs/promises").then((fs) => fs.mkdir(state.driverStateDir, { recursive: true }));
    await writeFile(join(state.driverStateDir, "competitor"), "exact bytes\n");
    await assert.rejects(() =>
      destroySandbox({
        root,
        name: stateName,
        sourceRevision,
        profile: "insecure-container",
        adapter: adapter("insecure-container", log),
      }),
    );
    assert.equal(await readFile(join(state.driverStateDir, "competitor"), "utf8"), "exact bytes\n");
    assert.deepEqual(log, []);
    await rm(state.driverStateDir, { recursive: true });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core rejects false destroy success when custom .cogs-dev parent is unsafe", async () => {
  const base = await temp();
  const parent = join(base, ".cogs-dev");
  const root = join(parent, "launcher");
  const log: string[] = [];
  try {
    await mkdir(parent, { mode: 0o700 });
    await mkdir(root, { mode: 0o700 });
    const destructive = Object.freeze({
      ...adapter("insecure-container", log),
      destroy: Object.freeze(async (state: LauncherState, generation: string) => {
        log.push("destroy");
        await rm(state.driverStateDir, { recursive: true, force: true });
        await chmod(parent, 0o755);
        return result("insecure-container", "destroy", generation);
      }),
    });
    await createSandbox({ root, name: "unsafe", sourceRevision, profile: "insecure-container", adapter: destructive });
    await assert.rejects(() =>
      destroySandbox({ root, name: "unsafe", sourceRevision, profile: "insecure-container", adapter: destructive }),
    );
    assert.deepEqual(log, ["create", "verify", "destroy"]);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("core destroy grants no authority when launcher and driver dirs are absent", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    await assert.rejects(() =>
      destroySandbox({
        root,
        name: "absent",
        sourceRevision,
        profile: "insecure-container",
        adapter: adapter("insecure-container", log),
      }),
    );
    assert.deepEqual(log, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core rejects stale reset/status revisions but destroy works across revisions", async () => {
  const root = await temp();
  try {
    const profileAdapter = adapter("insecure-container", []);
    await createSandbox({
      root,
      name: "stale",
      sourceRevision,
      profile: "insecure-container",
      adapter: profileAdapter,
    });
    const nextRevision = "3".repeat(40);
    await assert.rejects(() =>
      statusSandbox({
        root,
        name: "stale",
        sourceRevision: nextRevision,
        profile: "insecure-container",
        adapter: profileAdapter,
      }),
    );
    await assert.rejects(() =>
      resetSandbox({
        root,
        name: "stale",
        sourceRevision: nextRevision,
        profile: "insecure-container",
        adapter: profileAdapter,
      }),
    );
    await destroySandbox({
      root,
      name: "stale",
      sourceRevision: nextRevision,
      profile: "insecure-container",
      adapter: profileAdapter,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core snapshots options without getters and ignores post-call mutation", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const opts = {
      root,
      name: "snap",
      sourceRevision,
      profile: "insecure-container" as const,
      adapter: adapter("insecure-container", log),
    };
    const pending = createSandbox(opts);
    opts.name = "mutated";
    await pending;
    assert.deepEqual(log, ["create", "verify"]);
    const hostile = {};
    Object.defineProperty(hostile, "root", {
      get: () => {
        throw new Error("SECRET");
      },
      enumerable: true,
    });
    await assert.rejects(() => createSandbox(hostile as never));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("core destroy consumes authority rather than adopting after exact profile absence", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const profileAdapter = adapter("insecure-container", log);
    await createSandbox({
      root,
      name: "destroy",
      sourceRevision,
      profile: "insecure-container",
      adapter: profileAdapter,
    });
    assert.deepEqual(
      await destroySandbox({
        root,
        name: "destroy",
        sourceRevision,
        profile: "insecure-container",
        adapter: profileAdapter,
      }),
      { removed: true },
    );
    await assert.rejects(() =>
      destroySandbox({ root, name: "destroy", sourceRevision, profile: "insecure-container", adapter: profileAdapter }),
    );
    assert.deepEqual(log, ["create", "verify", "destroy"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const failure of ["failed", "partial", "malformed", "stale", "lost"] as const) {
  test(`create ${failure} response never arms parent rollback or adopts competitor`, async () => {
    const root = await temp(),
      log: string[] = [];
    const options = { root, name: "receipt", sourceRevision, profile: "linux-kvm" as const };
    const state = await resolveLauncherState({ root, name: options.name, sourceRevision });
    const competitor = Buffer.from([0, 1, 255, 42]);
    try {
      await mkdir(state.driverStateDir, { mode: 0o700 });
      await writeFile(join(state.driverStateDir, "competitor"), competitor);
      const before = await lstat(state.driverStateDir);
      const bad = Object.freeze({
        ...adapter("linux-kvm", log),
        create: Object.freeze(async (_state: LauncherState, generation: string) => {
          log.push("create");
          if (failure === "failed" || failure === "partial" || failure === "lost") throw new Error(failure);
          const receipt = result("linux-kvm", "create", failure === "stale" ? "0".repeat(32) : generation);
          return failure === "malformed" ? Object.freeze({ ...receipt, extra: true }) : receipt;
        }),
      });
      await assert.rejects(createSandbox({ ...options, adapter: bad }));
      assert.deepEqual(log, ["create"]);
      assert.deepEqual(await readFile(join(state.driverStateDir, "competitor")), competitor);
      assert.equal((await lstat(state.driverStateDir)).ino, before.ino);
      assert.equal((await readManifest(state)).phase, "cleanup-required");
      await assert.rejects(destroySandbox({ ...options, adapter: bad }));
      assert.deepEqual(log, ["create"]);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(state.driverStateDir, { recursive: true, force: true });
    }
  });
}

test("acquisition is issuer registered, fresh, phase-independent, and original-revision bound", async () => {
  const root = await temp(),
    log: string[] = [];
  const options = {
    root,
    name: "nonce",
    sourceRevision,
    profile: "linux-kvm" as const,
    adapter: adapter("linux-kvm", log),
  };
  try {
    const created = await createSandbox(options);
    const acquisition = acquiredSandbox(created, options);
    assert(Object.isFrozen(acquisition));
    assert.match(acquisition.generation, /^[a-f0-9]{32}$/);
    assert.throws(() => acquiredSandbox(Object.freeze({ ...created }), options));
    const state = await resolveLauncherState({ root, name: options.name, sourceRevision });
    await writePhase(state, created.manifest, "cleanup-required");
    assert.deepEqual(await readAcquisition(state), acquisition);
    await assert.rejects(destroySandbox(options, undefined, Object.freeze({ ...acquisition })));
    await destroySandbox({ ...options, sourceRevision: "3".repeat(40) }, undefined, acquisition);
    const next = await createSandbox(options);
    assert.notEqual(acquiredSandbox(next, options).generation, acquisition.generation);
    await assert.rejects(destroySandbox(options, undefined, acquisition));
    assert.equal((await readManifest(state)).phase, "sandbox-ready");
    await destroySandbox(options, undefined, acquiredSandbox(next, options));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("concurrent and pre-existing create preserve exact launcher custody", async () => {
  const root = await temp(),
    log: string[] = [];
  let release!: () => void, entered!: () => void;
  const barrier = new Promise<void>((r) => {
    release = r;
  });
  const entry = new Promise<void>((r) => {
    entered = r;
  });
  const base = adapter("linux-kvm", log);
  const options = {
    root,
    name: "concurrent",
    sourceRevision,
    profile: "linux-kvm" as const,
    adapter: Object.freeze({
      ...base,
      create: Object.freeze(async (state: LauncherState, nonce: string) => {
        entered();
        await barrier;
        return base.create(state, nonce);
      }),
    }),
  };
  const state = await resolveLauncherState({ root, name: options.name, sourceRevision });
  try {
    const pending = createSandbox(options);
    await entry;
    const bytes = await readFile(join(state.dir, ".cogs-launcher-acquisition"));
    await assert.rejects(createSandbox(options), /locked/);
    assert.deepEqual(await readFile(join(state.dir, ".cogs-launcher-acquisition")), bytes);
    release();
    await pending;
    const inventory = await readdir(state.dir);
    await assert.rejects(createSandbox(options));
    assert.deepEqual(await readdir(state.dir), inventory);
    assert.deepEqual(await readFile(join(state.dir, ".cogs-launcher-acquisition")), bytes);
    assert.deepEqual(log, ["create", "verify"]);
  } finally {
    release();
    await rm(root, { recursive: true, force: true });
  }
});

test("replaced launcher state during verify grants no mutation or deletion authority", async () => {
  const root = await temp(),
    log: string[] = [];
  const options = { root, name: "replace", sourceRevision, profile: "linux-kvm" as const };
  const state = await resolveLauncherState({ root, name: options.name, sourceRevision });
  try {
    const profileAdapter = Object.freeze({
      ...adapter("linux-kvm", log),
      verify: Object.freeze(async (_state: LauncherState, nonce: string) => {
        await rename(state.dir, `${state.dir}-old`);
        await mkdir(state.dir, { mode: 0o700 });
        await writeFile(join(state.dir, "foreign"), "untouched");
        return result("linux-kvm", "verify", nonce);
      }),
    });
    await assert.rejects(createSandbox({ ...options, adapter: profileAdapter }));
    assert.deepEqual(await readdir(state.dir), ["foreign"]);
    assert.equal(await readFile(join(state.dir, "foreign"), "utf8"), "untouched");
    assert.deepEqual(log, ["create"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("lost destroy response remains consumed despite mutable phase and replacement", async () => {
  const root = await temp(),
    log: string[] = [];
  const options = { root, name: "retirement", sourceRevision, profile: "linux-kvm" as const };
  const state = await resolveLauncherState({ root, name: options.name, sourceRevision });
  try {
    const profileAdapter = Object.freeze({
      ...adapter("linux-kvm", log),
      destroy: Object.freeze(async () => {
        log.push("destroy");
        throw new Error("lost response after effect");
      }),
    });
    await createSandbox({ ...options, adapter: profileAdapter });
    await assert.rejects(destroySandbox({ ...options, adapter: profileAdapter }));
    await writePhase(state, await readManifest(state), "sandbox-ready");
    await mkdir(state.driverStateDir, { mode: 0o700 });
    await writeFile(join(state.driverStateDir, "foreign"), "retained");
    await assert.rejects(destroySandbox({ ...options, adapter: profileAdapter }));
    assert.deepEqual(log, ["create", "verify", "destroy"]);
    assert.equal(await readFile(join(state.driverStateDir, "foreign"), "utf8"), "retained");
    await lstat(state.recoveryPath);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(state.driverStateDir, { recursive: true, force: true });
  }
});

test("mutable worker recovery and phase cannot clear acquisition uncertainty", async () => {
  const root = await temp(),
    log: string[] = [];
  const options = {
    root,
    name: "sticky",
    sourceRevision,
    profile: "linux-kvm" as const,
    adapter: adapter("linux-kvm", log),
  };
  try {
    await createSandbox(options);
    await assert.rejects(statusSandbox({ ...options, adapter: adapter("linux-kvm", log, "verify") }));
    const state = await resolveLauncherState({ root, name: options.name, sourceRevision });
    await rm(state.recoveryPath);
    await writePhase(state, await readManifest(state), "sandbox-ready");
    await assert.rejects(statusSandbox(options), /sticky/);
    await assert.rejects(resetSandbox(options), /sticky/);
    assert.deepEqual(log, ["create", "verify", "verify"]);
    await destroySandbox(options); // independently retained published acquisition may still settle
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("create lock-release failure has no successful acquisition response", async () => {
  const root = await temp(),
    log: string[] = [];
  try {
    const profileAdapter = Object.freeze({
      ...adapter("linux-kvm", log),
      verify: Object.freeze(async (state: LauncherState, nonce: string) => {
        await writeFile(join(state.lockDir, "extra"), "uncertain");
        return result("linux-kvm", "verify", nonce);
      }),
    });
    await assert.rejects(
      createSandbox({ root, name: "lock", sourceRevision, profile: "linux-kvm", adapter: profileAdapter }),
      /lock cleanup failed/,
    );
    assert.deepEqual(log, ["create"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

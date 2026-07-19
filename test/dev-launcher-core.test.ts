import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { type DriverResult, deepFreeze, type LauncherProfile } from "../dev/launcher/contract.ts";
import { beginWorkerStartup, createApiToken } from "../dev/launcher/control.ts";
import { createSandbox, destroySandbox, resetSandbox, statusSandbox } from "../dev/launcher/core.ts";
import type { ProfileAdapter } from "../dev/launcher/profiles.ts";
import type { LauncherState } from "../dev/launcher/state.ts";
import { readManifest, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";

const sourceRevision = "2".repeat(40);

function result(profile: LauncherProfile, operation: DriverResult["operation"]): DriverResult {
  return deepFreeze({
    profile,
    operation,
    result: profile === "linux-kvm" ? (operation === "destroy" ? "destroyed" : "ready") : "pass",
    authority: profile === "linux-kvm" ? "authoritative-local" : "functional-only",
  });
}

function adapter(profile: LauncherProfile, log: string[], fail?: string): ProfileAdapter {
  const op = async (name: DriverResult["operation"], state: LauncherState) => {
    log.push(name);
    if (fail === name) throw new Error("profile failed");
    if (name === "destroy") await rm(state.driverStateDir, { recursive: true, force: true });
    return result(profile, name);
  };
  const create = Object.freeze((state: LauncherState) => op("create", state));
  const verify = Object.freeze((state: LauncherState) => op("verify", state));
  const reset = Object.freeze((state: LauncherState) => op("reset", state));
  const destroy = Object.freeze((state: LauncherState) => op("destroy", state));
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
      create: Object.freeze(async (state: LauncherState) => {
        log.push("create");
        await rm(state.driverStateDir, { recursive: true, force: true });
        return deepFreeze({
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

test("core destroy removes orphan profile state when launcher state is absent", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    const stateName = "orphan";
    const { resolveLauncherState } = await import("../dev/launcher/state.ts");
    const state = await resolveLauncherState({ root, name: stateName, sourceRevision });
    await import("node:fs/promises").then((fs) => fs.mkdir(state.driverStateDir, { recursive: true }));
    assert.deepEqual(
      await destroySandbox({
        root,
        name: stateName,
        sourceRevision,
        profile: "insecure-container",
        adapter: adapter("insecure-container", log),
      }),
      { removed: true },
    );
    assert.deepEqual(log, ["destroy"]);
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
      destroy: Object.freeze(async (state: LauncherState) => {
        log.push("destroy");
        await rm(state.driverStateDir, { recursive: true, force: true });
        await chmod(parent, 0o755);
        return result("insecure-container", "destroy");
      }),
    });
    await assert.rejects(() =>
      destroySandbox({ root, name: "unsafe", sourceRevision, profile: "insecure-container", adapter: destructive }),
    );
    assert.deepEqual(log, ["destroy"]);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test("core destroy invokes adapter even when launcher and driver dirs are absent", async () => {
  const root = await temp();
  const log: string[] = [];
  try {
    assert.deepEqual(
      await destroySandbox({
        root,
        name: "absent",
        sourceRevision,
        profile: "insecure-container",
        adapter: adapter("insecure-container", log),
      }),
      { removed: true },
    );
    assert.deepEqual(log, ["destroy"]);
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

test("core destroy is idempotent after exact profile absence", async () => {
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
    assert.deepEqual(log, ["create", "verify", "destroy", "destroy"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

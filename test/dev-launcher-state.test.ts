import assert from "node:assert/strict";
import { chmod, link, lstat, mkdtemp, readdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { canonicalJson, createLauncherManifest, deepFreeze, parseCanonicalManifest } from "../dev/launcher/contract.ts";
import {
  createState,
  markRecovery,
  readManifest,
  removeOwnedState,
  resolveLauncherState,
  withStateLock,
  writePhase,
} from "../dev/launcher/state.ts";

const sourceRevision = "0".repeat(40);

async function root(): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "cogs-launcher-state-")));
  await chmod(dir, 0o700);
  return dir;
}

test("launcher state rejects noncanonical roots before state side effects", async () => {
  const dir = await root();
  try {
    await assert.rejects(() =>
      resolveLauncherState({ root: `${dir}/../${dir.split("/").pop()}`, name: "x", sourceRevision }),
    );
    await assert.rejects(() => resolveLauncherState({ root: "relative", name: "x", sourceRevision }));
    await assert.rejects(() => resolveLauncherState({ root: dir, name: "x", sourceRevision: "bad" }));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher state enforces direct child names, modes, canonical manifest, and owned removal", async () => {
  const dir = await root();
  try {
    await assert.rejects(() => resolveLauncherState({ root: dir, name: "../x", sourceRevision }));
    await assert.rejects(() => resolveLauncherState({ root: dir, name: "bad/slash", sourceRevision }));
    const state = await resolveLauncherState({ root: dir, name: "ok_1", sourceRevision });
    const manifest = await createState(state, "insecure-container");
    assert.equal(manifest.phase, "creating");
    assert.equal((await lstat(state.dir)).mode & 0o777, 0o700);
    assert.equal((await lstat(state.controlDir)).mode & 0o777, 0o700);
    assert.equal((await lstat(state.sentinelPath)).mode & 0o777, 0o600);
    assert.equal((await lstat(state.manifestPath)).mode & 0o777, 0o600);
    assert.deepEqual(await readManifest(state), manifest);
    const ready = await writePhase(state, manifest, "sandbox-ready");
    assert.equal((await readManifest(state)).phase, "sandbox-ready");
    assert.equal(canonicalJson(ready), await readFile(state.manifestPath, "utf8"));
    await removeOwnedState(state);
    await assert.rejects(() => lstat(state.dir), /ENOENT/);
    assert.equal(
      (await readdir(dir)).some((entry) => entry.startsWith(".remove-")),
      false,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher state rejects symlinks, malformed duplicate manifests, extras, symbols, and accessors", async () => {
  assert.throws(() => parseCanonicalManifest('{"version":"x","version":"x"}\n'));
  const hostile = {
    get version() {
      throw new Error("secret");
    },
  };
  assert.throws(() => canonicalJson(hostile));
  const cyclic: { self?: unknown } = {};
  cyclic.self = cyclic;
  assert.equal(deepFreeze(cyclic).self, cyclic);
  assert.throws(() => canonicalJson(cyclic));
  const withExtra = {
    ...createLauncherManifest({
      sourceRevision,
      stateId: "1".repeat(16),
      stateName: "state",
      profile: "linux-kvm",
      phase: "creating",
      owned: { sandboxState: "control/sandbox", controlDir: "control", lockName: "state.lock" },
    }),
    extra: true,
  };
  assert.throws(() => parseCanonicalManifest(`${JSON.stringify(withExtra)}\n`));

  const dir = await root();
  try {
    await symlink(dir, join(dir, "link"));
    await assert.rejects(() => resolveLauncherState({ root: join(dir, "link"), name: "x", sourceRevision }));
    const state = await resolveLauncherState({ root: dir, name: "badmanifest", sourceRevision });
    await createState(state, "linux-kvm");
    await writeFile(state.manifestPath, '{"version":"x","version":"x"}\n', { mode: 0o600 });
    await assert.rejects(() => readManifest(state));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher state rejects unsafe file reads by mode and hardlink", async () => {
  const dir = await root();
  try {
    const state = await resolveLauncherState({ root: dir, name: "readsafe", sourceRevision });
    await createState(state, "insecure-container");
    await chmod(state.manifestPath, 0o644);
    await assert.rejects(() => readManifest(state));
    await chmod(state.manifestPath, 0o600);
    await link(state.sentinelPath, join(dir, "sentinel-hardlink"));
    await assert.rejects(() => readManifest(state));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher state lock release fails on owner replacement or extra entry", async () => {
  const dir = await root();
  try {
    const state = await resolveLauncherState({ root: dir, name: "lockextra", sourceRevision });
    await assert.rejects(
      () =>
        withStateLock(state, async () => {
          await writeFile(join(state.lockDir, "extra"), "x", { mode: 0o600 });
        }),
      /cleanup failed/,
    );
    await assert.rejects(() => withStateLock(state, async () => undefined), /locked/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher state lock serializes and never auto-breaks existing locks", async () => {
  const dir = await root();
  try {
    const state = await resolveLauncherState({ root: dir, name: "lock", sourceRevision });
    let entered = false;
    await assert.rejects(
      () =>
        withStateLock(state, async () => {
          entered = true;
          await withStateLock(state, async () => undefined);
        }),
      /locked/,
    );
    assert.equal(entered, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher state id is stable across source revisions for destroy", async () => {
  const dir = await root();
  try {
    const first = await resolveLauncherState({ root: dir, name: "upgrade", sourceRevision: "1".repeat(40) });
    const second = await resolveLauncherState({ root: dir, name: "upgrade", sourceRevision: "2".repeat(40) });
    assert.equal(first.stateId, second.stateId);
    await createState(first, "linux-kvm");
    assert.equal((await readManifest(second)).sourceRevision, "1".repeat(40));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher state records recovery sentinel on uncertain cleanup", async () => {
  const dir = await root();
  try {
    const state = await resolveLauncherState({ root: dir, name: "recover", sourceRevision });
    await createState(state, "insecure-container");
    await markRecovery(state, "destroy-uncertain");
    const recovery = await readFile(state.recoveryPath, "utf8");
    assert.match(recovery, /cogs\.dev-launcher-recovery\/v1alpha1/);
    assert.doesNotMatch(recovery, /SECRET|prompt|credential/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

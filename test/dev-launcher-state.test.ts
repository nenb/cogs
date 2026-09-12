import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import fs, { chmod, link, lstat, mkdtemp, readdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { canonicalJson, createLauncherManifest, deepFreeze, parseCanonicalManifest } from "../dev/launcher/contract.ts";
import {
  clearRecovery,
  consumeDriverAcquisition,
  createState,
  markAcquisitionUncertain,
  markRecovery,
  publishDriverAcquisition,
  readAcquisition,
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

test("launcher retirement preserves final-boundary authority replacements and sticky uncertainty", async (t) => {
  const originalRename = fs.rename,
    originalUnlink = fs.unlink;
  for (const operation of ["lock", "recovery", "state"] as const) {
    const names =
      operation === "state"
        ? [
            "manifest.json",
            ".cogs-launcher-owner",
            ".cogs-launcher-acquisition",
            ".cogs-launcher-recovery",
            ".cogs-launcher-driver",
            ".cogs-launcher-retirement",
            ".cogs-launcher-uncertainty",
          ]
        : [operation === "lock" ? "owner" : ".cogs-launcher-recovery"];
    for (const target of names)
      for (const boundary of ["rename", "unlink"]) {
        const dir = await root();
        const state = await resolveLauncherState({ root: dir, name: "race", sourceRevision });
        await createState(state, "linux-kvm");
        const authority = await readAcquisition(state);
        await publishDriverAcquisition(state, authority);
        await consumeDriverAcquisition(state, authority);
        await markAcquisitionUncertain(state, authority);
        await markRecovery(state, "original");
        let fired = false,
          foreignInode = 0,
          foreignBytes = Buffer.alloc(0);
        const moves = new Map<string, string>();
        const replace = async (path: string, moved?: string) => {
          fired = true;
          // Byte-identical replacements still confer no authority. Keep the original
          // inode live rather than relying on platform-specific inode reuse timing.
          foreignBytes = await readFile(moved ?? path);
          if (!moved) await originalRename(path, join(dir, "saved"));
          await writeFile(path, foreignBytes, { mode: 0o600 });
          foreignInode = (await lstat(path)).ino;
        };
        t.mock.method(fs, "rename", async (from: string, to: string) => {
          if (from.endsWith(`/${target}`)) {
            if (boundary === "rename" && !fired) await replace(from);
            moves.set(to, from);
          }
          return originalRename(from, to);
        });
        t.mock.method(fs, "unlink", async (path: string) => {
          const old = moves.get(path);
          if (boundary === "unlink" && old && !fired) await replace(old, path);
          return originalUnlink(path);
        });
        syncBuiltinESMExports();
        try {
          await assert.rejects(
            operation === "lock"
              ? withStateLock(state, async () => undefined)
              : operation === "recovery"
                ? clearRecovery(state)
                : removeOwnedState(state),
          );
          assert(fired, `${operation}/${target}/${boundary}`);
          const retained = (await readdir(dir, { recursive: true })).map((name) => join(dir, name));
          let preserved = false;
          for (const path of retained)
            if ((await lstat(path)).ino === foreignInode) {
              assert.deepEqual(await readFile(path), foreignBytes);
              preserved = true;
            }
          assert(preserved, `${target}: foreign inode must survive`);
          await assert.rejects(readAcquisition(state), /sticky/);
          await assert.rejects(clearRecovery(state), /sticky/);
          await assert.rejects(createState(state, "linux-kvm"), /sticky/);
          let effects = 0;
          await assert.rejects(
            withStateLock(state, async () => {
              effects++;
            }),
            /sticky/,
          );
          assert.equal(effects, 0);
        } finally {
          t.mock.restoreAll();
          syncBuiltinESMExports();
          await rm(dir, { recursive: true, force: true });
        }
      }
  }
});

test("launcher retirement I/O uncertainty remains sticky even after quarantine removal", async (t) => {
  for (const fault of ["unlink", "post-rmdir"]) {
    const dir = await root();
    const state = await resolveLauncherState({ root: dir, name: "io", sourceRevision });
    await createState(state, "linux-kvm");
    await markRecovery(state, "original");
    const original = fs[fault === "unlink" ? "unlink" : "rmdir"];
    let fired = false;
    t.mock.method(fs, fault === "unlink" ? "unlink" : "rmdir", async (path: string) => {
      if (path.includes(`/.retire-${state.stateId}-`) && !fired) {
        fired = true;
        if (fault === "post-rmdir") await original(path);
        throw new Error("injected retirement I/O failure");
      }
      return original(path);
    });
    syncBuiltinESMExports();
    try {
      await assert.rejects(clearRecovery(state), /cleanup failed/);
      assert(fired);
      await assert.rejects(readAcquisition(state), /sticky/);
      await assert.rejects(clearRecovery(state), /sticky/);
    } finally {
      t.mock.restoreAll();
      syncBuiltinESMExports();
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("launcher acquisition opens nonblocking nofollow before rejecting special-file fstat", async (t) => {
  const dir = await root();
  const state = await resolveLauncherState({ root: dir, name: "special", sourceRevision });
  await createState(state, "linux-kvm");
  const originalOpen = fs.open;
  let opened = 0,
    closed = 0,
    reads = 0;
  t.mock.method(fs, "open", async (path: string, flags: number) => {
    if (!path.endsWith("/.cogs-launcher-acquisition")) return originalOpen(path, flags);
    assert.equal(flags, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    opened++;
    return {
      stat: async () => ({ isFile: () => false }),
      close: async () => {
        closed++;
      },
      readFile: async () => {
        reads++;
        throw new Error("special file read");
      },
    };
  });
  syncBuiltinESMExports();
  try {
    const before = await readdir(state.dir);
    await assert.rejects(readAcquisition(state), /invalid launcher state/);
    assert.equal(opened, 1);
    assert.equal(closed, 1);
    assert.equal(reads, 0);
    assert.deepEqual(await readdir(state.dir), before);
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher acquisition special files reject without blocking or effects (real FIFO)", async (t) => {
  const available = spawnSync("sh", ["-c", "command -v mkfifo"], { encoding: "utf8" });
  if (available.status !== 0) return t.skip("mkfifo unavailable");
  const dir = await root();
  try {
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "--input-type=module",
        "-e",
        `
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {constants} from 'node:fs';
import fs from 'node:fs/promises';
import {syncBuiltinESMExports} from 'node:module';
import {join} from 'node:path';
import * as s from './dev/launcher/state.ts';
const state=await s.resolveLauncherState({root:process.argv[1],name:'fifo',sourceRevision:'0'.repeat(40)});
const authority=s.issueAcquisition(state,'linux-kvm');
await s.createState(state,'linux-kvm',authority); await s.publishDriverAcquisition(state,authority);
const originalOpen=fs.open;
let opens=0;
fs.open=async (path,flags,...rest)=>{
 if (typeof path==='string' && path.startsWith(state.dir+'/') && !(flags & constants.O_CREAT)) {
  assert.equal(flags & (constants.O_NONBLOCK|constants.O_NOFOLLOW),constants.O_NONBLOCK|constants.O_NOFOLLOW); opens++;
 }
 return originalOpen(path,flags,...rest);
};
syncBuiltinESMExports();
for (const name of ['.cogs-launcher-acquisition','.cogs-launcher-owner','.cogs-launcher-driver']) {
 const path=join(state.dir,name), saved=join(state.root,'saved');
 await fs.rename(path,saved);
 assert.equal(spawnSync('mkfifo',['-m','600',path]).status,0);
 const before=await fs.readdir(state.dir);
 const ino=(await fs.lstat(path)).ino;
 const checks=name==='.cogs-launcher-driver'
  ? [()=>s.assertDriverAcquisition(state,authority),()=>s.consumeDriverAcquisition(state,authority)]
  : [()=>s.readAcquisition(state),()=>s.assertAcquisition(state,authority),()=>s.assertAcquisitionUsable(state,authority)];
 for (const check of checks) await assert.rejects(check,/invalid launcher state/);
 assert.deepEqual(await fs.readdir(state.dir),before);
 assert.equal((await fs.lstat(path)).ino,ino);
 assert((await fs.lstat(path)).isFIFO());
 await fs.unlink(path); await fs.rename(saved,path);
}
assert(opens>0);
assert.equal((await s.readAcquisition(state)).generation,authority.generation);
await s.assertDriverAcquisition(state,authority);
`,
        dir,
      ],
      { encoding: "utf8", timeout: 10000 },
    );
    assert.equal(result.error, undefined, result.stderr);
    assert.equal(result.status, 0, result.stderr);
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

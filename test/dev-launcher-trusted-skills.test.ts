import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createState, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";
import { createTrustedSkillInputs } from "../dev/launcher/trusted-skills.ts";
import { verifyCogsSkillBundle } from "../src/skills/bundle.ts";
import { createCogsPrivateSkillStore } from "../src/skills/local-private-store.ts";
import { createCogsSharedSkillOciLayoutResolver } from "../src/skills/oci-layout.ts";
import { SshConnectionManager } from "../src/ssh/connection.ts";

const sourceRevision = "b".repeat(40);
const bundleDigest = "sha256:db1d1d550f597a03595794d95ca6c596c16a4b3b4f2304301f03c93bc6b53c0c";
const configDigest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const manifestDigest = "sha256:726176e9bdb7524fbe935a0235fcbe5d509bf44592b9571421fc9fd8551ff1c1";
const indexDigest = "sha256:8774a0322b44a711ccfb252d59ab4dc9bcdc09d791f9a72b985765931d305111";
const aliceNamespace = "2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90";

type Setup = Awaited<ReturnType<typeof setup>>;

async function setup() {
  const temp = await realpath(await mkdtemp(join(tmpdir(), "cogs-trusted-skills-")));
  await chmod(temp, 0o700);
  const launcherRoot = join(temp, "launcher");
  await mkdir(launcherRoot, { mode: 0o700 });
  await chmod(launcherRoot, 0o700);
  const state = await resolveLauncherState({ root: launcherRoot, name: "session", sourceRevision });
  const creating = await createState(state, "insecure-container");
  await writePhase(state, creating, "sandbox-ready");
  return { temp, state, staticRoot: join(state.sandboxDir, "trusted-skills") };
}

async function cleanup(value: Setup): Promise<void> {
  await rm(value.temp, { recursive: true, force: true });
}

function sha256(bytes: Buffer): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function read(path: string): Promise<Buffer> {
  const handle = await open(path, "r");
  try {
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

function manager(): SshConnectionManager {
  return new SshConnectionManager({
    config: {
      endpoint: "127.0.0.1:22",
      username: "root",
      hostKeySha256: `SHA256:${"A".repeat(43)}`,
      clientKeyPath: "/run/cogs/ssh/launcher-test",
    },
  });
}

test("creates byte-exact real empty OCI and private provenance and removes exact inventory", async () => {
  const value = await setup();
  try {
    const handle = await createTrustedSkillInputs(value.state);
    assert.equal(handle.sharedRevision, manifestDigest);
    assert.equal(handle.userRevision, bundleDigest);
    assert.equal(Object.isFrozen(handle), true);
    assert.deepEqual(Object.keys(handle).sort(), ["close", "createPreparer", "sharedRevision", "userRevision"]);
    assert.equal(JSON.stringify(handle).includes(value.staticRoot), false);

    assert.equal(
      (await read(join(value.staticRoot, ".cogs-trusted-skills-owner"))).toString("utf8"),
      `${value.state.stateId}\n`,
    );
    const shared = join(value.staticRoot, "shared-oci");
    const blobRoot = join(shared, "blobs", "sha256");
    const bundleBytes = await read(join(blobRoot, bundleDigest.slice(7)));
    const configBytes = await read(join(blobRoot, configDigest.slice(7)));
    const manifestBytes = await read(join(blobRoot, manifestDigest.slice(7)));
    const indexBytes = await read(join(shared, "index.json"));
    assert.equal(bundleBytes.length, 109);
    assert.equal(configBytes.toString("utf8"), "{}");
    assert.equal(manifestBytes.length, 451);
    assert.equal(indexBytes.length, 246);
    assert.equal(sha256(bundleBytes), bundleDigest);
    assert.equal(sha256(configBytes), configDigest);
    assert.equal(sha256(manifestBytes), manifestDigest);
    assert.equal(sha256(indexBytes), indexDigest);
    assert.equal(verifyCogsSkillBundle(bundleBytes).fileCount, 0);

    const sharedResolver = await createCogsSharedSkillOciLayoutResolver({ layoutRoot: shared });
    const sharedResult = await sharedResolver.resolve({ manifestDigest });
    assert.equal(sharedResult.bundleDigest, bundleDigest);
    assert.equal(sharedResult.fileCount, 0);
    const privateStore = await createCogsPrivateSkillStore({
      sourceRoot: join(value.staticRoot, "private-source"),
      storeRoot: join(value.staticRoot, "private-store"),
    });
    const userResult = await privateStore.resolve({ userId: "alice", digest: bundleDigest });
    assert.equal(userResult.fileCount, 0);
    assert.equal(userResult.userNamespace, `sha256:${aliceNamespace}`);

    const preparer = handle.createPreparer(manager());
    assert.equal(Object.isFrozen(preparer), true);
    assert.deepEqual(Object.keys(preparer), ["prepare"]);
    const first = handle.close();
    assert.equal(handle.close(), first);
    await first;
    await assert.rejects(lstat(value.staticRoot), { code: "ENOENT" });
    assert.deepEqual(await readdir(value.state.sandboxDir), []);
  } finally {
    await cleanup(value);
  }
});

test("does not create mutable Pi session or agent roots", async () => {
  const value = await setup();
  try {
    const handle = await createTrustedSkillInputs(value.state);
    const rootEntries = (await readdir(value.staticRoot)).sort();
    assert.deepEqual(rootEntries, [".cogs-trusted-skills-owner", "private-source", "private-store", "shared-oci"]);
    assert.equal(
      rootEntries.some((entry) => /session|agent|history|export/u.test(entry)),
      false,
    );
    await handle.close();
  } finally {
    await cleanup(value);
  }
});

test("rejects collisions, wrong phase, and pre-abort without broad deletion", async () => {
  const collision = await setup();
  try {
    await mkdir(collision.staticRoot, { mode: 0o700 });
    await writeFile(join(collision.staticRoot, "caller-owned"), "keep", { mode: 0o600 });
    await assert.rejects(createTrustedSkillInputs(collision.state), /trusted skills/);
    assert.deepEqual(await readdir(collision.staticRoot), ["caller-owned"]);
  } finally {
    await cleanup(collision);
  }

  const wrongPhase = await setup();
  try {
    const manifest = await import("../dev/launcher/state.ts").then(({ readManifest }) =>
      readManifest(wrongPhase.state),
    );
    await writePhase(wrongPhase.state, manifest, "cleanup-required");
    await assert.rejects(createTrustedSkillInputs(wrongPhase.state), /trusted skills/);
    assert.deepEqual(await readdir(wrongPhase.state.sandboxDir), []);
  } finally {
    await cleanup(wrongPhase);
  }

  const aborted = await setup();
  try {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(createTrustedSkillInputs(aborted.state, controller.signal), /trusted skills/);
    assert.deepEqual(await readdir(aborted.state.sandboxDir), []);
  } finally {
    await cleanup(aborted);
  }
});

test("aborts after partial creation and rolls back only exact known objects", async () => {
  for (const stage of ["after-directories", "after-shared-files", "after-private-store"]) {
    const value = await setup();
    try {
      const controller = new AbortController();
      await assert.rejects(
        createTrustedSkillInputs(
          value.state,
          controller.signal,
          Object.freeze({
            after: Object.freeze((observed: string) => {
              if (observed === stage) controller.abort();
            }),
          }),
        ),
        /trusted skills/,
      );
      assert.deepEqual(await readdir(value.state.sandboxDir), []);
    } finally {
      await cleanup(value);
    }
  }
});

test("preserves unknown partial artifacts and reports one generic error", async () => {
  const value = await setup();
  try {
    const error = await createTrustedSkillInputs(
      value.state,
      undefined,
      Object.freeze({
        after: Object.freeze(async (stage: string) => {
          if (stage === "after-private-store")
            await writeFile(join(value.staticRoot, "unknown"), "unknown", { mode: 0o600 });
        }),
      }),
    ).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    assert.equal((error as Error).message, "launcher trusted skills failed");
    assert.equal((await readdir(value.staticRoot)).includes("unknown"), true);
    assert.equal(JSON.stringify(error).includes(value.staticRoot), false);
  } finally {
    await cleanup(value);
  }
});

test("rejects sentinel growth and replacement during final readiness verification", async () => {
  for (const mutation of ["grow", "replace"] as const) {
    const value = await setup();
    try {
      await assert.rejects(
        createTrustedSkillInputs(
          value.state,
          undefined,
          Object.freeze({
            after: Object.freeze(async (stage: string) => {
              if (stage !== "after-sentinel-open") return;
              const sentinel = join(value.staticRoot, ".cogs-trusted-skills-owner");
              if (mutation === "grow") {
                await writeFile(sentinel, `${value.state.stateId}\nextra`, { mode: 0o600 });
              } else {
                const replacement = join(value.staticRoot, "sentinel-replacement");
                await writeFile(replacement, `${value.state.stateId}\n`, { mode: 0o600 });
                await rename(replacement, sentinel);
              }
            }),
          }),
        ),
        /trusted skills/,
      );
      await lstat(value.staticRoot);
    } finally {
      await cleanup(value);
    }
  }
});

test("rejects final snapshot mutation and post-create parent uncertainty without broad removal", async () => {
  const race = await setup();
  try {
    await assert.rejects(
      createTrustedSkillInputs(
        race.state,
        undefined,
        Object.freeze({
          after: Object.freeze(async (stage: string) => {
            if (stage === "after-final-snapshot")
              await writeFile(join(race.staticRoot, "shared-oci", "index.json"), "changed", { mode: 0o600 });
          }),
        }),
      ),
      /trusted skills/,
    );
    await lstat(race.staticRoot);
  } finally {
    await cleanup(race);
  }

  const parent = await setup();
  try {
    await assert.rejects(
      createTrustedSkillInputs(
        parent.state,
        undefined,
        Object.freeze({
          after: Object.freeze(async (stage: string) => {
            if (stage === "after-directory-create") await chmod(parent.state.sandboxDir, 0o755);
          }),
        }),
      ),
      /trusted skills/,
    );
    await chmod(parent.state.sandboxDir, 0o700);
    try {
      await lstat(parent.staticRoot);
    } catch (error) {
      assert.equal((error as NodeJS.ErrnoException).code, "ENOENT");
    }
  } finally {
    await cleanup(parent);
  }
});

test("cleanup unlink race preserves static root and returns same failing promise", async () => {
  const value = await setup();
  try {
    let injected = false;
    const handle = await createTrustedSkillInputs(
      value.state,
      undefined,
      Object.freeze({
        after: Object.freeze(async (stage: string) => {
          if (stage === "after-file-unlink" && !injected) {
            injected = true;
            await writeFile(join(value.staticRoot, "unknown-after-unlink"), "x", { mode: 0o600 });
          }
        }),
      }),
    );
    const first = handle.close();
    assert.equal(handle.close(), first);
    await assert.rejects(first, /trusted skills/);
    await lstat(value.staticRoot);
  } finally {
    await cleanup(value);
  }
});

test("cleanup rejects file mutation, inode replacement, unknown entries, and nonempty active root", async () => {
  const mutations: Array<(value: Setup) => Promise<void>> = [
    async (value) => {
      await writeFile(join(value.staticRoot, ".cogs-trusted-skills-owner"), "wrong\n", { mode: 0o600 });
    },
    async (value) => {
      await writeFile(join(value.staticRoot, "shared-oci", "index.json"), "changed", { mode: 0o600 });
    },
    async (value) => {
      const target = join(value.staticRoot, "shared-oci", "index.json");
      const replacement = join(value.staticRoot, "shared-oci", "replacement");
      await writeFile(replacement, await read(target), { mode: 0o600 });
      await rename(replacement, target);
    },
    async (value) => {
      await writeFile(join(value.staticRoot, "unknown"), "unknown", { mode: 0o600 });
    },
    async (value) => {
      await mkdir(join(value.staticRoot, "unknown-dir"), { mode: 0o700 });
      await writeFile(join(value.staticRoot, "unknown-dir", "file"), "x", { mode: 0o600 });
    },
    async (value) => {
      await chmod(join(value.staticRoot, "shared-oci"), 0o755);
    },
    async (value) => {
      await symlink("shared-oci", join(value.staticRoot, "linked"));
    },
    async (value) => {
      for (let index = 0; index < 70; index += 1) {
        await writeFile(join(value.staticRoot, `wide-${index}`), "x", { mode: 0o600 });
      }
    },
    async (value) => {
      let current = value.staticRoot;
      for (let index = 0; index < 10; index += 1) {
        current = join(current, `deep-${index}`);
        await mkdir(current, { mode: 0o700 });
        await chmod(current, 0o700);
      }
    },
  ];
  for (const mutate of mutations) {
    const value = await setup();
    try {
      const handle = await createTrustedSkillInputs(value.state);
      await mutate(value);
      const first = handle.close();
      assert.equal(handle.close(), first);
      await assert.rejects(first, /trusted skills/);
      await lstat(value.staticRoot);
    } finally {
      await cleanup(value);
    }
  }
});

test("rejects hostile seams and non-real SSH manager values", async () => {
  const value = await setup();
  try {
    await assert.rejects(createTrustedSkillInputs(value.state, undefined, {} as never), /trusted skills/);
    await assert.rejects(
      createTrustedSkillInputs(value.state, undefined, Object.freeze({ after: () => undefined }) as never),
      /trusted skills/,
    );
    await assert.rejects(createTrustedSkillInputs(value.state, {} as never), /trusted skills/);
    const handle = await createTrustedSkillInputs(value.state);
    assert.throws(() => handle.createPreparer({} as SshConnectionManager), /trusted skills/);
    await handle.close();
  } finally {
    await cleanup(value);
  }
});

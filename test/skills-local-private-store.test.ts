import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, open, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import {
  buildCogsSkillBundle,
  COGS_SKILLS_BUNDLE_MAX_DECODED_BYTES,
  COGS_SKILLS_BUNDLE_MAX_FILE_BYTES,
} from "../src/skills/bundle.ts";
import { CogsPrivateSkillStoreError, createCogsPrivateSkillStore } from "../src/skills/local-private-store.ts";

const execFileAsync = promisify(execFile);

function userNamespace(userId: string): string {
  return createHash("sha256").update(userId, "utf8").digest("hex");
}

function assertInvalid(operation: () => Promise<unknown> | unknown): Promise<void> | void {
  const validate = (error: unknown) => {
    assert.ok(error instanceof CogsPrivateSkillStoreError);
    assert.equal(error.message, "invalid private skill store");
    assert.equal(error.code, "COGS_PRIVATE_SKILL_STORE_INVALID");
    assert.equal(String(error).includes("/"), false);
    return true;
  };
  const result = operation();
  if (result instanceof Promise) return assert.rejects(result, validate);
  assert.fail("operation unexpectedly succeeded");
}

async function withTemp<T>(fn: (root: string) => Promise<T>): Promise<T> {
  const root = await mkdtemp(path.join(tmpdir(), "cogs-private-skills-"));
  try {
    return await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function createRoots(root: string) {
  const sourceRoot = path.join(root, "source");
  const storeRoot = path.join(root, "store");
  await mkdir(sourceRoot, { recursive: true });
  await mkdir(storeRoot, { recursive: true });
  return { sourceRoot, storeRoot };
}

async function writeUserFile(sourceRoot: string, userId: string, relative: string, bytes: Buffer | string) {
  const file = path.join(sourceRoot, userNamespace(userId), ...relative.split("/"));
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, bytes);
  return file;
}

test("snapshots, stores, and resolves deterministic private skills", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    const userId = "user-1";
    await writeUserFile(sourceRoot, userId, "skill/SKILL.md", "---\nname: one\ndescription: one\n---\n");
    const expected = buildCogsSkillBundle({
      entries: [
        {
          path: "skill/SKILL.md",
          executable: false,
          content: Buffer.from("---\nname: one\ndescription: one\n---\n"),
        },
      ],
    });

    const store = await createCogsPrivateSkillStore({ sourceRoot, storeRoot });
    const snapshot = await store.snapshot({ userId, expectedDigest: expected.digest });
    assert.equal(snapshot.scope, "user");
    assert.equal(snapshot.userNamespace, `sha256:${userNamespace(userId)}`);
    assert.equal(snapshot.digest, expected.digest);
    assert.equal(snapshot.fileCount, 1);
    assert.equal(
      snapshot.bundle.copyFile("skill/SKILL.md").toString("utf8"),
      "---\nname: one\ndescription: one\n---\n",
    );
    assert.ok(Object.isFrozen(snapshot));

    const blob = path.join(
      storeRoot,
      userNamespace(userId),
      "blobs",
      "sha256",
      expected.digest.slice("sha256:".length),
    );
    assert.equal((await lstat(blob)).isFile(), true);
    const resolved = await store.resolve({ userId, digest: expected.digest });
    assert.equal(resolved.digest, expected.digest);
    assert.deepEqual(resolved.bundle.files, snapshot.bundle.files);
  });
});

test("empty source directory snapshots to deterministic empty bundle", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    const userId = "empty-user";
    await mkdir(path.join(sourceRoot, userNamespace(userId)), { recursive: true });
    const empty = buildCogsSkillBundle({ entries: [] });
    const store = await createCogsPrivateSkillStore({ sourceRoot, storeRoot });
    const result = await store.snapshot({ userId, expectedDigest: empty.digest });
    assert.equal(result.fileCount, 0);
    assert.equal((await store.resolve({ userId, digest: empty.digest })).digest, empty.digest);
  });
});

test("digest mismatch fails before store side effects", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    const userId = "mismatch-user";
    await writeUserFile(sourceRoot, userId, "a.md", "a");
    const wrong = buildCogsSkillBundle({ entries: [] }).digest;
    const store = await createCogsPrivateSkillStore({ sourceRoot, storeRoot });
    await assertInvalid(() => store.snapshot({ userId, expectedDigest: wrong }));
    assert.deepEqual(await readdir(storeRoot), []);
  });
});

test("resolve is scoped by user namespace", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    await writeUserFile(sourceRoot, "user-a", "a.md", "a");
    const expected = buildCogsSkillBundle({
      entries: [{ path: "a.md", executable: false, content: Buffer.from("a") }],
    });
    const store = await createCogsPrivateSkillStore({ sourceRoot, storeRoot });
    await store.snapshot({ userId: "user-a", expectedDigest: expected.digest });
    await assertInvalid(() => store.resolve({ userId: "user-b", digest: expected.digest }));
    assert.equal((await readdir(storeRoot)).includes("user-b"), false);
  });
});

test("rejects links, hardlinks, fifos, oversized files, too many files, and excessive depth", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    const store = await createCogsPrivateSkillStore({ sourceRoot, storeRoot });

    await mkdir(path.join(sourceRoot, userNamespace("symlink-user")), { recursive: true });
    await symlink("target", path.join(sourceRoot, userNamespace("symlink-user"), "link.md"));
    await assertInvalid(() =>
      store.snapshot({ userId: "symlink-user", expectedDigest: buildCogsSkillBundle({ entries: [] }).digest }),
    );

    const hard = await writeUserFile(sourceRoot, "hardlink-user", "hard.md", "hard");
    await link(hard, path.join(path.dirname(hard), "other.md"));
    const hardExpected = buildCogsSkillBundle({
      entries: [{ path: "hard.md", executable: false, content: Buffer.from("hard") }],
    });
    await assertInvalid(() => store.snapshot({ userId: "hardlink-user", expectedDigest: hardExpected.digest }));

    const fifoDir = path.join(sourceRoot, userNamespace("fifo-user"));
    await mkdir(fifoDir, { recursive: true });
    try {
      await execFileAsync("mkfifo", [path.join(fifoDir, "pipe")]);
      await assertInvalid(() =>
        store.snapshot({ userId: "fifo-user", expectedDigest: buildCogsSkillBundle({ entries: [] }).digest }),
      );
    } catch (error) {
      if ((error as { code?: string }).code !== "ENOENT") throw error;
    }

    await writeUserFile(sourceRoot, "large-user", "large.md", Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES + 1));
    await assertInvalid(() =>
      store.snapshot({ userId: "large-user", expectedDigest: buildCogsSkillBundle({ entries: [] }).digest }),
    );

    for (let index = 0; index < 129; index += 1) await writeUserFile(sourceRoot, "many-user", `f${index}.md`, "");
    await assertInvalid(() =>
      store.snapshot({ userId: "many-user", expectedDigest: buildCogsSkillBundle({ entries: [] }).digest }),
    );

    for (let index = 0; index < 257; index += 1) {
      await mkdir(path.join(sourceRoot, userNamespace("wide-user"), `d${index}`), { recursive: true });
    }
    await assertInvalid(() =>
      store.snapshot({ userId: "wide-user", expectedDigest: buildCogsSkillBundle({ entries: [] }).digest }),
    );

    await writeUserFile(sourceRoot, "total-user", "a.md", Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES));
    await writeUserFile(sourceRoot, "total-user", "b.md", Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES));
    await writeUserFile(sourceRoot, "total-user", "c.md", Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES));
    await writeUserFile(sourceRoot, "total-user", "d.md", Buffer.alloc(1));
    assert.equal(COGS_SKILLS_BUNDLE_MAX_DECODED_BYTES, COGS_SKILLS_BUNDLE_MAX_FILE_BYTES * 3);
    await assertInvalid(() =>
      store.snapshot({ userId: "total-user", expectedDigest: buildCogsSkillBundle({ entries: [] }).digest }),
    );

    let deep = path.join(sourceRoot, userNamespace("deep-user"));
    for (let index = 0; index < 17; index += 1) deep = path.join(deep, `d${index}`);
    await mkdir(deep, { recursive: true });
    await assertInvalid(() =>
      store.snapshot({ userId: "deep-user", expectedDigest: buildCogsSkillBundle({ entries: [] }).digest }),
    );
  });
});

test("detects source file and directory races via fs adapter", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    const userId = "race-user";
    await writeUserFile(sourceRoot, userId, "a.md", "a");
    const expected = buildCogsSkillBundle({
      entries: [{ path: "a.md", executable: false, content: Buffer.from("a") }],
    });
    let statCalls = 0;
    const store = await createCogsPrivateSkillStore({
      sourceRoot,
      storeRoot,
      fs: {
        open: async (target: string, flags: number | string, mode?: number) => {
          const handle = await open(target, flags, mode);
          return {
            stat: async () => {
              const stat = (await handle.stat({ bigint: true })) as never as { mtimeNs: bigint };
              statCalls += 1;
              if (statCalls > 1) stat.mtimeNs += 1n;
              return stat as never;
            },
            read: (buffer: Buffer, offset: number, length: number, position: number) =>
              handle.read(buffer, offset, length, position),
            writeFile: (bytes: Buffer) => handle.writeFile(bytes),
            sync: () => handle.sync(),
            close: () => handle.close(),
          };
        },
      },
    });
    await assertInvalid(() => store.snapshot({ userId, expectedDigest: expected.digest }));
  });
});

test("validates hostile config, roots, input shapes and aborts generically", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    await assertInvalid(() => createCogsPrivateSkillStore({ sourceRoot, storeRoot: sourceRoot }));
    await assertInvalid(() => createCogsPrivateSkillStore({ sourceRoot, storeRoot: path.join(sourceRoot, "nested") }));
    let accessorCalls = 0;
    await assertInvalid(() =>
      createCogsPrivateSkillStore(
        Object.defineProperty({ sourceRoot }, "storeRoot", {
          enumerable: true,
          get: () => {
            accessorCalls += 1;
            return storeRoot;
          },
        }) as never,
      ),
    );
    assert.equal(accessorCalls, 0);

    const store = await createCogsPrivateSkillStore({ sourceRoot, storeRoot });
    await assertInvalid(() =>
      store.snapshot({ userId: "bad/user", expectedDigest: buildCogsSkillBundle({ entries: [] }).digest }),
    );
    await assertInvalid(() => store.resolve({ userId: "user", digest: `sha256:${"0".repeat(63)}g` }));
    const controller = new AbortController();
    controller.abort();
    await assertInvalid(() =>
      store.snapshot({
        userId: "user",
        expectedDigest: buildCogsSkillBundle({ entries: [] }).digest,
        signal: controller.signal,
      }),
    );
    assert.deepEqual(await readdir(storeRoot), []);
  });
});

test("preexisting mismatched or linked blobs fail while concurrent same digest resolves", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    const userId = "store-user";
    await writeUserFile(sourceRoot, userId, "a.md", "a");
    const expected = buildCogsSkillBundle({
      entries: [{ path: "a.md", executable: false, content: Buffer.from("a") }],
    });
    const namespace = userNamespace(userId);
    const blobDir = path.join(storeRoot, namespace, "blobs", "sha256");
    await mkdir(blobDir, { recursive: true });
    const blob = path.join(blobDir, expected.digest.slice("sha256:".length));
    await writeFile(blob, "wrong");
    const store = await createCogsPrivateSkillStore({ sourceRoot, storeRoot });
    await assertInvalid(() => store.snapshot({ userId, expectedDigest: expected.digest }));
    await rm(path.join(storeRoot, namespace), { recursive: true, force: true });

    await Promise.all([
      store.snapshot({ userId, expectedDigest: expected.digest }),
      store.snapshot({ userId, expectedDigest: expected.digest }),
    ]);
    assert.equal((await lstat(path.join(blobDir, expected.digest.slice("sha256:".length)))).nlink, 1);

    const linked = path.join(blobDir, "linked");
    const stored = path.join(blobDir, expected.digest.slice("sha256:".length));
    await link(stored, linked);
    await assertInvalid(() => store.resolve({ userId, digest: expected.digest }));
    await rm(linked, { force: true });
    await chmod(stored, 0o644);
    await assertInvalid(() => store.resolve({ userId, digest: expected.digest }));
  });
});

test("write and cleanup faults attempt temp cleanup", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    const userId = "fault-user";
    await writeUserFile(sourceRoot, userId, "a.md", "a");
    const expected = buildCogsSkillBundle({
      entries: [{ path: "a.md", executable: false, content: Buffer.from("a") }],
    });
    let tempPath = "";
    const store = await createCogsPrivateSkillStore({
      sourceRoot,
      storeRoot,
      fs: {
        open: async (target: string, flags: number | string, mode?: number) => {
          const handle = await open(target, flags, mode);
          const isTemp = path.basename(target).startsWith(".tmp-");
          if (isTemp) tempPath = target;
          return {
            stat: () => handle.stat({ bigint: true }) as never,
            read: (buffer: Buffer, offset: number, length: number, position: number) =>
              handle.read(buffer, offset, length, position),
            writeFile: async (bytes: Buffer) => {
              if (isTemp) throw new Error("write fault");
              await handle.writeFile(bytes);
            },
            sync: () => handle.sync(),
            close: () => handle.close(),
          };
        },
      },
    });
    await assertInvalid(() => store.snapshot({ userId, expectedDigest: expected.digest }));
    assert.notEqual(tempPath, "");
    await assert.rejects(lstat(tempPath), { code: "ENOENT" });

    let firstTempUnlink = true;
    const cleanupFaultStore = await createCogsPrivateSkillStore({
      sourceRoot,
      storeRoot,
      fs: {
        unlink: async (target: string) => {
          if (path.basename(target).startsWith(".tmp-") && firstTempUnlink) {
            firstTempUnlink = false;
            throw Object.assign(new Error("unlink fault"), { code: "EIO" });
          }
          await rm(target, { force: true });
        },
      },
    });
    await assertInvalid(() => cleanupFaultStore.snapshot({ userId, expectedDigest: expected.digest }));
    const blob = path.join(
      storeRoot,
      userNamespace(userId),
      "blobs",
      "sha256",
      expected.digest.slice("sha256:".length),
    );
    assert.equal((await lstat(blob)).isFile(), true);
  });
});

test("EEXIST publish waits for transient nlink2 before verifying bytes", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    const userId = "nlink-user";
    await writeUserFile(sourceRoot, userId, "a.md", "a");
    const expected = buildCogsSkillBundle({
      entries: [{ path: "a.md", executable: false, content: Buffer.from("a") }],
    });
    const store = await createCogsPrivateSkillStore({ sourceRoot, storeRoot });
    await store.snapshot({ userId, expectedDigest: expected.digest });
    let finalLstatCalls = 0;
    const finalName = expected.digest.slice("sha256:".length);
    const waitingStore = await createCogsPrivateSkillStore({
      sourceRoot,
      storeRoot,
      fs: {
        lstat: async (target: string) => {
          const stat = await lstat(target, { bigint: true });
          if (path.basename(target) === finalName) {
            finalLstatCalls += 1;
            if (finalLstatCalls === 1) {
              Object.defineProperty(stat, "nlink", { value: 2n });
              return stat as never;
            }
          }
          return stat as never;
        },
      },
    });
    await waitingStore.snapshot({ userId, expectedDigest: expected.digest });
    assert.ok(finalLstatCalls >= 2);
  });
});

test("executable metadata derives from any execute bit", async () => {
  await withTemp(async (root) => {
    const { sourceRoot, storeRoot } = await createRoots(root);
    const file = await writeUserFile(sourceRoot, "exec-user", "run.sh", "#!/bin/sh\n");
    await chmod(file, 0o755);
    const expected = buildCogsSkillBundle({
      entries: [{ path: "run.sh", executable: true, content: Buffer.from("#!/bin/sh\n") }],
    });
    const store = await createCogsPrivateSkillStore({ sourceRoot, storeRoot });
    const result = await store.snapshot({ userId: "exec-user", expectedDigest: expected.digest });
    assert.equal(result.bundle.files[0]?.executable, true);
  });
});

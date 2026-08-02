import assert from "node:assert/strict";
import { chmod, link, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  type TrustedFileCaptureOptions,
  TrustedFileError,
  withTrustedFileBytes,
} from "../src/runtime/trusted-files.ts";

const uid = process.getuid?.() ?? -1;
const gid = process.getgid?.() ?? -1;

async function fixture(content = "trusted-material") {
  const created = await mkdtemp(join(tmpdir(), "cogs-trusted-file-"));
  const root = await realpath(created);
  const directory = join(root, "input");
  const path = join(directory, "material");
  await mkdir(directory, { mode: 0o700 });
  await writeFile(path, content, { mode: 0o600 });
  await chmod(path, 0o600);
  const options = (): TrustedFileCaptureOptions => ({
    path,
    minimumBytes: 1,
    maximumBytes: 1024,
    allowedModes: [0o600],
    allowedUids: [uid],
    allowedGids: [gid],
  });
  return { root, directory, path, options, close: () => rm(root, { recursive: true, force: true }) };
}

async function rejects(operation: Promise<unknown>, forbidden: readonly string[] = []): Promise<void> {
  await assert.rejects(operation, (error) => {
    assert.ok(error instanceof TrustedFileError);
    assert.equal(error.message, "trusted file unavailable");
    const text = String(error.stack ?? error);
    for (const value of forbidden) assert.equal(text.includes(value), false);
    return true;
  });
}

test("trusted capture holds a regular no-follow generation and clears callback-scoped bytes", async () => {
  const item = await fixture();
  let retained: Buffer | undefined;
  try {
    const result = await withTrustedFileBytes(item.options(), async (bytes, identity) => {
      retained = bytes;
      assert.equal(bytes.toString("utf8"), "trusted-material");
      assert.equal(identity.uid, uid);
      assert.equal(identity.gid, gid);
      assert.equal(identity.mode, 0o600);
      assert.equal(identity.size, Buffer.byteLength("trusted-material"));
      assert.equal(typeof identity.device, "bigint");
      assert.equal(typeof identity.inode, "bigint");
      assert.equal(Object.isFrozen(identity), true);
      return "accepted";
    });
    assert.equal(result, "accepted");
    assert.ok(retained);
    assert.equal(
      retained.every((byte) => byte === 0),
      true,
    );
  } finally {
    await item.close();
  }
});

test("trusted capture rejects final and parent symlinks without exposing paths", async () => {
  const item = await fixture();
  try {
    const alias = join(item.directory, "alias");
    await symlink(item.path, alias);
    await rejects(
      withTrustedFileBytes({ ...item.options(), path: alias }, async () => undefined),
      [alias, item.path],
    );

    const parentAlias = join(item.root, "parent-alias");
    await symlink(item.directory, parentAlias);
    const nested = join(parentAlias, "material");
    await rejects(
      withTrustedFileBytes({ ...item.options(), path: nested }, async () => undefined),
      [nested],
    );
  } finally {
    await item.close();
  }
});

test("trusted capture rejects hard links, modes, owners, sizes, and noncanonical paths before callbacks", async () => {
  const mutations: Array<(item: Awaited<ReturnType<typeof fixture>>) => Promise<TrustedFileCaptureOptions>> = [
    async (item) => {
      await link(item.path, join(item.directory, "second-name"));
      return item.options();
    },
    async (item) => {
      await chmod(item.path, 0o640);
      return item.options();
    },
    async (item) => ({ ...item.options(), allowedModes: [0o400] }),
    async (item) => ({ ...item.options(), allowedUids: [uid + 1] }),
    async (item) => ({ ...item.options(), allowedGids: [gid + 1] }),
    async (item) => ({ ...item.options(), minimumBytes: 100 }),
    async (item) => ({ ...item.options(), maximumBytes: 2 }),
    async (item) => ({ ...item.options(), path: `${item.directory}/../input/material` }),
  ];
  for (const mutate of mutations) {
    const item = await fixture();
    let called = false;
    try {
      const options = await mutate(item);
      await rejects(
        withTrustedFileBytes(options, async () => {
          called = true;
        }),
        [item.path],
      );
      assert.equal(called, false);
    } finally {
      await item.close();
    }
  }
});

test("trusted capture rejects hostile option descriptors without invoking getters", async () => {
  const item = await fixture();
  let getterCalls = 0;
  try {
    const options = item.options() as Record<string, unknown>;
    Object.defineProperty(options, "path", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return item.path;
      },
    });
    await rejects(
      withTrustedFileBytes(options as TrustedFileCaptureOptions, async () => undefined),
      [item.path],
    );
    assert.equal(getterCalls, 0);

    let trapCalls = 0;
    const proxy = new Proxy(item.options(), {
      getPrototypeOf() {
        trapCalls += 1;
        return Object.prototype;
      },
      ownKeys() {
        trapCalls += 1;
        return [];
      },
    });
    await rejects(
      withTrustedFileBytes(proxy, async () => undefined),
      [item.path],
    );
    assert.equal(trapCalls, 0);

    const sparse = item.options();
    (sparse as unknown as { allowedModes: number[] }).allowedModes = new Array(2);
    await rejects(
      withTrustedFileBytes(sparse, async () => undefined),
      [item.path],
    );
  } finally {
    await item.close();
  }
});

test("trusted capture redacts callback failures and clears bytes on rejection", async () => {
  const item = await fixture("sensitive-jwt-material");
  let retained: Buffer | undefined;
  try {
    await rejects(
      withTrustedFileBytes(item.options(), async (bytes) => {
        retained = bytes;
        throw new Error(`${bytes.toString("utf8")} ${item.path}`);
      }),
      ["sensitive-jwt-material", item.path],
    );
    assert.ok(retained);
    assert.equal(
      retained.every((byte) => byte === 0),
      true,
    );
  } finally {
    await item.close();
  }
});

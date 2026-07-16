import assert from "node:assert/strict";
import { constants } from "node:fs";
import { test } from "node:test";
import type { CogsEgressPkiMaterial } from "../src/egress/egress-material.ts";
import type { CogsEnvoyRuntimeConfig } from "../src/egress/envoy-runtime-config.ts";
import {
  CogsEgressTmpfsError,
  type CogsEgressTmpfsStats,
  type CogsEgressTmpfsStoragePort,
  withCogsEgressTmpfsMaterial,
} from "../src/egress/tmpfs-material-writer.ts";

const parent = "/run/cogs/egress";
const child = `${parent}/envoy`;
const paths = Object.freeze({
  bootstrap: `${child}/bootstrap.json`,
  proxyCertificate: `${child}/proxy-cert.pem`,
  proxyPrivateKey: `${child}/proxy-key.pem`,
  proxyCaCertificate: `${child}/proxy-ca.pem`,
});
const config: CogsEnvoyRuntimeConfig = Object.freeze({
  paths,
  bootstrapJson: '{"static_resources":{}}\n',
  routeCount: 1,
});
const pki: CogsEgressPkiMaterial = Object.freeze({
  certificateChainPem: "CERT-CHAIN\n",
  privateKeyPem: "PRIVATE-KEY\n",
  caCertificatePem: "CA-CERT\n",
  expiresAtMs: Date.now() + 60_000,
});

test("writes fixed material paths with strict modes, syncs, freezes callback paths, and cleans in reverse", async () => {
  const storage = new FakeStorage();
  let callbackPaths: unknown;
  await withCogsEgressTmpfsMaterial(
    config,
    pki,
    async (materialPaths) => {
      callbackPaths = materialPaths;
      assert.equal(Object.isFrozen(materialPaths), true);
      assert.deepEqual(materialPaths, paths);
      assert.equal(storage.text(paths.bootstrap), config.bootstrapJson);
      assert.equal(storage.text(paths.proxyCertificate), pki.certificateChainPem);
      assert.equal(storage.text(paths.proxyPrivateKey), pki.privateKeyPem);
      assert.equal(storage.text(paths.proxyCaCertificate), pki.caCertificatePem);
      return "ok";
    },
    { storage, euid: 501 },
  );
  assert.ok(callbackPaths);
  assert.equal(storage.entries.has(child), false);
  assert.deepEqual(
    storage.openFileCalls.map((call) => [call.path, call.flags, call.mode]),
    [
      [paths.bootstrap, strictFileFlags, 0o600],
      [paths.proxyCertificate, strictFileFlags, 0o600],
      [paths.proxyPrivateKey, strictFileFlags, 0o600],
      [paths.proxyCaCertificate, strictFileFlags, 0o600],
    ],
  );
  assert.deepEqual(storage.unlinks, [
    paths.proxyCaCertificate,
    paths.proxyPrivateKey,
    paths.proxyCertificate,
    paths.bootstrap,
  ]);
  assert.deepEqual(storage.rmdirs, [child]);
  assert.ok(storage.openDirCalls.some((call) => call.path === child && call.flags === strictDirFlags));
  assert.ok(storage.openDirCalls.some((call) => call.path === parent && call.flags === strictDirFlags));
});

test("rejects non-tmpfs, parent owner/mode/realpath, preexisting child, symlink, and hardlink cases", async () => {
  for (const mutate of [
    (s: FakeStorage) => {
      s.fsType = 0;
    },
    (s: FakeStorage) => {
      s.real = "/private/run/cogs/egress";
    },
    (s: FakeStorage) => {
      s.must(parent).uid = 502;
    },
    (s: FakeStorage) => {
      s.must(parent).mode = 0o755;
    },
    (s: FakeStorage) => {
      s.must(parent).isSymbolicLink = true;
    },
    (s: FakeStorage) => {
      s.addDir(child);
    },
    (s: FakeStorage) => {
      s.afterMkdir = () => {
        s.must(child).isSymbolicLink = true;
      };
    },
    (s: FakeStorage) => {
      s.afterOpen = (path) => {
        if (path === paths.bootstrap) s.must(path).nlink = 2;
      };
    },
  ]) {
    const storage = new FakeStorage();
    mutate(storage);
    await assert.rejects(
      withCogsEgressTmpfsMaterial(config, pki, async () => {}, { storage, euid: 501 }),
      generic,
    );
  }
});

test("rejects zero, oversized, multibyte-oversized, open, and malformed partial writes generically", async () => {
  const zero = new FakeStorage();
  zero.writePlan = [0];
  await assert.rejects(
    withCogsEgressTmpfsMaterial(config, pki, async () => {}, { storage: zero, euid: 501 }),
    generic,
  );

  const oversizedConfig = { ...config, bootstrapJson: "x".repeat(1024 * 1024 + 1) };
  await assert.rejects(
    withCogsEgressTmpfsMaterial(oversizedConfig, pki, async () => {}, { storage: new FakeStorage(), euid: 501 }),
    generic,
  );

  let called = false;
  const multibyte = new FakeStorage();
  await assert.rejects(
    withCogsEgressTmpfsMaterial(
      config,
      { ...pki, privateKeyPem: "é".repeat(70_000) },
      async () => {
        called = true;
      },
      { storage: multibyte, euid: 501 },
    ),
    generic,
  );
  assert.equal(called, false);
  assert.deepEqual(multibyte.rmdirs, [child]);

  const open = new FakeStorage();
  open.fail = "open";
  await assert.rejects(
    withCogsEgressTmpfsMaterial(
      config,
      pki,
      async () => {
        called = true;
      },
      { storage: open, euid: 501 },
    ),
    generic,
  );
  assert.deepEqual(open.rmdirs, [child]);

  const partial = new FakeStorage();
  partial.writePlan = [2, 1, 99];
  await assert.rejects(
    withCogsEgressTmpfsMaterial(config, pki, async () => {}, { storage: partial, euid: 501 }),
    generic,
  );
});

test("operation failure still cleans material and redacts content", async () => {
  const storage = new FakeStorage();
  await assert.rejects(
    withCogsEgressTmpfsMaterial(
      config,
      pki,
      async () => {
        throw new Error(`${pki.privateKeyPem} ${paths.proxyPrivateKey}`);
      },
      { storage, euid: 501 },
    ),
    generic,
  );
  assert.equal(storage.entries.has(child), false);
  assert.equal(storage.entries.has(paths.proxyPrivateKey), false);
});

test("cleanup identity mismatch refuses deletion of unknown objects and fails generically", async () => {
  const storage = new FakeStorage();
  await assert.rejects(
    withCogsEgressTmpfsMaterial(
      config,
      pki,
      async () => {
        storage.must(paths.proxyPrivateKey).ino = 9999n;
      },
      { storage, euid: 501 },
    ),
    generic,
  );
  assert.equal(storage.entries.has(paths.proxyPrivateKey), true);
  assert.equal(storage.unlinks.includes(paths.proxyPrivateKey), false);
});

test("sync, close, unlink, and rmdir failures are generic", async () => {
  for (const fault of ["sync", "close", "unlink", "rmdir"] as const) {
    const storage = new FakeStorage();
    storage.fail = fault;
    let operated = false;
    await assert.rejects(
      withCogsEgressTmpfsMaterial(
        config,
        pki,
        async () => {
          operated = true;
        },
        { storage, euid: 501 },
      ),
      generic,
    );
    if (fault === "unlink" || fault === "rmdir") assert.equal(operated, true);
    if (fault === "sync") assert.deepEqual(storage.unlinks, [paths.bootstrap]);
  }
});

test("duplicate cleanup attempts do not perform extra unlink or rmdir I/O", async () => {
  const storage = new FakeStorage();
  await withCogsEgressTmpfsMaterial(config, pki, async () => {}, { storage, euid: 501 });
  const unlinkCount = storage.unlinks.length;
  const rmdirCount = storage.rmdirs.length;
  await storage.cleanupAgain?.();
  assert.equal(storage.unlinks.length, unlinkCount);
  assert.equal(storage.rmdirs.length, rmdirCount);
});

const strictFileFlags = constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_WRONLY;
const strictDirFlags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;

type Entry = {
  dev: bigint;
  ino: bigint;
  uid: number;
  mode: number;
  nlink: number;
  size: number;
  isDirectory: boolean;
  isFile: boolean;
  isSymbolicLink: boolean;
  content: Uint8Array;
  removed?: boolean;
};

class FakeStorage implements CogsEgressTmpfsStoragePort {
  public entries = new Map<string, Entry>();
  public real = parent;
  public fsType = 0x01021994;
  public openFileCalls: { path: string; flags: number; mode: number }[] = [];
  public openDirCalls: { path: string; flags: number }[] = [];
  public unlinks: string[] = [];
  public rmdirs: string[] = [];
  public writePlan: number[] = [];
  public fail?: "open" | "sync" | "close" | "unlink" | "rmdir";
  public afterMkdir?: () => void;
  public afterOpen?: (path: string) => void;
  public cleanupAgain?: () => Promise<void>;
  #next = 10n;

  public constructor() {
    this.addDir(parent);
  }

  public addDir(path: string): void {
    this.entries.set(path, this.entry({ path, isDirectory: true, mode: 0o700 }));
  }

  public text(path: string): string {
    return new TextDecoder().decode(this.must(path).content);
  }

  public must(path: string): Entry {
    const entry = this.entries.get(path);
    if (entry === undefined) throw new Error(`missing ${path}`);
    return entry;
  }

  public async realpath(_path: string): Promise<string> {
    return this.real;
  }

  public async lstat(path: string): Promise<CogsEgressTmpfsStats> {
    const entry = this.entries.get(path);
    if (entry === undefined || entry.removed === true) throw notFound();
    return { ...entry };
  }

  public async statfs(_path: string): Promise<{ type: number | bigint }> {
    return { type: this.fsType };
  }

  public async mkdir(path: string, mode: number): Promise<void> {
    assert.equal(mode, 0o700);
    if (this.entries.has(path)) throw new Error("exists");
    this.addDir(path);
    this.afterMkdir?.();
  }

  public async openFile(path: string, flags: number, mode: number): Promise<FakeFile> {
    this.openFileCalls.push({ path, flags, mode });
    if (this.fail === "open") throw new Error("open leaked");
    assert.equal(flags, strictFileFlags);
    assert.equal(mode, 0o600);
    if (this.entries.has(path)) throw new Error("exists");
    const entry = this.entry({ path, isFile: true, mode, content: new Uint8Array() });
    this.entries.set(path, entry);
    this.afterOpen?.(path);
    return new FakeFile(this, path, entry);
  }

  public async openDir(path: string, flags: number): Promise<FakeFile> {
    this.openDirCalls.push({ path, flags });
    assert.equal(flags, strictDirFlags);
    const entry = this.must(path);
    if (!entry.isDirectory) throw new Error("not dir");
    return new FakeFile(this, path, entry);
  }

  public async unlink(path: string): Promise<void> {
    if (this.fail === "unlink") throw new Error("unlink leaked");
    this.unlinks.push(path);
    const entry = this.must(path);
    if (!entry.isFile) throw new Error("not file");
    this.entries.delete(path);
  }

  public async rmdir(path: string): Promise<void> {
    if (this.fail === "rmdir") throw new Error("rmdir leaked");
    this.rmdirs.push(path);
    this.entries.delete(path);
    this.cleanupAgain = async () => undefined;
  }

  private entry(input: Partial<Entry> & { path: string }): Entry {
    return {
      dev: 1n,
      ino: this.#next++,
      uid: 501,
      mode: input.mode ?? 0o600,
      nlink: 1,
      size: input.content?.byteLength ?? 0,
      isDirectory: false,
      isFile: false,
      isSymbolicLink: false,
      content: input.content ?? new Uint8Array(),
      ...input,
    };
  }
}

class FakeFile {
  public constructor(
    private readonly storage: FakeStorage,
    private readonly path: string,
    private readonly entry: Entry,
  ) {}
  public async write(data: Uint8Array): Promise<number> {
    const planned = this.storage.writePlan.shift();
    const count = planned ?? data.byteLength;
    if (count < 1 || count > data.byteLength) return count;
    const next = new Uint8Array(this.entry.content.byteLength + count);
    next.set(this.entry.content);
    next.set(data.subarray(0, count), this.entry.content.byteLength);
    this.entry.content = next;
    this.entry.size = next.byteLength;
    return count;
  }
  public async sync(): Promise<void> {
    if (this.storage.fail === "sync") throw new Error("sync leaked");
  }
  public async stat(): Promise<CogsEgressTmpfsStats> {
    return { ...this.entry };
  }
  public async close(): Promise<void> {
    if (this.storage.fail === "close") throw new Error(`close leaked ${this.path}`);
  }
}

function notFound(): Error & { code: "ENOENT" } {
  const error = new Error("missing") as Error & { code: "ENOENT" };
  error.code = "ENOENT";
  return error;
}

function generic(error: unknown): boolean {
  assert.ok(error instanceof CogsEgressTmpfsError);
  assert.equal(error.code, "COGS_EGRESS_TMPFS_FAILED");
  assert.equal(error.message, "egress tmpfs material unavailable");
  assert.doesNotMatch(
    String(error.stack),
    /PRIVATE-KEY|proxy-key|bootstrap|sync leaked|close leaked|unlink leaked|rmdir leaked/,
  );
  return true;
}

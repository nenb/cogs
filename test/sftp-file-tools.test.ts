import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import ssh2, { type Stats } from "ssh2";
import {
  type CogsSftpPort,
  CogsSftpStatusError,
  SshConnectionManager,
  type SshSftpChannel,
  type SshTransportConnection,
} from "../src/ssh/connection.ts";
import { createSftpFileToolPorts } from "../src/ssh/file-tools.ts";

class FakeStats implements Stats {
  public uid = 0;
  public gid = 0;
  public atime = 0;
  public mtime = 0;
  public constructor(
    public mode: number,
    public size: number,
    private readonly kind: "file" | "dir" | "symlink" | "fifo" = "file",
  ) {}
  public isDirectory() {
    return this.kind === "dir";
  }
  public isFile() {
    return this.kind === "file";
  }
  public isBlockDevice() {
    return false;
  }
  public isCharacterDevice() {
    return false;
  }
  public isSymbolicLink() {
    return this.kind === "symlink";
  }
  public isFIFO() {
    return this.kind === "fifo";
  }
  public isSocket() {
    return false;
  }
}

type Node = { kind: "file"; data: Buffer } | { kind: "dir" } | { kind: "symlink" } | { kind: "fifo" };

class FakeSftp extends EventEmitter {
  public files = new Map<string, Node>([
    ["/workspace", { kind: "dir" }],
    ["/shared", { kind: "dir" }],
    ["/shared/skills", { kind: "dir" }],
    ["/user", { kind: "dir" }],
    ["/user/skills", { kind: "dir" }],
  ]);
  public handles = new Map<string, string>();
  public renameFails = false;
  public fsyncFails = false;
  public fsyncUnavailable = false;
  public closeFails = false;
  public unlinkFails = false;
  public hangCloseHandle = false;
  public fstatTypeOverride: "file" | "fifo" | undefined;
  public permissionPaths = new Set<string>();
  public failurePaths = new Set<string>();
  public rejectUndefinedRead = false;
  public rejectProxyRead = false;
  public rejectUndefinedCloseHandle = false;
  public shortRead = false;
  public growRead = false;
  public hangRead = false;
  public openCount = 0;
  public active = 0;
  public maxActive = 0;
  public unlinked: string[] = [];
  public seed(file: string, data: string | Buffer, kind: Node["kind"] = "file") {
    this.files.set(file, kind === "file" ? { kind, data: Buffer.from(data) } : ({ kind } as Node));
  }
  public lstat(p: string, cb: (err: Error | undefined, stats: Stats) => void) {
    setImmediate(() => {
      const n = this.files.get(p);
      n ? cb(undefined, stats(n)) : cb(new Error("missing"), undefined as never);
    });
  }
  public realpath(p: string, cb: (err: Error | undefined, resolved: string) => void) {
    setImmediate(() => (this.files.has(p) ? cb(undefined, p) : cb(new Error("missing"), "")));
  }
  public open(p: string, mode: string, _attrs: unknown, cb?: (err: Error | undefined, handle: Buffer) => void) {
    const callback = (typeof _attrs === "function" ? _attrs : cb) as (err: Error | undefined, handle: Buffer) => void;
    setImmediate(() => {
      if (mode.includes("x") && this.files.has(p)) return callback(new Error("exists"), undefined as never);
      if (mode.startsWith("r") && this.files.get(p)?.kind !== "file")
        return callback(new Error("not file"), undefined as never);
      if (mode.startsWith("w")) this.files.set(p, { kind: "file", data: Buffer.alloc(0) });
      const handle = Buffer.from(`h${++this.openCount}`);
      this.handles.set(handle.toString("hex"), p);
      callback(undefined, handle);
    });
  }
  public fstat(handle: Buffer, cb: (err: Error | undefined, stats: Stats) => void) {
    setImmediate(() => {
      const n = this.node(handle);
      n ? cb(undefined, stats(n)) : cb(new Error("bad handle"), undefined as never);
    });
  }
  public read(
    handle: Buffer,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    cb: (err: Error | undefined, bytesRead: number, buffer: Buffer, position: number) => void,
  ) {
    if (this.hangRead) return;
    setImmediate(() => {
      const n = this.node(handle);
      if (n?.kind !== "file") return cb(new Error("bad handle"), 0, buffer, position);
      const bytes = n.data.copy(buffer, offset, position, position + length);
      cb(undefined, bytes, buffer, position);
    });
  }
  public write(
    handle: Buffer,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    cb: (err?: Error) => void,
  ) {
    setImmediate(() => {
      const n = this.node(handle);
      if (n?.kind !== "file") return cb(new Error("bad handle"));
      const next = Buffer.alloc(Math.max(n.data.length, position + length));
      n.data.copy(next);
      buffer.copy(next, position, offset, offset + length);
      n.data = next;
      cb();
    });
  }
  public close(handle: Buffer, cb: (err?: Error) => void) {
    setImmediate(() => {
      this.handles.delete(handle.toString("hex"));
      cb();
    });
  }
  public unlink(p: string, cb: (err?: Error) => void) {
    setImmediate(() => {
      this.unlinked.push(p);
      this.files.delete(p);
      cb();
    });
  }
  public ext_openssh_fsync(_handle: Buffer, cb: (err?: Error) => void) {
    setImmediate(() => cb(this.fsyncFails ? new Error("fsync") : undefined));
  }
  public ext_openssh_rename(src: string, dst: string, cb: (err?: Error) => void) {
    setImmediate(() => {
      if (this.renameFails) return cb(new Error("rename"));
      const n = this.files.get(src);
      if (!n) return cb(new Error("missing"));
      this.files.set(dst, n);
      this.files.delete(src);
      cb();
    });
  }
  public end() {
    this.emit("close");
  }
  private node(handle: Buffer): Node | undefined {
    const p = this.handles.get(handle.toString("hex"));
    return p ? this.files.get(p) : undefined;
  }
}

function stats(node: Node): Stats {
  return node.kind === "file"
    ? new FakeStats(0o100600, node.data.length, "file")
    : new FakeStats(0o040700, 0, node.kind === "dir" ? "dir" : node.kind === "symlink" ? "symlink" : "fifo");
}

function portFor(sftp: FakeSftp): CogsSftpPort {
  const typeOf = (node: Node | undefined) =>
    node?.kind === "file"
      ? "file"
      : node?.kind === "dir"
        ? "directory"
        : node?.kind === "symlink"
          ? "symlink"
          : node?.kind === "fifo"
            ? "fifo"
            : "unknown";
  const statOf = (node: Node | undefined) => {
    if (!node) throw new CogsSftpStatusError("no_such_file");
    return { size: node.kind === "file" ? node.data.length : 0, type: typeOf(node) } as const;
  };
  const handlePath = (handle: Buffer) => sftp.handles.get(handle.toString("hex"));
  return {
    lstat: async (p) => {
      if (sftp.permissionPaths.has(p)) throw new CogsSftpStatusError("permission_denied");
      if (sftp.failurePaths.has(p)) throw new CogsSftpStatusError("failure");
      return statOf(sftp.files.get(p));
    },
    realpath: async (p) => {
      if (!sftp.files.has(p)) throw new CogsSftpStatusError("no_such_file");
      return p;
    },
    open: async (p, mode) => {
      if (mode === "wx" && sftp.files.has(p)) throw new Error("exists");
      if (mode === "r" && sftp.files.get(p)?.kind !== "file") throw new Error("not file");
      if (mode === "wx") sftp.files.set(p, { kind: "file", data: Buffer.alloc(0) });
      const handle = Buffer.from(`h${++sftp.openCount}`);
      sftp.handles.set(handle.toString("hex"), p);
      return handle;
    },
    read: async (handle, buffer, offset, length, position) => {
      if (sftp.hangRead) await new Promise(() => undefined);
      if (sftp.rejectUndefinedRead) return Promise.reject(undefined);
      if (sftp.rejectProxyRead)
        return Promise.reject(
          new Proxy(
            {},
            {
              getPrototypeOf: () => {
                throw new Error("proxy prototype leak");
              },
            },
          ),
        );
      const node = sftp.files.get(handlePath(handle) ?? "");
      if (node?.kind !== "file") throw new Error("bad handle");
      if (sftp.growRead && position >= node.data.length) {
        buffer[offset] = 0x78;
        return { bytesRead: 1, buffer, position };
      }
      const bytesRead = node.data.copy(buffer, offset, position, position + length);
      return { bytesRead: sftp.shortRead && bytesRead > 0 ? 0 : bytesRead, buffer, position };
    },
    write: async (handle, buffer, offset, length, position) => {
      const node = sftp.files.get(handlePath(handle) ?? "");
      if (node?.kind !== "file") throw new Error("bad handle");
      const next = Buffer.alloc(Math.max(node.data.length, position + length));
      node.data.copy(next);
      buffer.copy(next, position, offset, offset + length);
      node.data = next;
    },
    fstat: async (handle) => {
      const stat = statOf(sftp.files.get(handlePath(handle) ?? ""));
      return sftp.fstatTypeOverride === undefined ? stat : { ...stat, type: sftp.fstatTypeOverride };
    },
    closeHandle: async (handle) => {
      if (sftp.hangCloseHandle) await new Promise(() => undefined);
      if (sftp.rejectUndefinedCloseHandle) return Promise.reject(undefined);
      sftp.handles.delete(handle.toString("hex"));
      if (sftp.closeFails) throw new Error("close failed");
    },
    unlink: async (p) => {
      sftp.unlinked.push(p);
      if (sftp.unlinkFails) throw new Error("unlink failed");
      sftp.files.delete(p);
    },
    fsync: async () => {
      if (sftp.fsyncUnavailable) throw new Error("fsync unavailable");
      if (sftp.fsyncFails) throw new Error("fsync");
    },
    posixRename: async (src, dst) => {
      if (sftp.renameFails) throw new Error("rename");
      const node = sftp.files.get(src);
      if (!node) throw new Error("missing");
      sftp.files.set(dst, node);
      sftp.files.delete(src);
    },
  };
}

class FakeConnection extends EventEmitter implements SshTransportConnection {
  public destroyCalls = 0;
  public lateOpen = false;
  public hangClose = false;
  public throwClose = false;
  public rejectUndefinedClose = false;
  public constructor(private readonly sftp: FakeSftp) {
    super();
  }
  public openSftp(_signal: AbortSignal): Promise<SshSftpChannel> {
    const makeChannel = () => {
      let open = true;
      this.sftp.active++;
      this.sftp.maxActive = Math.max(this.sftp.maxActive, this.sftp.active);
      return {
        port: portFor(this.sftp),
        close: async () => {
          if (!open) return;
          if (this.rejectUndefinedClose) return Promise.reject(undefined);
          if (this.throwClose) throw new Error("channel close failed");
          if (this.hangClose) await new Promise(() => undefined);
          if (open) this.sftp.active--;
          open = false;
        },
        destroy: () => {
          this.destroyCalls++;
          if (open) this.sftp.active--;
          open = false;
        },
      };
    };
    if (!this.lateOpen) return Promise.resolve(makeChannel());
    return new Promise((resolve) => setTimeout(() => resolve(makeChannel()), 40));
  }
  public openExec(): Promise<never> {
    return Promise.reject(new Error("exec not implemented in sftp tests"));
  }
  public close(): Promise<void> {
    return Promise.resolve();
  }
  public destroy(): void {
    this.destroyCalls++;
  }
}

class FakeTransport {
  public readonly connection: FakeConnection;
  public constructor(sftp: FakeSftp) {
    this.connection = new FakeConnection(sftp);
  }
  public connect(): Promise<SshTransportConnection> {
    return Promise.resolve(this.connection);
  }
}

const keyPair = generateParsedTestKeyPair();
const validPin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function generateParsedTestKeyPair(): ReturnType<typeof ssh2.utils.generateKeyPairSync> {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const generated = ssh2.utils.generateKeyPairSync("ed25519", { comment: "cogs-sftp-test" });
    const parsed = ssh2.utils.parseKey(generated.private);
    if (!(parsed instanceof Error) && !Array.isArray(parsed) && parsed.isPrivateKey()) return generated;
  }
  throw new Error("test ssh private key fixture unavailable");
}

async function managerFor(
  sftp: FakeSftp,
  maxPermits = 2,
  onLost?: (reason: string) => void,
): Promise<{ manager: SshConnectionManager; root: string; transport: FakeTransport }> {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-sftp-tools-"));
  const keyPath = resolve(root, "id_key");
  await writeFile(keyPath, keyPair.private, { mode: 0o600 });
  await chmod(keyPath, 0o600);
  const transport = new FakeTransport(sftp);
  const manager = new SshConnectionManager({
    config: {
      endpoint: "sandbox.local:2222",
      username: "cogs",
      hostKeySha256: validPin,
      clientKeyPath: keyPath,
      connectTimeoutMs: 25,
      handshakeTimeoutMs: 25,
      permitAcquireTimeoutMs: 25,
      sftpOpenTimeoutMs: 25,
      shutdownTimeoutMs: 25,
      maxPermits,
      maxQueue: 8,
    },
    transport,
    ...(onLost === undefined ? {} : { onLost }),
  });
  await manager.start();
  return { manager, root, transport };
}

test("SFTP read validates paths, UTF-8, line bounds, file metadata, and truncation", async () => {
  const sftp = new FakeSftp();
  sftp.seed("/workspace/a.txt", "one\ntwo\nthree\nfour");
  sftp.seed("/workspace/bin", Buffer.from([0xff]));
  sftp.seed("/workspace/empty.txt", "");
  sftp.seed("/workspace/trailing.txt", "one\ntwo\n");
  sftp.seed("/workspace/big.txt", "123456");
  sftp.seed("/workspace/link", "", "symlink");
  const fixture = await managerFor(sftp);
  try {
    const ports = createSftpFileToolPorts({ manager: fixture.manager, maxReadBytes: 100, maxResultBytes: 16 * 1024 });
    assert.deepEqual(await ports.read({ path: "a.txt", offset: 1, limit: 2 }), {
      ok: true,
      path: "/workspace/a.txt",
      content: "two\nthree",
      encoding: "utf8",
      offset: 1,
      limit: 2,
      linesReturned: 2,
      totalLines: 4,
      eof: false,
      truncated: true,
      bytesRead: 18,
      sizeBytes: 18,
    });
    assert.ok(
      Buffer.byteLength(JSON.stringify(await ports.read({ path: "a.txt", offset: 1, limit: 2 })), "utf8") <= 16 * 1024,
    );
    assert.deepEqual(
      (await ports.read({ path: "empty.txt" })) as { content: string; linesReturned: number; eof: boolean },
      {
        ok: true,
        path: "/workspace/empty.txt",
        content: "",
        encoding: "utf8",
        offset: 0,
        limit: 2000,
        linesReturned: 0,
        totalLines: 0,
        eof: true,
        truncated: false,
        bytesRead: 0,
        sizeBytes: 0,
      },
    );
    assert.equal(
      ((await ports.read({ path: "trailing.txt", offset: 1, limit: 1 })) as { content: string }).content,
      "two\n",
    );
    assert.equal(
      ((await ports.read({ path: "trailing.txt", offset: 9, limit: 1 })) as { eof: boolean; linesReturned: number })
        .eof,
      true,
    );
    const smallPorts = createSftpFileToolPorts({
      manager: fixture.manager,
      maxReadBytes: 5,
      maxResultBytes: 16 * 1024,
    });
    assert.deepEqual(await smallPorts.read({ path: "big.txt" }), {
      ok: false,
      path: "/workspace/big.txt",
      content: "",
      encoding: "unknown",
      binary: false,
      reason: "too_large",
      truncated: true,
      eof: false,
      bytesRead: 0,
      sizeBytes: 6,
    });
    await assert.rejects(ports.read({ path: "../etc/passwd" }), /invalid path|outside/);
    await assert.rejects(ports.read({ path: "/workspace/link" }), /symlink|unsupported/);
    assert.deepEqual(await ports.read({ path: "/workspace/bin" }), {
      ok: false,
      path: "/workspace/bin",
      content: "",
      encoding: "binary",
      binary: true,
      reason: "invalid_utf8",
      truncated: false,
      eof: false,
      bytesRead: 0,
      sizeBytes: 1,
    });
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("SFTP write and edit use fsync plus atomic rename and preserve target on failures", async () => {
  const sftp = new FakeSftp();
  sftp.seed("/workspace/a.txt", "hello old world");
  const fixture = await managerFor(sftp);
  try {
    const ports = createSftpFileToolPorts({ manager: fixture.manager, maxWriteBytes: 100, maxReadBytes: 100 });
    assert.equal(
      ((await ports.write({ path: "/workspace/out.txt", content: "new" })) as { bytesWritten: number }).bytesWritten,
      3,
    );
    assert.equal((sftp.files.get("/workspace/out.txt") as { data: Buffer }).data.toString(), "new");
    assert.equal(
      ((await ports.edit({ path: "/workspace/a.txt", oldText: "old", newText: "NEW" })) as { occurrences: number })
        .occurrences,
      1,
    );
    assert.equal((sftp.files.get("/workspace/a.txt") as { data: Buffer }).data.toString(), "hello NEW world");
    await assert.rejects(ports.edit({ path: "/workspace/a.txt", oldText: "missing", newText: "x" }), /not unique/);
    assert.equal((sftp.files.get("/workspace/a.txt") as { data: Buffer }).data.toString(), "hello NEW world");
    sftp.renameFails = true;
    await assert.rejects(ports.write({ path: "/workspace/out.txt", content: "bad" }), /rename|operation/);
    assert.equal((sftp.files.get("/workspace/out.txt") as { data: Buffer }).data.toString(), "new");
    assert.ok(sftp.unlinked.some((name) => name.includes("/.cogs-") && name.endsWith(".tmp")));
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("SFTP operations are bounded by manager channel permits and abort/timeouts fail closed without fallback", async () => {
  const sftp = new FakeSftp();
  sftp.seed("/workspace/a.txt", "hello");
  const fixture = await managerFor(sftp, 1);
  try {
    const ports = createSftpFileToolPorts({ manager: fixture.manager, operationTimeoutMs: 20, idleTimeoutMs: 20 });
    const first = ports.read({ path: "/workspace/a.txt" });
    const second = ports.read({ path: "/workspace/a.txt" });
    await Promise.all([first, second]);
    assert.equal(sftp.maxActive, 1);
    sftp.hangRead = true;
    await assert.rejects(ports.read({ path: "/workspace/a.txt" }), /timed out|aborted/);
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("SFTP adversarial cases cover overlap, growth, cleanup failure, Unicode bounds, and late channels", async () => {
  const sftp = new FakeSftp();
  sftp.seed("/workspace/overlap.txt", "aaa");
  sftp.seed("/workspace/grow.txt", "abc");
  sftp.seed("/workspace/huge.txt", `😀${"x".repeat(200)}\nnext`);
  const fixture = await managerFor(sftp, 1);
  try {
    const ports = createSftpFileToolPorts({
      manager: fixture.manager,
      maxReadBytes: 1024,
      maxWriteBytes: 1024,
      maxResultBytes: 300,
      operationTimeoutMs: 20,
      idleTimeoutMs: 20,
      openTimeoutMs: 10,
      closeTimeoutMs: 10,
    });
    await assert.rejects(ports.edit({ path: "/workspace/overlap.txt", oldText: "aa", newText: "b" }), /not unique/);
    assert.equal((sftp.files.get("/workspace/overlap.txt") as { data: Buffer }).data.toString(), "aaa");
    sftp.growRead = true;
    await assert.rejects(ports.read({ path: "/workspace/grow.txt" }), /grew/);
    sftp.growRead = false;
    sftp.shortRead = true;
    await assert.rejects(ports.read({ path: "/workspace/grow.txt" }), /short/);
    sftp.shortRead = false;
    const huge = (await ports.read({ path: "/workspace/huge.txt", limit: 1 })) as {
      content: string;
      truncated: boolean;
      linesReturned: number;
    };
    assert.equal(huge.truncated, true);
    assert.equal(huge.content.includes("�"), false);
    assert.equal(huge.linesReturned, 0);
    await assert.rejects(ports.write({ path: "/workspace/bad\u0000name", content: "x" }), /invalid path/);
    await assert.rejects(ports.write({ path: "/workspace/e\u0301.txt", content: "x" }), /invalid path/);
    await assert.rejects(ports.write({ path: "/workspace/cf\u200d.txt", content: "x" }), /invalid path/);
    await assert.rejects(ports.write({ path: "/workspace/surrogate.txt", content: "\uD800" }), /invalid content/);
    sftp.renameFails = true;
    sftp.closeFails = true;
    await assert.rejects(ports.write({ path: "/workspace/cleanup.txt", content: "x" }), /cleanup failed/);
    assert.ok(sftp.unlinked.length > 0, "unlink attempted even when close failed");
    fixture.transport.connection.lateOpen = true;
    await assert.rejects(ports.read({ path: "/workspace/grow.txt" }), /open timed out|operation aborted/);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.ok(fixture.transport.connection.destroyCalls > 0, "late channel was destroyed");
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("real manager withSftp hard timeout destroys noncooperative operation before releasing permit", async () => {
  const sftp = new FakeSftp();
  const fixture = await managerFor(sftp, 1);
  try {
    const startedAt = Date.now();
    await assert.rejects(
      fixture.manager.withSftp(
        { operationTimeoutMs: 20, closeTimeoutMs: 10 },
        async () => new Promise(() => undefined),
      ),
      /timed out/,
    );
    assert.ok(Date.now() - startedAt < 250);
    assert.equal(sftp.active, 0);
    assert.ok(fixture.transport.connection.destroyCalls > 0);
    await fixture.manager.withSftp({ operationTimeoutMs: 50, closeTimeoutMs: 10 }, async () => undefined);
    assert.equal(sftp.active, 0);
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("SFTP focused safety cases cover target status, file types, fsync, and cleanup deadlines", async () => {
  const sftp = new FakeSftp();
  sftp.seed("/workspace/existing.txt", "stable");
  sftp.seed("/workspace/dir-target", "", "dir");
  sftp.seed("/workspace/fifo-target", "", "fifo");
  const fixture = await managerFor(sftp);
  try {
    const ports = createSftpFileToolPorts({
      manager: fixture.manager,
      maxWriteBytes: 100,
      maxReadBytes: 100,
      closeTimeoutMs: 10,
      operationTimeoutMs: 50,
      idleTimeoutMs: 50,
    });
    await assert.rejects(
      ports.write({ path: "/workspace/dir-target", content: "x" }),
      /unsupported|invalid path component|operation/,
    );
    await assert.rejects(ports.write({ path: "/workspace/fifo-target", content: "x" }), /unsupported|operation/);

    assert.equal(
      ((await ports.write({ path: "/workspace/new-from-absent.txt", content: "ok" })) as { bytesWritten: number })
        .bytesWritten,
      2,
    );
    sftp.permissionPaths.add("/workspace/permission-target.txt");
    await assert.rejects(
      ports.write({ path: "/workspace/permission-target.txt", content: "x" }),
      /permission denied|operation/,
    );
    sftp.permissionPaths.clear();
    sftp.failurePaths.add("/workspace/failure-target.txt");
    await assert.rejects(ports.write({ path: "/workspace/failure-target.txt", content: "x" }), /operation/);
    sftp.failurePaths.clear();

    sftp.fsyncFails = true;
    await assert.rejects(ports.write({ path: "/workspace/existing.txt", content: "bad" }), /operation|cleanup/);
    assert.equal((sftp.files.get("/workspace/existing.txt") as { data: Buffer }).data.toString(), "stable");
    assert.ok(sftp.unlinked.some((name) => name.includes("/.cogs-")));
    sftp.fsyncFails = false;
    sftp.fsyncUnavailable = true;
    await assert.rejects(ports.write({ path: "/workspace/existing.txt", content: "bad" }), /operation|cleanup/);
    assert.equal((sftp.files.get("/workspace/existing.txt") as { data: Buffer }).data.toString(), "stable");
    sftp.fsyncUnavailable = false;
    sftp.renameFails = true;
    await assert.rejects(ports.write({ path: "/workspace/existing.txt", content: "bad" }), /operation|cleanup/);
    assert.equal((sftp.files.get("/workspace/existing.txt") as { data: Buffer }).data.toString(), "stable");
    sftp.renameFails = false;

    const abort = new AbortController();
    abort.abort();
    await assert.rejects(ports.read({ path: "/workspace/existing.txt", signal: abort.signal }), /aborted/);
    sftp.fstatTypeOverride = "fifo";
    await assert.rejects(ports.read({ path: "/workspace/existing.txt" }), /unsupported file type/);
    await assert.rejects(
      ports.edit({ path: "/workspace/existing.txt", oldText: "stable", newText: "x" }),
      /unsupported file type/,
    );
    sftp.fstatTypeOverride = undefined;
    sftp.rejectUndefinedRead = true;
    await assert.rejects(ports.read({ path: "/workspace/existing.txt" }), /sftp file operation failed/);
    sftp.rejectUndefinedRead = false;
    sftp.rejectProxyRead = true;
    await assert.rejects(ports.read({ path: "/workspace/existing.txt" }), /sftp file operation failed/);
    sftp.rejectProxyRead = false;
    sftp.rejectUndefinedCloseHandle = true;
    await assert.rejects(ports.read({ path: "/workspace/existing.txt" }), /cleanup failed/);
    sftp.rejectUndefinedCloseHandle = false;
    sftp.hangCloseHandle = true;
    await assert.rejects(ports.read({ path: "/workspace/existing.txt" }), /cleanup failed|timed out|aborted/);
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("successful SFTP operation rejects and revokes readiness when channel close fails", async () => {
  const sftp = new FakeSftp();
  sftp.seed("/workspace/a.txt", "hello");
  const lost: string[] = [];
  const fixture = await managerFor(sftp, 1, (reason) => lost.push(reason));
  try {
    const ports = createSftpFileToolPorts({ manager: fixture.manager, closeTimeoutMs: 10, operationTimeoutMs: 50 });
    fixture.transport.connection.hangClose = true;
    await assert.rejects(ports.read({ path: "/workspace/a.txt" }), /ssh sftp operation failed/);
    assert.equal(sftp.active, 0);
    assert.equal(fixture.manager.ready, false);
    assert.deepEqual(lost, ["sftp-close-failed"]);
    await assert.rejects(ports.read({ path: "/workspace/a.txt" }), /closed/);
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("SFTP operation error destroys channel so follow-up close is idempotent and does not spuriously poison", async () => {
  const sftp = new FakeSftp();
  sftp.seed("/workspace/a.txt", "hello");
  const lost: string[] = [];
  const fixture = await managerFor(sftp, 1, (reason) => lost.push(reason));
  try {
    fixture.transport.connection.throwClose = true;
    await assert.rejects(
      fixture.manager.withSftp({ closeTimeoutMs: 10, operationTimeoutMs: 50 }, async () => {
        throw new Error("operation sentinel");
      }),
      /operation sentinel/,
    );
    assert.equal(sftp.active, 0);
    assert.equal(fixture.manager.ready, true);
    assert.deepEqual(lost, []);
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("SFTP manager treats undefined operation and close rejections as failures", async () => {
  const sftp = new FakeSftp();
  const fixture = await managerFor(sftp, 1);
  try {
    await assert.rejects(
      fixture.manager.withSftp({ closeTimeoutMs: 10, operationTimeoutMs: 50 }, async () => Promise.reject(undefined)),
      /ssh sftp operation failed/,
    );
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }

  const sftpClose = new FakeSftp();
  const lost: string[] = [];
  const closeFixture = await managerFor(sftpClose, 1, (reason) => lost.push(reason));
  try {
    closeFixture.transport.connection.rejectUndefinedClose = true;
    await assert.rejects(
      closeFixture.manager.withSftp({ closeTimeoutMs: 10, operationTimeoutMs: 50 }, async () => "ok"),
      /ssh sftp operation failed/,
    );
    assert.equal(closeFixture.manager.ready, false);
    assert.deepEqual(lost, ["sftp-close-failed"]);
  } finally {
    await closeFixture.manager.shutdown();
    await rm(closeFixture.root, { recursive: true, force: true });
  }
});

test("SFTP manager redacts hostile proxy operation rejection without throwing or hanging", async () => {
  const sftp = new FakeSftp();
  const fixture = await managerFor(sftp, 1);
  try {
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw new Error("proxy prototype leak");
        },
      },
    );
    await assert.rejects(
      Promise.race([
        fixture.manager.withSftp({ closeTimeoutMs: 10, operationTimeoutMs: 50 }, async () => Promise.reject(hostile)),
        new Promise((_, reject) => setTimeout(() => reject(new Error("hung proxy rejection")), 100)),
      ]),
      /ssh sftp operation failed/,
    );
  } finally {
    await fixture.manager.shutdown();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

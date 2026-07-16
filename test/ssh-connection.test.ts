import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { chmod, link, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import ssh2 from "ssh2";
import { validateLaunchConfig } from "../src/launch/config.ts";
import { type LaunchDependency, LaunchLifecycle } from "../src/launch/lifecycle.ts";
import {
  CogsSftpStatusError,
  createSshLaunchDependency,
  decodeOpenSshSha256Pin,
  Ssh2Connection,
  Ssh2Transport,
  SshConnectionManager,
  type SshTransport,
  type SshTransportConnection,
  type SshTransportConnectOptions,
  safeEqualHex,
} from "../src/ssh/connection.ts";

type FakeOptions = {
  readonly authFailure?: boolean;
  readonly hangConnect?: boolean;
  readonly hangClose?: boolean;
  readonly emitCloseBeforeResolve?: boolean;
  readonly throwDestroy?: boolean;
  readonly throwClose?: boolean;
  readonly throwOff?: boolean;
  readonly delayedResolveMs?: number;
};

class FakeConnection extends EventEmitter implements SshTransportConnection {
  public closeCalls = 0;
  public destroyCalls = 0;
  public listenersCount(): number {
    return this.listenerCount("close") + this.listenerCount("error");
  }
  #lost = false;
  public constructor(private readonly options: FakeOptions = {}) {
    super();
    if (options.emitCloseBeforeResolve) {
      this.#lost = true;
      queueMicrotask(() => this.emit("close"));
    }
  }
  public override on(event: "close" | "error", listener: (...args: unknown[]) => void): this {
    super.on(event, listener);
    if (event === "close" && this.#lost) queueMicrotask(() => listener());
    return this;
  }
  public override off(event: "close" | "error", listener: (...args: unknown[]) => void): this {
    if (this.options.throwOff) throw new Error("off failed");
    return super.off(event, listener);
  }
  public openSftp(): Promise<never> {
    return Promise.reject(new Error("sftp not implemented in connection tests"));
  }
  public openExec(): Promise<never> {
    return Promise.reject(new Error("exec not implemented in connection tests"));
  }
  public close(): Promise<void> {
    this.closeCalls += 1;
    if (this.options.throwClose) throw new Error("close failed");
    return this.options.hangClose ? new Promise(() => undefined) : Promise.resolve();
  }
  public destroy(): void {
    this.destroyCalls += 1;
    if (this.options.throwDestroy) throw new Error("destroy failed");
  }
}

class FakeTransport implements SshTransport {
  public connections: FakeConnection[] = [];
  public options: SshTransportConnectOptions[] = [];
  public constructor(private readonly fakeOptions: FakeOptions = {}) {}
  public connect(options: SshTransportConnectOptions, _signal: AbortSignal): Promise<SshTransportConnection> {
    this.options.push(options);
    if (this.fakeOptions.hangConnect) return new Promise(() => undefined);
    if (this.fakeOptions.authFailure)
      return Promise.reject(new Error(`auth failed ${options.privateKey.toString("utf8")}`));
    const connection = new FakeConnection(this.fakeOptions);
    this.connections.push(connection);
    if (this.fakeOptions.delayedResolveMs !== undefined)
      return new Promise((resolveConnection) =>
        setTimeout(() => resolveConnection(connection), this.fakeOptions.delayedResolveMs),
      );
    return Promise.resolve(connection);
  }
}

const keyPair = generateParsedTestKeyPair();
const validPin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function generateParsedTestKeyPair(): ReturnType<typeof ssh2.utils.generateKeyPairSync> {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const generated = ssh2.utils.generateKeyPairSync("ed25519", { comment: "cogs-test" });
    if (isSinglePrivateParsedKey(ssh2.utils.parseKey(generated.private))) return generated;
  }
  throw new Error("test ssh private key fixture unavailable");
}

function isSinglePrivateParsedKey(parsed: ReturnType<typeof ssh2.utils.parseKey>): boolean {
  return !(parsed instanceof Error) && !Array.isArray(parsed) && parsed.isPrivateKey();
}

async function keyFile(root: string, content = keyPair.private, name = "id_key"): Promise<string> {
  const path = resolve(root, name);
  await writeFile(path, content, { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

function config(
  path: string,
  overrides: Partial<ConstructorParameters<typeof SshConnectionManager>[0]["config"]> = {},
) {
  return {
    endpoint: "sandbox.local:2222",
    username: "cogs",
    hostKeySha256: validPin,
    clientKeyPath: path,
    connectTimeoutMs: 25,
    handshakeTimeoutMs: 25,
    permitAcquireTimeoutMs: 25,
    shutdownTimeoutMs: 25,
    maxPermits: 2,
    maxQueue: 4,
    ...overrides,
  };
}

async function started(root: string, transport = new FakeTransport(), overrides = {}): Promise<SshConnectionManager> {
  const manager = new SshConnectionManager({ config: config(await keyFile(root), overrides), transport });
  await manager.start();
  return manager;
}

function launchWithKey(path: string) {
  return validateLaunchConfig({
    version: "cogs.dev/v1alpha1",
    user_id: "user-1",
    session_id: "session-1",
    workspace_id: "workspace-1",
    sandbox: {
      ssh_endpoint: "sandbox.local:2222",
      ssh_host_key: validPin,
      client_key_path: path,
      proxy_auth_handle: "sessions/session-1/proxy",
    },
    model: { provider: "anthropic", id: "claude-sonnet-4-5", credential_handle: "users/user-1/model" },
    skills: {
      shared_revision: `sha256:${"a".repeat(64)}`,
      shared_path: "/shared/skills",
      user_revision: `sha256:${"b".repeat(64)}`,
      user_path: "/user/skills",
    },
    integrations: [],
    limits: { cpu: 1, memory_bytes: 268435456, tool_timeout_seconds: 30, max_tool_output_bytes: 4096 },
  });
}

test("SSH test key fixture is a single parsed private key", () => {
  assert.equal(isSinglePrivateParsedKey(ssh2.utils.parseKey(keyPair.private)), true);
});

test("SSH host-key pin decoding is OpenSSH-base64 to exact SHA256 hex", () => {
  const digest = decodeOpenSshSha256Pin(validPin);
  assert.equal(digest.length, 32);
  assert.equal(digest.toString("hex"), "00".repeat(32));
  assert.equal(safeEqualHex(digest.toString("hex"), "00".repeat(32)), true);
  assert.equal(safeEqualHex(digest.toString("hex"), `01${"00".repeat(31)}`), false);
  const rawHostKey = Buffer.from("cogs-known-host-key-fixture");
  const rawDigest = createHash("sha256").update(rawHostKey).digest();
  const rawPin = `SHA256:${rawDigest.toString("base64").replace(/=+$/, "")}`;
  assert.equal(decodeOpenSshSha256Pin(rawPin).toString("hex"), rawDigest.toString("hex"));
  assert.equal(
    safeEqualHex(createHash("sha256").update(Buffer.from("other-host-key")).digest("hex"), rawDigest.toString("hex")),
    false,
  );
  assert.throws(() => decodeOpenSshSha256Pin("SHA256:not-base64"), /host key pin/);
});

test("SSH config and private-key file validation fail closed", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-ssh-config-"));
  try {
    const key = await keyFile(root);
    assert.throws(() => new SshConnectionManager({ config: config(key, { hostKeySha256: "" }) }), /host key pin/);
    assert.throws(() => new SshConnectionManager({ config: config(key, { endpoint: "bad" }) }), /endpoint/);
    assert.throws(() => new SshConnectionManager({ config: config(key, { username: "root;bad" }) }), /username/);
    await assert.rejects(
      new SshConnectionManager({ config: config(resolve(root, "missing")), transport: new FakeTransport() }).start(),
      /key file/,
    );
    const dir = resolve(root, "dir");
    await mkdir(dir);
    await assert.rejects(
      new SshConnectionManager({ config: config(dir), transport: new FakeTransport() }).start(),
      /key file/,
    );
    const target = await keyFile(root, keyPair.private, "target");
    const symlinkPath = resolve(root, "link");
    await symlink(target, symlinkPath);
    await assert.rejects(
      new SshConnectionManager({ config: config(symlinkPath), transport: new FakeTransport() }).start(),
      /key file/,
    );
    const hardlink = resolve(root, "hardlink");
    await link(target, hardlink);
    await assert.rejects(
      new SshConnectionManager({ config: config(target), transport: new FakeTransport() }).start(),
      /link count/,
    );
    const world = await keyFile(root, keyPair.private, "world");
    await chmod(world, 0o644);
    await assert.rejects(
      new SshConnectionManager({ config: config(world), transport: new FakeTransport() }).start(),
      /permissions/,
    );
    await assert.rejects(
      new SshConnectionManager({
        config: config(await keyFile(root, "x".repeat(1024), "oversize"), { maxPrivateKeyBytes: 128 }),
        transport: new FakeTransport(),
      }).start(),
      /key size|private key/,
    );
    const grown = await keyFile(root, `${keyPair.private}\n# appended after original key`, "grown");
    await assert.rejects(
      new SshConnectionManager({
        config: config(grown, { maxPrivateKeyBytes: Buffer.byteLength(keyPair.private) }),
        transport: new FakeTransport(),
      }).start(),
      /key size|private key/,
    );
    await assert.rejects(
      new SshConnectionManager({
        config: config(await keyFile(root, "not a key", "badkey")),
        transport: new FakeTransport(),
      }).start(),
      /private key/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("SSH startup is public-key-only, bounded, redacted, and destroys late noncooperative connects", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-ssh-start-"));
  try {
    const transport = new FakeTransport();
    const manager = await started(root, transport);
    assert.equal(manager.ready, true);
    assert.equal(transport.options[0]?.username, "cogs");
    assert.equal(transport.options[0]?.privateKey.toString("utf8").includes("OPENSSH"), true);
    await manager.shutdown();
    await assert.rejects(
      new SshConnectionManager({
        config: config(await keyFile(root)),
        transport: new FakeTransport({ authFailure: true }),
      }).start(),
      (error: unknown) =>
        error instanceof Error && /ssh start failed/.test(error.message) && !/OPENSSH|auth failed/.test(error.message),
    );
    await assert.rejects(
      new SshConnectionManager({
        config: config(await keyFile(root)),
        transport: new FakeTransport({ hangConnect: true }),
      }).start(),
      /timed out/,
    );
    const abortController = new AbortController();
    const aborting = new SshConnectionManager({
      config: config(await keyFile(root), { connectTimeoutMs: 1000, handshakeTimeoutMs: 1000 }),
      transport: new FakeTransport({ hangConnect: true }),
    }).start(abortController.signal);
    const startedAt = Date.now();
    abortController.abort();
    await assert.rejects(aborting, /aborted/);
    assert.ok(Date.now() - startedAt < 250);

    await assert.rejects(
      new SshConnectionManager({
        config: config(await keyFile(root), { connectTimeoutMs: 10, handshakeTimeoutMs: 10 }),
        transport: new FakeTransport({ delayedResolveMs: 40, throwDestroy: true }),
      }).start(),
      /timed out/,
    );
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 60));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("SSH permit leases are bounded FIFO, cancellable, capacity-limited, and fail closed on loss", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-ssh-permits-"));
  try {
    const transport = new FakeTransport();
    const lost: string[] = [];
    const manager = new SshConnectionManager({
      config: config(await keyFile(root), { maxPermits: 2, maxQueue: 1 }),
      transport,
      onLost: (reason) => lost.push(reason),
    });
    await manager.start();
    const first = await manager.acquire("exec");
    const second = await manager.acquire("sftp");
    let thirdResolved = false;
    const third = manager.acquire("exec").then((lease) => {
      thirdResolved = true;
      return lease;
    });
    assert.throws(() => manager.acquire("sftp"), /queue full/);
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 20));
    assert.equal(thirdResolved, false);
    await first.release();
    const thirdLease = await third;
    assert.equal(thirdResolved, true);
    await second.release();
    await thirdLease.release();

    const queueAbort = await started(root, new FakeTransport(), { maxPermits: 1, maxQueue: 2 });
    const held = await queueAbort.acquire("exec");
    const controller = new AbortController();
    const queued = queueAbort.acquire("sftp", { signal: controller.signal });
    controller.abort();
    await assert.rejects(queued, /aborted/);
    const timed = queueAbort.acquire("sftp");
    await assert.rejects(timed, /timed out/);
    await held.release();
    await queueAbort.shutdown();

    transport.connections[0]?.emit("close");
    assert.deepEqual(lost, ["connection-lost"]);
    assert.throws(() => manager.acquire("exec"), /closed/);
    await manager.shutdown();
    await manager.shutdown();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("real ssh2 wrapper rejects pre-ready terminal events and has no error-listener gap", async () => {
  const server = createServer((socket) => socket.destroy());
  const uncaught: unknown[] = [];
  const onUncaught = (error: unknown) => uncaught.push(error);
  process.on("uncaughtException", onUncaught);
  try {
    await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    const address = server.address();
    assert.equal(typeof address, "object");
    assert.ok(address && typeof address === "object");
    const port = address.port;
    await assert.rejects(
      new Ssh2Transport().connect(
        {
          host: "127.0.0.1",
          port,
          username: "root",
          hostKeySha256: validPin,
          privateKey: Buffer.from(keyPair.private),
          connectTimeoutMs: 500,
          handshakeTimeoutMs: 500,
        },
        new AbortController().signal,
      ),
      /ssh connection failed/,
    );
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 0));
    assert.deepEqual(uncaught, []);
  } finally {
    process.off("uncaughtException", onUncaught);
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
  }
});

test("post-ready ssh2 error forces underlying client destroy during fail-closed teardown", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-ssh-wrapper-error-"));
  class FakeSsh2Client extends EventEmitter {
    public endCalls = 0;
    public destroyCalls = 0;
    public end(): void {
      this.endCalls += 1;
    }
    public destroy(): void {
      this.destroyCalls += 1;
      this.emit("close");
    }
  }
  try {
    const client = new FakeSsh2Client();
    const wrapped = new Ssh2Connection(client as unknown as ConstructorParameters<typeof Ssh2Connection>[0]);
    const manager = new SshConnectionManager({
      config: config(await keyFile(root), { shutdownTimeoutMs: 100 }),
      transport: { connect: async () => wrapped },
    });
    await manager.start();
    client.emit("error", new Error("post-ready protocol failure"));
    await manager.shutdown();
    assert.equal(manager.ready, false);
    assert.equal(client.endCalls, 0);
    assert.equal(client.destroyCalls, 1);
    await manager.shutdown();
    assert.equal(client.destroyCalls, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("SSH shutdown is idempotent, globally bounded, and removes listeners", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-ssh-shutdown-"));
  try {
    const transport = new FakeTransport({ hangClose: true });
    const lost: string[] = [];
    const manager = new SshConnectionManager({
      config: config(await keyFile(root)),
      transport,
      onLost: (reason) => lost.push(reason),
    });
    await manager.start();
    const connection = transport.connections[0];
    assert.ok(connection);
    assert.ok(connection.listenersCount() > 0);
    await manager.shutdown();
    await manager.shutdown();
    assert.equal(connection.destroyCalls, 1);
    assert.equal(connection.listenersCount(), 0);
    connection.emit("close");
    assert.deepEqual(lost, []);

    const throwingTransport = new FakeTransport({ throwClose: true, throwDestroy: true, throwOff: true });
    const throwing = await started(root, throwingTransport);
    await throwing.shutdown();
    assert.equal(throwing.ready, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("SSH launch dependency gates readiness and dependency loss revokes lifecycle readiness", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-ssh-lifecycle-"));
  try {
    const key = await keyFile(root);
    const transport = new FakeTransport();
    let lifecycle: LaunchLifecycle;
    const states: string[] = [];
    const launch = launchWithKey("/run/cogs/ssh/session-1");
    const trustedLaunch = { ...launch, sandbox: { ...launch.sandbox, client_key_path: key } };
    const ssh = createSshLaunchDependency({
      launch: trustedLaunch,
      username: "cogs",
      transport,
      onLost: () => {
        lifecycle.dependencyLost("ssh");
        throw new Error("observer failure");
      },
    });
    const noop = (name: "sessionStorage" | "proxy" | "auth" | "auditWal" | "egressRuntime"): LaunchDependency => ({
      name,
      start: async () => undefined,
      shutdown: async () => undefined,
    });
    lifecycle = new LaunchLifecycle({
      launchDocument: launch,
      dependencies: [noop("sessionStorage"), ssh, noop("proxy"), noop("auth"), noop("auditWal"), noop("egressRuntime")],
      onEvent: (event) => states.push(event.state),
    });
    await lifecycle.start();
    assert.equal(lifecycle.ready, true);
    transport.connections[0]?.emit("close");
    assert.equal(lifecycle.ready, false);
    assert.ok(states.includes("failed"));
    await lifecycle.dispose();

    const raceTransport = new FakeTransport({ emitCloseBeforeResolve: true });
    let raceLifecycle: LaunchLifecycle;
    const raceStates: string[] = [];
    const raceSsh = createSshLaunchDependency({
      launch: trustedLaunch,
      username: "cogs",
      transport: raceTransport,
      onLost: () => raceLifecycle.dependencyLost("ssh"),
    });
    raceLifecycle = new LaunchLifecycle({
      launchDocument: launch,
      dependencies: [
        noop("sessionStorage"),
        raceSsh,
        noop("proxy"),
        noop("auth"),
        noop("auditWal"),
        noop("egressRuntime"),
      ],
      onEvent: (event) => raceStates.push(event.state),
    });
    await raceLifecycle.start();
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 0));
    assert.equal(raceLifecycle.ready, false);
    assert.ok(raceStates.includes("failed"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("ssh2 SFTP wrapper maps only exact numeric own status codes and destroys channels", async () => {
  class FakeSftp extends EventEmitter {
    public destroyed = 0;
    public readError: unknown;
    public read(
      _handle: Buffer,
      buffer: Buffer,
      _offset: number,
      _length: number,
      position: number,
      cb: (err: Error | undefined, bytesRead: number, buffer: Buffer, position: number) => void,
    ) {
      setImmediate(() => cb(this.readError as Error, 0, buffer, position));
    }
    public end(): void {
      this.emit("close");
    }
    public destroy(): void {
      this.destroyed++;
      this.emit("close");
    }
  }
  class FakeClient extends EventEmitter {
    public constructor(private readonly sftpImpl: FakeSftp) {
      super();
    }
    public sftp(cb: (error: Error | undefined, sftp: FakeSftp) => void): void {
      setImmediate(() => cb(undefined, this.sftpImpl));
    }
    public end(): void {
      this.emit("close");
    }
    public destroy(): void {
      this.emit("close");
    }
  }
  const sftp = new FakeSftp();
  const wrapped = new Ssh2Connection(new FakeClient(sftp) as never);
  const channel = await wrapped.openSftp(new AbortController().signal);
  const eof = new Error("permission message says EOF but is exact status");
  Object.defineProperty(eof, "code", { value: 1, enumerable: true });
  sftp.readError = eof;
  assert.equal(
    (await channel.port.read(Buffer.from("h"), Buffer.alloc(1), 0, 1, 0, new AbortController().signal)).bytesRead,
    0,
  );
  const denied = new Error("missing EOF words must not classify");
  Object.defineProperty(denied, "code", { value: 3, enumerable: true });
  sftp.readError = denied;
  await assert.rejects(
    channel.port.read(Buffer.from("h"), Buffer.alloc(1), 0, 1, 0, new AbortController().signal),
    (error: unknown) => error instanceof CogsSftpStatusError && error.status === "permission_denied",
  );
  const accessor = new Error("EOF accessor must not classify");
  Object.defineProperty(accessor, "code", { get: () => 1 });
  sftp.readError = accessor;
  await assert.rejects(
    channel.port.read(Buffer.from("h"), Buffer.alloc(1), 0, 1, 0, new AbortController().signal),
    /^Error: sftp operation failed$/,
  );
  channel.destroy();
  assert.equal(sftp.destroyed, 1);
});

test("ssh2 SFTP wrapper accepts zero EOF and partial slice read tuples and cleans late wx handles", async () => {
  class FakeSftp extends EventEmitter {
    public files = new Set<string>();
    public closed = 0;
    public unlinked = 0;
    public mode: "zero" | "slice" | "late-open" = "zero";
    public read(
      _handle: Buffer,
      buffer: Buffer,
      offset: number,
      _length: number,
      position: number,
      cb: (err: Error | undefined, bytesRead: number, buffer: Buffer, position: number) => void,
    ) {
      setImmediate(() => {
        if (this.mode === "zero") return cb(undefined, 0, Buffer.alloc(0), position);
        buffer[offset] = 0x61;
        buffer[offset + 1] = 0x62;
        return cb(undefined, 2, Buffer.from("ab"), position);
      });
    }
    public open(
      path: string,
      _mode: string,
      _attrs: unknown,
      cb?: (err: Error | undefined, handle: Buffer) => void,
    ): void {
      const callback = (typeof _attrs === "function" ? _attrs : cb) as (err: Error | undefined, handle: Buffer) => void;
      setTimeout(() => {
        this.files.add(path);
        callback(undefined, Buffer.from("late"));
      }, 10);
    }
    public close(_handle: Buffer, cb: (err?: Error) => void): void {
      this.closed++;
      setImmediate(() => cb());
    }
    public unlink(path: string, cb: (err?: Error) => void): void {
      this.unlinked++;
      this.files.delete(path);
      setImmediate(() => cb());
    }
    public end(): void {
      this.emit("close");
    }
    public destroy(): void {
      this.emit("close");
    }
  }
  class FakeClient extends EventEmitter {
    public constructor(private readonly sftpImpl: FakeSftp) {
      super();
    }
    public sftp(cb: (error: Error | undefined, sftp: FakeSftp) => void): void {
      cb(undefined, this.sftpImpl);
    }
    public end(): void {
      this.emit("close");
    }
    public destroy(): void {
      this.emit("close");
    }
  }
  const sftp = new FakeSftp();
  const channel = await new Ssh2Connection(new FakeClient(sftp) as never).openSftp(new AbortController().signal);
  assert.equal(
    (await channel.port.read(Buffer.from("h"), Buffer.alloc(4), 1, 2, 9, new AbortController().signal)).bytesRead,
    0,
  );
  sftp.mode = "slice";
  const destination = Buffer.alloc(4);
  assert.deepEqual(await channel.port.read(Buffer.from("h"), destination, 1, 2, 11, new AbortController().signal), {
    bytesRead: 2,
    buffer: destination,
    position: 11,
  });
  assert.equal(destination.subarray(1, 3).toString(), "ab");
  sftp.mode = "late-open";
  const controller = new AbortController();
  const opened = channel.port.open("/workspace/.cogs-late.tmp", "wx", controller.signal);
  controller.abort();
  await assert.rejects(opened, /sftp operation failed/);
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(sftp.closed, 1);
  assert.equal(sftp.unlinked, 1);
  assert.equal(sftp.files.has("/workspace/.cogs-late.tmp"), false);
});

test("ssh2 SFTP callbacks reject malformed async values without uncaught throws or hangs", async () => {
  class BadStatsSftp extends EventEmitter {
    public calls = 0;
    public lstat(_path: string, cb: (error: Error | undefined, stats: unknown) => void): void {
      setImmediate(() => {
        this.calls++;
        cb(
          undefined,
          new Proxy(
            {},
            {
              getOwnPropertyDescriptor: () => {
                throw new Error("stats proxy boom");
              },
            },
          ),
        );
        cb(undefined, { size: 1, mode: 0o100600 });
      });
    }
    public fstat(_handle: Buffer, cb: (error: Error | undefined, stats: unknown) => void): void {
      setImmediate(() =>
        cb(undefined, {
          get size() {
            throw new Error("accessor must not run");
          },
          mode: 0o100600,
        }),
      );
    }
    public read(
      _handle: Buffer,
      buffer: Buffer,
      _offset: number,
      _length: number,
      position: number,
      cb: (error: unknown, bytesRead: number, buffer: Buffer, position: number) => void,
    ): void {
      setImmediate(() =>
        cb(
          new Proxy(
            {},
            {
              getOwnPropertyDescriptor: () => {
                throw new Error("error proxy boom");
              },
            },
          ),
          0,
          buffer,
          position,
        ),
      );
    }
    public end(): void {
      this.emit("close");
    }
    public destroy(): void {
      this.emit("close");
    }
  }
  class FakeClient extends EventEmitter {
    public constructor(private readonly sftpImpl: BadStatsSftp) {
      super();
    }
    public sftp(cb: (error: Error | undefined, sftp: BadStatsSftp) => void): void {
      cb(undefined, this.sftpImpl);
    }
    public end(): void {
      this.emit("close");
    }
    public destroy(): void {
      this.emit("close");
    }
  }
  const uncaught: unknown[] = [];
  const onUncaught = (error: unknown) => uncaught.push(error);
  process.on("uncaughtException", onUncaught);
  try {
    const sftp = new BadStatsSftp();
    const channel = await new Ssh2Connection(new FakeClient(sftp) as never).openSftp(new AbortController().signal);
    await assert.rejects(
      Promise.race([
        channel.port.lstat("/bad", new AbortController().signal),
        new Promise((_, reject) => setTimeout(() => reject(new Error("hung lstat")), 50)),
      ]),
      /stats proxy boom|invalid stats|operation/,
    );
    await assert.rejects(
      Promise.race([
        channel.port.fstat(Buffer.from("h"), new AbortController().signal),
        new Promise((_, reject) => setTimeout(() => reject(new Error("hung fstat")), 50)),
      ]),
      /sftp operation failed/,
    );
    await assert.rejects(
      Promise.race([
        channel.port.read(Buffer.from("h"), Buffer.alloc(1), 0, 1, 0, new AbortController().signal),
        new Promise((_, reject) => setTimeout(() => reject(new Error("hung read")), 50)),
      ]),
      /sftp operation failed/,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.deepEqual(uncaught, []);
    assert.equal(sftp.calls, 1);
  } finally {
    process.off("uncaughtException", onUncaught);
  }
});

test("ssh2 SFTP wrapper validates own-data stats and malformed handles/read tuples without raw leakage", async () => {
  class StrictSftp extends EventEmitter {
    public openMode: "empty" | "oversize" | "valid" = "valid";
    public readMode: "bad-buffer" | "bad-position" | "mismatch" = "bad-buffer";
    public lstat(_path: string, cb: (error: Error | undefined, stats: unknown) => void): void {
      setImmediate(() =>
        cb(undefined, {
          size: 7,
          mode: 0o100600,
          isDirectory: () => {
            throw new Error("predicate must not be called");
          },
          isFile: () => {
            throw new Error("predicate must not be called");
          },
        }),
      );
    }
    public fstat(_handle: Buffer, cb: (error: Error | undefined, stats: unknown) => void): void {
      setImmediate(() => cb(undefined, { size: -1, mode: 0o100600 }));
    }
    public open(
      _path: string,
      _mode: string,
      _attrs: unknown,
      cb?: (error: Error | undefined, handle: Buffer) => void,
    ): void {
      const callback = (typeof _attrs === "function" ? _attrs : cb) as (
        error: Error | undefined,
        handle: Buffer,
      ) => void;
      setImmediate(() => {
        callback(
          undefined,
          this.openMode === "empty"
            ? Buffer.alloc(0)
            : this.openMode === "oversize"
              ? Buffer.alloc(257)
              : Buffer.from("ok"),
        );
        callback(undefined, Buffer.from("late"));
      });
    }
    public read(
      _handle: Buffer,
      buffer: Buffer,
      offset: number,
      _length: number,
      position: number,
      cb: (error: Error | undefined, bytesRead: number, buffer: Buffer, position: number) => void,
    ): void {
      setImmediate(() => {
        if (this.readMode === "bad-buffer") return cb(undefined, 1, Buffer.from("z"), position);
        buffer[offset] = 0x61;
        if (this.readMode === "bad-position") return cb(undefined, 1, buffer, position + 1);
        return cb(undefined, 1, Buffer.from("b"), position);
      });
    }
    public close(_handle: Buffer, cb: (error?: Error) => void): void {
      setImmediate(() => cb());
    }
    public unlink(_path: string, cb: (error?: Error) => void): void {
      setImmediate(() => cb());
    }
    public end(): void {
      this.emit("close");
    }
    public destroy(): void {
      this.emit("close");
    }
  }
  class FakeClient extends EventEmitter {
    public constructor(private readonly sftpImpl: StrictSftp) {
      super();
    }
    public sftp(cb: (error: Error | undefined, sftp: StrictSftp) => void): void {
      cb(undefined, this.sftpImpl);
    }
    public end(): void {
      this.emit("close");
    }
    public destroy(): void {
      this.emit("close");
    }
  }
  const sftp = new StrictSftp();
  const channel = await new Ssh2Connection(new FakeClient(sftp) as never).openSftp(new AbortController().signal);
  assert.deepEqual(await channel.port.lstat("/file", new AbortController().signal), { size: 7, type: "file" });
  await assert.rejects(channel.port.fstat(Buffer.from("h"), new AbortController().signal), /sftp operation failed/);
  sftp.openMode = "empty";
  await assert.rejects(channel.port.open("/x", "r", new AbortController().signal), /invalid handle/);
  sftp.openMode = "oversize";
  await assert.rejects(channel.port.open("/x", "r", new AbortController().signal), /invalid handle/);
  for (const mode of ["bad-buffer", "bad-position", "mismatch"] as const) {
    sftp.readMode = mode;
    await assert.rejects(
      channel.port.read(Buffer.from("h"), Buffer.alloc(2), 0, 1, 0, new AbortController().signal),
      /sftp operation failed/,
    );
  }
});

test("ssh2 SFTP stats reject POSIX mode high bits and channel observes remote close before close call", async () => {
  class ModeSftp extends EventEmitter {
    public mode = 0o100600;
    public lstat(_path: string, cb: (error: Error | undefined, stats: unknown) => void): void {
      setImmediate(() => cb(undefined, { size: 1, mode: this.mode }));
    }
    public endCalls = 0;
    public end(): void {
      this.endCalls++;
      this.emit("close");
    }
    public destroy(): void {
      this.emit("close");
    }
  }
  class FakeClient extends EventEmitter {
    public constructor(private readonly sftpImpl: ModeSftp) {
      super();
    }
    public sftp(cb: (error: Error | undefined, sftp: ModeSftp) => void): void {
      cb(undefined, this.sftpImpl);
    }
    public end(): void {
      this.emit("close");
    }
    public destroy(): void {
      this.emit("close");
    }
  }
  const sftp = new ModeSftp();
  const channel = await new Ssh2Connection(new FakeClient(sftp) as never).openSftp(new AbortController().signal);
  assert.deepEqual(await channel.port.lstat("/ok", new AbortController().signal), { size: 1, type: "file" });
  sftp.mode = 0o200000;
  await assert.rejects(channel.port.lstat("/bad", new AbortController().signal), /sftp operation failed/);
  sftp.emit("close");
  await channel.close();
  assert.equal(sftp.endCalls, 0);
});

test("ssh2 exec wrapper waits for exit plus close and rejects malformed events", async () => {
  class FakeChannel extends EventEmitter {
    public stderr = new EventEmitter();
    public signalCalls: string[] = [];
    public closeCalls = 0;
    public destroyCalls = 0;
    public signal(name: string): void {
      this.signalCalls.push(name);
    }
    public close(): void {
      this.closeCalls += 1;
      this.emit("close");
    }
    public destroy(): void {
      this.destroyCalls += 1;
      this.emit("close");
    }
  }
  class FakeClient extends EventEmitter {
    public channel = new FakeChannel();
    public exec(
      _command: string,
      _options: unknown,
      callback: (error: Error | undefined, channel?: unknown) => void,
    ): void {
      callback(undefined, this.channel);
    }
  }
  const client = new FakeClient();
  const connection = new Ssh2Connection(client as never);
  const exec = await connection.openExec("fixed", new AbortController().signal);
  const stdout: Buffer[] = [];
  exec.port.onStdout((chunk) => stdout.push(chunk));
  client.channel.emit("data", Buffer.from("ok"));
  const terminal = exec.port.terminal();
  client.channel.emit("exit", 0, undefined, false, "");
  await Promise.race([
    terminal.then(() => assert.fail("terminal settled before close")),
    new Promise((resolve) => setTimeout(resolve, 5)),
  ]);
  client.channel.emit("close");
  assert.deepEqual(await terminal, { code: 0, signal: null });
  assert.equal(Buffer.concat(stdout).toString("utf8"), "ok");
  await assert.rejects(exec.port.signal("TERM"), /closed/);

  const malformedClient = new FakeClient();
  const malformed = await new Ssh2Connection(malformedClient as never).openExec("fixed", new AbortController().signal);
  malformedClient.channel.emit("data", "not-buffer");
  await assert.rejects(malformed.port.terminal(), /exec channel failed/);

  const duplicateClient = new FakeClient();
  const duplicate = await new Ssh2Connection(duplicateClient as never).openExec("fixed", new AbortController().signal);
  duplicateClient.channel.emit("exit", 0, undefined, false, "");
  duplicateClient.channel.emit("exit", 0, undefined, false, "");
  await assert.rejects(duplicate.port.terminal(), /exec channel failed/);

  const noExitClient = new FakeClient();
  const noExit = await new Ssh2Connection(noExitClient as never).openExec("fixed", new AbortController().signal);
  noExitClient.channel.emit("close");
  await assert.rejects(noExit.port.terminal(), /exec channel failed/);
});

test("ssh2 exec wrapper rejects malformed terminal tuples, late callbacks, and keeps late error sinks", async () => {
  class FakeChannel extends EventEmitter {
    public stderr = new EventEmitter();
    public closeCalls = 0;
    public destroyCalls = 0;
    public signal(_name: string): void {}
    public close(): void {
      this.closeCalls += 1;
      this.emit("close");
    }
    public destroy(): void {
      this.destroyCalls += 1;
    }
  }
  class TwiceClient extends EventEmitter {
    public first = new FakeChannel();
    public late = new FakeChannel();
    public exec(
      _command: string,
      _options: unknown,
      callback: (error: Error | undefined, channel?: unknown) => void,
    ): void {
      callback(undefined, this.first);
      callback(undefined, this.late);
    }
  }
  const twice = new TwiceClient();
  const opened = await new Ssh2Connection(twice as never).openExec("fixed", new AbortController().signal);
  assert.equal(twice.late.destroyCalls, 1);
  twice.first.emit("exit", 0, undefined, false, "");
  twice.first.emit("close");
  assert.deepEqual(await opened.port.terminal(), { code: 0, signal: null });
  twice.first.emit("error", new Error("late"));
  twice.first.stderr.emit("error", new Error("late"));

  for (const allowedSignal of ["SIGFPE", "SIGILL"] as const) {
    class SignalClient extends EventEmitter {
      public channel = new FakeChannel();
      public exec(
        _command: string,
        _options: unknown,
        callback: (error: Error | undefined, channel?: unknown) => void,
      ): void {
        callback(undefined, this.channel);
      }
    }
    const signalClient = new SignalClient();
    const signalExec = await new Ssh2Connection(signalClient as never).openExec("fixed", new AbortController().signal);
    signalClient.channel.emit("exit", null, allowedSignal, false, "");
    signalClient.channel.emit("close");
    assert.deepEqual(await signalExec.port.terminal(), { code: null, signal: allowedSignal });
  }

  for (const tuple of [
    [null, "TERM", false, ""],
    [null, "SIGBOGUS", false, ""],
    [0, undefined, true, ""],
    [0, undefined, false, "x".repeat(2048)],
  ] as const) {
    class Client extends EventEmitter {
      public channel = new FakeChannel();
      public exec(
        _command: string,
        _options: unknown,
        callback: (error: Error | undefined, channel?: unknown) => void,
      ): void {
        callback(undefined, this.channel);
      }
    }
    const client = new Client();
    const exec = await new Ssh2Connection(client as never).openExec("fixed", new AbortController().signal);
    client.channel.emit("exit", ...tuple);
    await assert.rejects(exec.port.terminal(), /exec channel failed/);
  }

  class ThrowingClient extends EventEmitter {
    public channel = new FakeChannel();
    public exec(
      _command: string,
      _options: unknown,
      callback: (error: Error | undefined, channel?: unknown) => void,
    ): void {
      this.channel.on = () => {
        throw new Error("on failed");
      };
      callback(undefined, this.channel);
    }
  }
  await assert.rejects(
    new Ssh2Connection(new ThrowingClient() as never).openExec("fixed", new AbortController().signal),
    /ssh exec open failed/,
  );
});

test("ssh2 exec wrapper guards hostile stderr/off/destroy during attach cleanup and late destroy", async () => {
  class HostileChannel extends EventEmitter {
    public readonly stderrEmitter = new EventEmitter();
    public get stderr(): EventEmitter {
      return this.stderrEmitter;
    }
    public signal(_name: string): void {}
    public close(): void {
      this.emit("close");
    }
    public destroy(): void {
      throw new Error("destroy failed");
    }
    public override off(_event: string | symbol, _listener: (...args: never[]) => void): this {
      throw new Error("off failed");
    }
  }
  class Client extends EventEmitter {
    public channel = new HostileChannel();
    public late = new HostileChannel();
    public exec(
      _command: string,
      _options: unknown,
      callback: (error: Error | undefined, channel?: unknown) => void,
    ): void {
      callback(undefined, this.channel);
      callback(undefined, this.late);
    }
  }
  const client = new Client();
  const exec = await new Ssh2Connection(client as never).openExec("fixed", new AbortController().signal);
  client.channel.emit("exit", 0, undefined, false, "");
  client.channel.emit("close");
  assert.deepEqual(await exec.port.terminal(), { code: 0, signal: null });
  client.channel.emit("error", new Error("late channel"));
  client.channel.stderrEmitter.emit("error", new Error("late stderr"));

  class BadStderr extends HostileChannel {
    public override get stderr(): EventEmitter {
      throw new Error("stderr getter failed");
    }
  }
  class BadClient extends EventEmitter {
    public exec(
      _command: string,
      _options: unknown,
      callback: (error: Error | undefined, channel?: unknown) => void,
    ): void {
      callback(undefined, new BadStderr());
    }
  }
  await assert.rejects(
    new Ssh2Connection(new BadClient() as never).openExec("fixed", new AbortController().signal),
    /ssh exec open failed/,
  );
});

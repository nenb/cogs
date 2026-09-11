import { createHash, randomBytes } from "node:crypto";
import { type BigIntStats, constants } from "node:fs";
import { type FileHandle, lstat, open, realpath } from "node:fs/promises";
import { Socket } from "node:net";
import { dirname, resolve } from "node:path";
import { Client, type SFTPWrapper, type Stats } from "ssh2";
import type { LaunchConfig } from "../launch/config.ts";
import { withTrustedFileBytes } from "../runtime/trusted-files.ts";
import {
  type CogsSftpPort,
  type CogsSftpStats,
  decodeOpenSshSha256Pin,
  type SshConnectionManager,
  safeEqualHex,
} from "../ssh/connection.ts";
import { type CogsSkillBundleHandle, verifyCogsSkillBundle } from "./bundle.ts";
import type { CogsPrivateSkillStore } from "./local-private-store.ts";
import type { CogsSharedSkillOciResolver } from "./oci-layout.ts";
import {
  type CogsPreparedSkillSet,
  CogsSkillPreparationError,
  type CogsSkillPreparerPort,
  loadCogsRetainedSkillPair,
  readAgentsFile,
} from "./session-preparer.ts";

const RECEIPT_VERSION = "cogs.skill-snapshot-receipt/v1";
const CONTROL_VERSION = "cogs.skill-snapshot-control/v1";
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const HEX_ID = /^[a-f0-9]{64}$/;
const NONCE = /^[a-f0-9]{32}$/;
const BUNDLE_FILE = ".cogs-skills-bundle.json";
const AUTHORIZED_SETS = new WeakMap<object, SnapshotLease>();

type MountReceipt = Readonly<{
  source_device: string;
  source_inode: string;
  destination: string;
  read_only: true;
  bundle_digest: `sha256:${string}`;
}>;
export type CogsSkillSnapshotReceipt = Readonly<{
  version: typeof RECEIPT_VERSION;
  generation: string;
  consumer_id: string;
  session_id: string;
  launch_digest: `sha256:${string}`;
  worker_id: string;
  sandbox_id: string;
  sandbox_mount_namespace: string;
  shared: MountReceipt;
  user: MountReceipt;
}>;

/** This check does not confer authority: only root custody AND a live admission can register a set. */
export function isRuntimeReadOnlySkillSet(value: unknown): boolean {
  return typeof value === "object" && value !== null && AUTHORIZED_SETS.get(value)?.alive === true;
}

export function parseCogsSkillSnapshotReceipt(bytes: Uint8Array): CogsSkillSnapshotReceipt {
  try {
    if (bytes.length < 2 || bytes.length > 8192) fail();
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    const value = JSON.parse(text) as CogsSkillSnapshotReceipt;
    exactKeys(value, [
      "version",
      "generation",
      "consumer_id",
      "session_id",
      "launch_digest",
      "worker_id",
      "sandbox_id",
      "sandbox_mount_namespace",
      "shared",
      "user",
    ]);
    if (
      value.version !== RECEIPT_VERSION ||
      !matches(NONCE, value.generation) ||
      !matches(NONCE, value.consumer_id) ||
      !matches(DIGEST, value.launch_digest) ||
      !matches(HEX_ID, value.worker_id) ||
      !matches(HEX_ID, value.sandbox_id) ||
      value.worker_id === value.sandbox_id ||
      !matches(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/, value.session_id) ||
      !matches(/^mnt:\[[1-9][0-9]{0,19}\]$/, value.sandbox_mount_namespace)
    )
      fail();
    for (const scope of ["shared", "user"] as const) {
      const mount = value[scope];
      exactKeys(mount, ["source_device", "source_inode", "destination", "read_only", "bundle_digest"]);
      if (
        !matches(/^(0|[1-9][0-9]{0,19})$/, mount.source_device) ||
        !matches(/^[1-9][0-9]{0,19}$/, mount.source_inode) ||
        !matches(DIGEST, mount.bundle_digest) ||
        mount.read_only !== true ||
        mount.destination !== `/${scope}/skills/${mount.bundle_digest.slice(7)}`
      )
        fail();
      if (BigInt(mount.source_device) > 0xffffffffffffffffn || BigInt(mount.source_inode) > 0xffffffffffffffffn) fail();
      Object.freeze(mount);
    }
    if (
      value.shared.source_device === value.user.source_device &&
      value.shared.source_inode === value.user.source_inode
    )
      fail();
    if (text !== canonical(value)) fail();
    return Object.freeze(value);
  } catch {
    return fail();
  }
}

export function createCogsMountedSkillSessionPreparer(
  options: Readonly<{
    ssh: SshConnectionManager;
    sharedResolver: CogsSharedSkillOciResolver;
    privateStore: CogsPrivateSkillStore;
    receiptPath: string;
    controlSocketPath: string;
    onLost: () => void;
  }>,
): CogsSkillPreparerPort {
  const captured = Object.freeze({ ...options });
  let used = false;
  return Object.freeze({
    prepare: async ({ launch, signal }: { launch: LaunchConfig; signal?: AbortSignal }) => {
      if (used) fail();
      used = true;
      let lease: SnapshotLease | undefined;
      try {
        // Missing authority fails before any local snapshot or guest observation.
        lease = await acquireLease(captured.receiptPath, captured.controlSocketPath, launch, captured.onLost, signal);
        const active = AbortSignal.any([lease.signal, signal ?? new AbortController().signal]);
        const retained = await loadCogsRetainedSkillPair(captured, launch, active);
        for (const scope of ["shared", "user"] as const)
          if (lease.receipt[scope].bundle_digest !== retained[scope].bundle.digest) fail();
        // A dedicated pinned SFTP channel supplies bounded READDIR, absent from the tool SFTP port.
        await withSnapshotSftp(launch, active, async (sftp, operationSignal) => {
          await verifyCogsMountedSkillBundle(sftp, retained.shared.bundle, "/shared/skills", operationSignal);
          await verifyCogsMountedSkillBundle(sftp, retained.user.bundle, "/user/skills", operationSignal);
        });
        const agents = await captured.ssh.withSftp({ signal: active, operationTimeoutMs: 5000 }, readAgentsFile);
        if (!lease.alive || active.aborted) fail();
        const authority = lease;
        const metadata = Object.freeze({
          shared: authorizedSet("shared", retained.sharedRevision, retained.shared.bundle, authority),
          user: authorizedSet("user", retained.userRevision, retained.user.bundle, authority),
          agentsStatus: agents.status,
          skillCount: retained.piSkills.length,
        });
        return Object.freeze({
          piSkills: retained.piSkills,
          eagerTrustedSkillPrompt: retained.eagerTrustedSkillPrompt,
          agentsFiles: Object.freeze(agents.file === undefined ? [] : [agents.file]),
          metadata,
          dispose: () => authority.release(),
        });
      } catch {
        await lease?.release().catch(() => undefined);
        return fail();
      }
    },
  });
}

function authorizedSet(
  scope: "shared" | "user",
  revision: `sha256:${string}`,
  bundle: CogsSkillBundleHandle,
  lease: SnapshotLease,
): CogsPreparedSkillSet {
  if (!lease.alive || lease.receipt[scope].bundle_digest !== bundle.digest) fail();
  const set: CogsPreparedSkillSet = Object.freeze({
    scope,
    revision,
    bundleDigest: bundle.digest,
    guestRoot: scope === "shared" ? "/shared/skills" : "/user/skills",
    guestSubtree: lease.receipt[scope].destination,
    fileCount: bundle.fileCount,
    byteCount: bundle.decodedByteLength,
    readOnlyEnforced: true,
  });
  AUTHORIZED_SETS.set(set, lease);
  return set;
}

async function acquireLease(
  receiptPath: string,
  socketPath: string,
  launch: LaunchConfig,
  onLost: () => void,
  signal?: AbortSignal,
): Promise<SnapshotLease> {
  // Production worker is unprivileged. Its own uid must not be the root supervisor authority.
  if (process.geteuid?.() === undefined || process.geteuid() === 0 || typeof onLost !== "function") fail();
  const held: Array<{ path: string; handle: FileHandle; identity: string }> = [];
  let lease: SnapshotLease | undefined;
  try {
    const parents = new Set<string>();
    for (const target of [receiptPath, socketPath]) {
      if (resolve(target) !== target || target.length > 4096 || target.includes("\0")) fail();
      for (let p = dirname(target); ; p = dirname(p)) {
        parents.add(p);
        if (p === "/") break;
      }
    }
    for (const p of [...parents].sort()) {
      const before = await lstat(p, { bigint: true });
      if (!before.isDirectory() || before.uid !== 0n || (before.mode & 0o7022n) !== 0n) fail();
      const handle = await open(p, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      held.push({ path: p, handle, identity: custodyIdentity(before) });
      if (custodyIdentity(await handle.stat({ bigint: true })) !== custodyIdentity(before)) fail();
    }
    const receiptStat = await lstat(receiptPath, { bigint: true });
    if ((receiptStat.mode & 0o7000n) !== 0n) fail();
    const socketStat = await lstat(socketPath, { bigint: true });
    if (
      !socketStat.isSocket() ||
      socketStat.uid !== 0n ||
      socketStat.gid !== BigInt(process.getegid?.() ?? -1) ||
      (socketStat.mode & 0o7777n) !== 0o660n ||
      socketStat.nlink !== 1n ||
      (await realpath(socketPath)) !== socketPath
    )
      fail();
    const receipt = await withTrustedFileBytes(
      {
        path: receiptPath,
        minimumBytes: 2,
        maximumBytes: 8192,
        allowedUids: [0],
        allowedGids: [0, process.getegid?.() ?? -1].filter((v, i, a) => a.indexOf(v) === i),
        allowedModes: [0o400, 0o440, 0o444],
      },
      async (bytes) => parseCogsSkillSnapshotReceipt(bytes),
    );
    if (receipt.session_id !== launch.session_id || receipt.launch_digest !== digest(Buffer.from(canonical(launch))))
      fail();
    lease = new SnapshotLease(receipt, onLost);
    await lease.connect(socketPath, signal);
    if (
      custodyIdentity(await lstat(socketPath, { bigint: true })) !== custodyIdentity(socketStat) ||
      custodyIdentity(await lstat(receiptPath, { bigint: true })) !== custodyIdentity(receiptStat)
    )
      fail();
    for (const directory of held) {
      if (
        custodyIdentity(await lstat(directory.path, { bigint: true })) !== directory.identity ||
        custodyIdentity(await directory.handle.stat({ bigint: true })) !== directory.identity
      )
        fail();
    }
    // Path custody, not an echo or a TypeScript object, authenticates the server.
    // The supervisor must authenticate the connecting kernel peer and bind this
    // pid/nonce to its exact worker/container/mount census before replying leased.
    await lease.admit();
    for (const item of held) await item.handle.close();
    held.length = 0;
    return lease;
  } catch {
    await lease?.release().catch(() => undefined);
    return fail();
  } finally {
    for (const item of held.reverse()) await item.handle.close().catch(() => undefined);
  }
}

function custodyIdentity(stat: BigIntStats): string {
  return [stat.dev, stat.ino, stat.uid, stat.gid, stat.mode, stat.nlink, stat.size, stat.mtimeNs, stat.ctimeNs].join(
    ":",
  );
}

class SnapshotLease {
  readonly #socket = new Socket();
  readonly #controller = new AbortController();
  readonly #closed: Promise<void>;
  readonly #nonce = randomBytes(16).toString("hex");
  #admitted = false;
  #released = false;
  #sequence = 0;
  #pending:
    | { expected: string; resolve: () => void; reject: () => void; timer: ReturnType<typeof setTimeout> }
    | undefined;
  #input = Buffer.alloc(0);
  #heartbeat: ReturnType<typeof setTimeout> | undefined;
  #release: Promise<void> | undefined;
  public constructor(
    readonly receipt: CogsSkillSnapshotReceipt,
    readonly onLost: () => void,
  ) {
    this.#closed = new Promise((resolveClosed) =>
      this.#socket.once("close", () => {
        this.#lose();
        resolveClosed();
      }),
    );
    this.#socket.on("error", () => this.#lose());
    this.#socket.on("end", () => this.#lose());
    this.#socket.on("data", (chunk: Buffer) => {
      const pending = this.#pending;
      if (!pending || chunk.length + this.#input.length > 1024) return this.#lose();
      this.#input = Buffer.concat([this.#input, chunk]);
      if (!this.#input.includes(10)) return;
      if (!this.#input.equals(Buffer.from(pending.expected))) return this.#lose();
      this.#pending = undefined;
      this.#input = Buffer.alloc(0);
      clearTimeout(pending.timer);
      pending.resolve();
    });
  }
  public get signal(): AbortSignal {
    return this.#controller.signal;
  }
  public get alive(): boolean {
    return this.#admitted && !this.#released && !this.signal.aborted;
  }
  public async connect(path: string, signal?: AbortSignal): Promise<void> {
    const abort = () => this.#lose();
    signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(abort, 5000);
    try {
      if (signal?.aborted) fail();
      await new Promise<void>((resolveConnect, reject) => {
        this.#socket.once("connect", resolveConnect);
        void this.#closed.then(() => reject(new CogsSkillPreparationError()));
        this.#socket.connect(path);
      });
      if (this.signal.aborted || signal?.aborted) fail();
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }
  public async admit(): Promise<void> {
    await this.#exchange("acquire", "leased");
    if (this.signal.aborted) fail();
    this.#admitted = true;
    this.#scheduleHeartbeat();
  }
  public release(): Promise<void> {
    this.#release ??= (async () => {
      if (this.#heartbeat) clearTimeout(this.#heartbeat);
      try {
        // Join an in-flight heartbeat before sending the final release.
        while (this.#pending && !this.signal.aborted) await new Promise((r) => setTimeout(r, 10));
        if (!this.alive) fail();
        await this.#exchange("release", "released");
        this.#released = true;
      } finally {
        this.#lose();
        await this.#closed;
      }
    })();
    return this.#release;
  }
  #scheduleHeartbeat(): void {
    if (this.#release || !this.alive) return;
    this.#heartbeat = setTimeout(() => {
      void this.#exchange("ping", "alive").then(
        () => this.#scheduleHeartbeat(),
        () => this.#lose(),
      );
    }, 1000);
  }
  #exchange(op: string, reply: string): Promise<void> {
    if (this.signal.aborted || this.#pending || this.#sequence >= Number.MAX_SAFE_INTEGER)
      return Promise.reject(new CogsSkillPreparationError());
    const message = {
      version: CONTROL_VERSION,
      op,
      nonce: this.#nonce,
      sequence: ++this.#sequence,
      receipt_digest: digest(Buffer.from(canonical(this.receipt))),
      consumer_id: this.receipt.consumer_id,
      pid: process.pid,
    };
    return new Promise<void>((resolveReply, reject) => {
      this.#pending = {
        expected: canonical({ ...message, op: reply }),
        resolve: resolveReply,
        reject: () => reject(new CogsSkillPreparationError()),
        timer: setTimeout(() => this.#lose(), 2000),
      };
      this.#socket.write(canonical(message), (error) => {
        if (error) this.#lose();
      });
    });
  }
  #lose(): void {
    if (this.signal.aborted) return;
    this.#controller.abort();
    if (this.#heartbeat) clearTimeout(this.#heartbeat);
    if (this.#pending) {
      clearTimeout(this.#pending.timer);
      this.#pending.reject();
      this.#pending = undefined;
    }
    this.#socket.destroy();
    if (!this.#released) {
      try {
        this.onLost();
      } catch {
        /* failure remains latched */
      }
    }
  }
}

/** Narrow verification port: no mutating operations and no authority-bearing result. */
export type CogsSnapshotSftpPort = Pick<CogsSftpPort, "lstat" | "realpath" | "read" | "fstat" | "closeHandle"> &
  Readonly<{
    open: (path: string, mode: "r", signal: AbortSignal) => Promise<Buffer>;
    list: (path: string, maximum: number, signal: AbortSignal) => Promise<readonly string[]>;
  }>;

type ExpectedEntry = { mode: number; size?: number; hash?: string; children?: Set<string> };
export async function verifyCogsMountedSkillBundle(
  sftp: CogsSnapshotSftpPort,
  input: CogsSkillBundleHandle,
  root: "/shared/skills" | "/user/skills",
  signal: AbortSignal,
): Promise<void> {
  try {
    if (root !== "/shared/skills" && root !== "/user/skills") fail();
    const bundle = verifyCogsSkillBundle(input.copyBytes());
    if (bundle.digest !== input.digest) fail();
    const subtree = `${root}/${bundle.digest.slice(7)}`;
    const inventory = new Map<string, ExpectedEntry>([[subtree, { mode: 0o40555, children: new Set() }]]);
    let directories = 1;
    const add = (relative: string, size: number, hash: string, mode: number) => {
      const parts = relative.split("/");
      if (parts.length > 16) fail();
      let parent = subtree;
      for (const [index, part] of parts.entries()) {
        inventory.get(parent)?.children?.add(part);
        const p = `${parent}/${part}`;
        if (index === parts.length - 1) {
          if (inventory.has(p)) fail();
          inventory.set(p, { mode, size, hash });
        } else if (!inventory.has(p)) {
          if (++directories > 128) fail();
          inventory.set(p, { mode: 0o40555, children: new Set() });
        } else if (!inventory.get(p)?.children) fail();
        parent = p;
      }
    };
    add(BUNDLE_FILE, bundle.byteLength, bundle.digest, 0o100444);
    for (const file of bundle.files) add(file.path, file.size, file.sha256, file.executable ? 0o100555 : 0o100444);
    const observations = new Map<string, string>();
    let calls = 0;
    let bytes = 0;
    const observe = async <T>(operation: () => Promise<T>): Promise<T> => {
      if (++calls > 8192 || signal.aborted) fail();
      const value = await operation();
      if (signal.aborted) fail();
      return value;
    };
    for (let pass = 0; pass < 2; pass++) {
      for (const [p, expected] of inventory) {
        const before = await observe(() => sftp.lstat(p, signal));
        const stamp = statsStamp(before, expected);
        if (pass === 1 && observations.get(p) !== stamp) fail();
        observations.set(p, stamp);
        if ((await observe(() => sftp.realpath(p, signal))) !== p) fail();
        if (expected.children) {
          const names = await observe(() => sftp.list(p, expected.children?.size ?? 0, signal));
          if (!Array.isArray(names) || names.length !== expected.children.size || new Set(names).size !== names.length)
            fail();
          for (const name of names) if (!expected.children.has(name)) fail();
        } else {
          const handle = await observe(() => sftp.open(p, "r", signal));
          try {
            if (statsStamp(await observe(() => sftp.fstat(handle, signal)), expected) !== stamp) fail();
            const hash = createHash("sha256");
            let position = 0;
            const size = expected.size ?? fail();
            for (;;) {
              const length = Math.min(32 * 1024, size - position + 1);
              const buffer = Buffer.alloc(length);
              const result = await observe(() => sftp.read(handle, buffer, 0, length, position, signal));
              if (
                result.buffer !== buffer ||
                result.position !== position ||
                !Number.isSafeInteger(result.bytesRead) ||
                result.bytesRead < 0 ||
                result.bytesRead > length
              )
                fail();
              if (result.bytesRead === 0) {
                if (position !== size) fail();
                break;
              }
              position += result.bytesRead;
              bytes += result.bytesRead;
              if (position > size || bytes > 4 * 1024 * 1024) fail();
              hash.update(buffer.subarray(0, result.bytesRead));
            }
            if (
              `sha256:${hash.digest("hex")}` !== expected.hash ||
              statsStamp(await observe(() => sftp.fstat(handle, signal)), expected) !== stamp
            )
              fail();
          } finally {
            await sftp.closeHandle(handle, signal);
          }
        }
        if (statsStamp(await observe(() => sftp.lstat(p, signal)), expected) !== stamp) fail();
      }
      // Postwalk detects directory replacement/addition while descendants were read.
      for (const [p, expected] of inventory)
        if (expected.children) {
          if (statsStamp(await observe(() => sftp.lstat(p, signal)), expected) !== observations.get(p)) fail();
          const names = await observe(() => sftp.list(p, expected.children?.size ?? 0, signal));
          if (
            names.length !== expected.children.size ||
            new Set(names).size !== names.length ||
            names.some((n) => !expected.children?.has(n))
          )
            fail();
        }
    }
  } catch {
    fail();
  }
}

function statsStamp(stat: CogsSftpStats, expected: ExpectedEntry): string {
  if (
    stat.mode !== expected.mode ||
    stat.type !== (expected.children ? "directory" : "file") ||
    !Number.isSafeInteger(stat.size) ||
    stat.size < 0 ||
    stat.size > 16 * 1024 * 1024 ||
    (expected.size !== undefined && stat.size !== expected.size)
  )
    fail();
  // ssh2 adds uid/gid/mtime; atime is deliberately excluded (our reads can change it).
  const extra = stat as CogsSftpStats & { uid?: number; gid?: number; mtime?: number };
  for (const value of [extra.uid, extra.gid, extra.mtime])
    if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > 0xffffffff) fail();
  return [stat.mode, stat.type, stat.size, extra.uid, extra.gid, extra.mtime].join(":");
}

/** Pinned, read-only SFTP observation; this function cannot grant a snapshot lease. */
export async function withSnapshotSftp<T>(
  launch: LaunchConfig,
  parent: AbortSignal,
  operation: (port: CogsSnapshotSftpPort, signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const uid = process.geteuid?.() ?? fail(),
    gid = process.getegid?.() ?? fail();
  return withTrustedFileBytes(
    {
      path: launch.sandbox.client_key_path,
      minimumBytes: 128,
      maximumBytes: 16 * 1024,
      allowedUids: [uid],
      allowedGids: [gid],
      allowedModes: [0o400, 0o600],
    },
    async (key) => {
      const client = new Client();
      const deadline = new AbortController();
      const timer = setTimeout(() => deadline.abort(), 30_000);
      const signal = AbortSignal.any([parent, deadline.signal]);
      const closed = new Promise<void>((done) => client.once("close", done));
      const abort = () => client.destroy();
      const check = () => {
        if (signal.aborted) fail();
      };
      const rpc = <R>(invoke: (cb: (error: Error | undefined | null, value: R) => void) => void): Promise<R> => {
        check();
        return new Promise<R>((accept, reject) => {
          const lost = () => {
            cleanup();
            reject(new CogsSkillPreparationError());
          };
          const cleanup = () => {
            client.off("close", lost);
            signal.removeEventListener("abort", lost);
          };
          client.once("close", lost);
          signal.addEventListener("abort", lost, { once: true });
          try {
            invoke((error, value) => {
              cleanup();
              error || signal.aborted ? reject(new CogsSkillPreparationError()) : accept(value);
            });
          } catch {
            lost();
          }
        });
      };
      client.on("error", abort);
      signal.addEventListener("abort", abort, { once: true });
      let issued = false;
      try {
        check();
        const endpoint = new URL(`ssh://${launch.sandbox.ssh_endpoint}`);
        const pin = decodeOpenSshSha256Pin(launch.sandbox.ssh_host_key).toString("hex");
        const ready = new Promise<void>((accept, reject) => {
          client.once("ready", accept);
          void closed.then(() => reject(new CogsSkillPreparationError()));
        });
        issued = true;
        client.connect({
          host: endpoint.hostname.replace(/^\[|\]$/g, ""),
          port: Number(endpoint.port || 22),
          username: "root",
          privateKey: key,
          agentForward: false,
          tryKeyboard: false,
          hostHash: "sha256",
          hostVerifier: (hash: string) => safeEqualHex(hash, pin),
          readyTimeout: 5000,
          authHandler: [{ type: "publickey", username: "root", key } as never],
          algorithms: {
            cipher: {
              remove: ["aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "3des-cbc", "arcfour"],
            } as never,
            hmac: { remove: ["hmac-sha1", "hmac-md5"] } as never,
            serverHostKey: { remove: ["ssh-dss", "ssh-rsa"] } as never,
          },
        });
        await ready;
        const sftp = await rpc<SFTPWrapper>((cb) => client.sftp(cb));
        const stats = (s: Stats): CogsSftpStats => ({
          size: s.size,
          mode: s.mode,
          type: s.isFile() ? "file" : s.isDirectory() ? "directory" : "unknown",
          ...{ uid: s.uid, gid: s.gid, mtime: s.mtime },
        });
        const port: CogsSnapshotSftpPort = Object.freeze({
          lstat: async (p) => stats(await rpc<Stats>((cb) => sftp.lstat(p, cb))),
          realpath: (p) => rpc<string>((cb) => sftp.realpath(p, cb)),
          open: (p, mode) => {
            if (mode !== "r") fail();
            return rpc<Buffer>((cb) => sftp.open(p, "r", cb));
          },
          fstat: async (h) => stats(await rpc<Stats>((cb) => sftp.fstat(h, cb))),
          closeHandle: (h) => rpc<void>((cb) => sftp.close(h, (error) => cb(error, undefined))),
          read: (h, b, o, l, p) =>
            rpc((cb) =>
              sftp.read(h, b, o, l, p, (error, count, buffer, position) => {
                if ((error as { code?: number } | undefined)?.code === 1)
                  return cb(undefined, { bytesRead: 0, buffer: b, position: p });
                if (
                  error ||
                  !Number.isSafeInteger(count) ||
                  count < 0 ||
                  count > l ||
                  position !== p ||
                  !Buffer.isBuffer(buffer) ||
                  ![count, l, b.length].includes(buffer.length) ||
                  !(buffer.length === count ? buffer : buffer.subarray(o, o + count)).equals(b.subarray(o, o + count))
                )
                  return cb(new CogsSkillPreparationError(), { bytesRead: 0, buffer: b, position: p });
                cb(undefined, { bytesRead: count, buffer: b, position: p });
              }),
            ),
          list: async (p, maximum) => {
            const handle = await rpc<Buffer>((cb) => sftp.opendir(p, cb));
            const names: string[] = [];
            const seen = new Set<string>();
            try {
              for (let calls = 0; ; calls++) {
                if (calls > maximum + 2) fail();
                const batch = await rpc<false | Array<{ filename: string }>>((cb) =>
                  sftp.readdir(handle, (error, list) =>
                    (error as { code?: number } | undefined)?.code === 1 ? cb(undefined, false) : cb(error, list),
                  ),
                );
                if (batch === false) break;
                if (!Array.isArray(batch) || batch.length < 1 || batch.length > maximum + 2 - seen.size) fail();
                for (const entry of batch) {
                  if (typeof entry.filename !== "string" || entry.filename.length > 256 || seen.has(entry.filename))
                    fail();
                  seen.add(entry.filename);
                  if (entry.filename !== "." && entry.filename !== "..") names.push(entry.filename);
                }
                if (names.length > maximum) fail();
              }
              return names;
            } finally {
              await rpc<void>((cb) => sftp.close(handle, (error) => cb(error, undefined)));
            }
          },
        });
        const result = await operation(port, signal);
        check();
        return result;
      } finally {
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        client.destroy();
        // A deadline requests destruction, never proves SSH/channel retirement.
        if (issued) await closed;
      }
    },
  );
}

function matches(pattern: RegExp, value: unknown): boolean {
  return typeof value === "string" && pattern.test(value);
}
function exactKeys(value: unknown, keys: string[]): void {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join() !== keys.sort().join()
  )
    fail();
}
function canonical(value: unknown): string {
  const encode = (v: unknown): string =>
    Array.isArray(v)
      ? `[${v.map(encode).join(",")}]`
      : v !== null && typeof v === "object"
        ? `{${Object.keys(v)
            .sort()
            .map((key) => `${JSON.stringify(key)}:${encode((v as Record<string, unknown>)[key])}`)
            .join(",")}}`
        : JSON.stringify(v);
  return `${encode(value)}\n`;
}
function digest(bytes: Buffer): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
function fail(): never {
  throw new CogsSkillPreparationError();
}

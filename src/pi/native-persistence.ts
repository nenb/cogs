import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { type SessionEntry, SessionManager } from "@earendil-works/pi-coding-agent";

export type PersistenceCause =
  | "native-write"
  | "native-mutation"
  | "serialization"
  | "history-mismatch"
  | "history-io"
  | "file-sync"
  | "directory-sync"
  | "close"
  | "owner-marker"
  | "activity";
export class NativePersistenceError extends Error {
  readonly code = "COGS_NATIVE_PERSISTENCE_FAILED";
  constructor(readonly causeCategory: PersistenceCause) {
    super(`native persistence ${causeCategory}`);
  }
}
export type NativeFrontier = Readonly<{
  nativeSessionId: string;
  revision: number;
  entries: number;
  lastAppendId: string | null;
  bytes: number;
  wireSha256: string;
  valueSha256: string;
  dev: bigint;
  ino: bigint;
  dirDev: bigint;
  dirIno: bigint;
}>;
export interface NativePersistenceFence {
  assertUsable(): void;
  poison(cause: PersistenceCause): void;
  state(): Readonly<{
    cause: PersistenceCause | undefined;
    durable: NativeFrontier | undefined;
    revision: number;
    active: number;
  }>;
  /** Register the actual promise, never a timeout wrapper. Includes retry/compaction/navigation. */
  track<T>(operation: () => Promise<T>): Promise<T>;
  commitAtRest(): Promise<NativeFrontier>;
  requireComplete(): NativeFrontier;
}
export interface NativePersistenceOptions {
  /** Must seal admission synchronously. Notification exceptions cannot undo poison. */
  readonly onPoison: (cause: PersistenceCause) => void;
  /** Owner must independently join model/tool/Git/native callback work. */
  readonly isAtRest: () => boolean;
  /** Candidate only: acknowledgment must not publish history or a clean retirement receipt. */
  readonly acknowledge: (candidate: NativeFrontier) => Promise<void>;
}
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_LINE = 4 * 1024 * 1024;
const MAX_ENTRIES = 100_000;
const installed = new WeakSet<SessionManager>();
const digest = (bytes: string | Buffer) => createHash("sha256").update(bytes).digest("hex");
function error(cause: PersistenceCause): never {
  throw new NativePersistenceError(cause);
}

/** Strict v3 validation BEFORE native open: no migration, discovery, fallback, fork or rewrite.
 * The caller's durable active-generation custody must already exist. Resume authority is external;
 * this helper authenticates bytes, not whether an earlier crashed generation retired.
 */
export function openStrictNativeSession(path: string, sessionDir: string, cwd: string): SessionManager {
  const before = scan(path, sessionDir, false);
  const manager = SessionManager.open(path, sessionDir, cwd);
  const after = scan(path, sessionDir, false);
  if (
    !sameIdentity(before, after) ||
    before.wireSha256 !== after.wireSha256 ||
    memoryDigest(manager) !== after.valueSha256
  )
    error("history-mismatch");
  return manager;
}

/** Pi 0.84.2 only. Install on the securely seeded, reopened manager BEFORE createAgentSession.
 * Own descriptors are immutable; neither prototypes nor native JSONL bytes are patched.
 */
export function installNativePersistence(
  manager: SessionManager,
  options: NativePersistenceOptions,
): NativePersistenceFence {
  if (installed.has(manager) || !manager.isPersisted()) error("native-mutation");
  const path = manager.getSessionFile();
  if (!path) error("history-mismatch");
  const directory = manager.getSessionDir();
  let cause: PersistenceCause | undefined;
  let durable: NativeFrontier | undefined;
  let revision = 0;
  let active = 0;
  let mutating = false;
  let committing: Promise<NativeFrontier> | undefined;
  let expected = scan(path, directory, false);
  if (memoryDigest(manager) !== expected.valueSha256) error("history-mismatch");
  const identity = expected;
  // Only commitments are retained, never a second transcript/body ledger.
  const wire = createHash("sha256");
  const values = createHash("sha256");
  scan(path, directory, false, (bytes, parsed) => {
    wire.update(bytes);
    values.update(line(parsed));
  });
  const poison = (next: PersistenceCause) => {
    if (cause !== undefined) return;
    cause = next;
    try {
      options.onPoison(next);
    } catch {
      /* admission cell is already terminal */
    }
  };
  const assertUsable = () => {
    if (cause !== undefined) error(cause);
    if (manager.getSessionFile() !== path || manager.getSessionId() !== identity.nativeSessionId) {
      poison("history-mismatch");
      error("history-mismatch");
    }
  };
  const fail = (next: PersistenceCause): never => {
    poison(next);
    return error(cause ?? next);
  };
  const nativePersist = manager._persist;
  Object.defineProperty(manager, "_persist", {
    value: function (this: SessionManager, entry: SessionEntry) {
      assertUsable();
      if (this !== manager || !mutating || committing) fail("activity");
      let bytes: string;
      try {
        bytes = line(entry);
      } catch {
        return fail("serialization");
      }
      if (expected.bytes + Buffer.byteLength(bytes) > MAX_BYTES || expected.entries >= MAX_ENTRIES)
        fail("serialization");
      wire.update(bytes);
      values.update(bytes);
      revision++;
      expected = Object.freeze({
        ...expected,
        revision,
        entries: expected.entries + 1,
        lastAppendId: entry.id,
        bytes: expected.bytes + Buffer.byteLength(bytes),
        wireSha256: wire.copy().digest("hex"),
        valueSha256: values.copy().digest("hex"),
      });
      try {
        nativePersist.call(manager, entry);
      } catch {
        fail("native-write");
      }
    },
  });
  const names = [
    "appendMessage",
    "appendThinkingLevelChange",
    "appendModelChange",
    "appendCompaction",
    "appendCustomEntry",
    "appendSessionInfo",
    "appendCustomMessageEntry",
    "appendLabelChange",
    "branchWithSummary",
    "branch",
    "resetLeaf",
  ] as const;
  for (const name of names) {
    const native = manager[name];
    Object.defineProperty(manager, name, {
      value: function (this: SessionManager, ...args: unknown[]) {
        assertUsable();
        if (this !== manager || mutating || committing) fail("activity");
        const start = revision;
        mutating = true;
        try {
          const result = Reflect.apply(native, manager, args);
          const count = name === "branch" || name === "resetLeaf" ? 0 : 1;
          if (revision !== start + count) fail("native-mutation");
          return result;
        } catch {
          return fail(cause ?? "native-mutation");
        } finally {
          mutating = false;
        }
      },
    });
  }
  for (const name of ["setSessionFile", "newSession", "createBranchedSession"] as const)
    Object.defineProperty(manager, name, { value: () => error("native-mutation") });
  installed.add(manager);
  const atRest = () => {
    assertUsable();
    if (active || mutating || !options.isAtRest()) fail("activity");
  };
  const verifyMemory = () => {
    try {
      if (memoryDigest(manager) !== expected.valueSha256) fail("history-mismatch");
    } catch {
      fail(cause ?? "serialization");
    }
  };
  const requireComplete = () => {
    atRest();
    if (committing || !durable || durable.revision !== revision) error("activity");
    verifyMemory();
    try {
      const current = scan(path, directory, false);
      if (!sameIdentity(identity, current) || current.wireSha256 !== durable.wireSha256) fail("history-mismatch");
    } catch (caught) {
      fail(caught instanceof NativePersistenceError ? caught.causeCategory : "history-io");
    }
    return durable;
  };
  return Object.freeze({
    assertUsable,
    poison,
    state: () => Object.freeze({ cause, durable, revision, active }),
    track<T>(operation: () => Promise<T>): Promise<T> {
      assertUsable();
      if (committing) fail("activity");
      active++;
      // Register before executing arbitrary callbacks; retirement follows actual settlement.
      return Promise.resolve()
        .then(() => {
          assertUsable();
          return operation();
        })
        .finally(() => {
          active--;
        });
    },
    requireComplete,
    commitAtRest(): Promise<NativeFrontier> {
      if (committing) return committing;
      // Store before callbacks can reenter. This is a commit lock, not a refreshed close budget.
      committing = Promise.resolve()
        .then(async () => {
          atRest();
          verifyMemory();
          const start = revision;
          let candidate: NativeFrontier;
          try {
            candidate = Object.freeze({ ...scan(path, directory, true), revision });
            if (
              !sameIdentity(identity, candidate) ||
              candidate.bytes !== expected.bytes ||
              candidate.wireSha256 !== expected.wireSha256 ||
              candidate.valueSha256 !== expected.valueSha256
            )
              fail("history-mismatch");
            await options.acknowledge(candidate);
          } catch (caught) {
            return fail(caught instanceof NativePersistenceError ? caught.causeCategory : "owner-marker");
          }
          atRest();
          verifyMemory();
          if (revision !== start) fail("activity");
          // The asynchronous owner acknowledgment can run arbitrary code. Revalidate afterward.
          try {
            const current = scan(path, directory, true);
            if (!sameIdentity(candidate, current) || current.wireSha256 !== candidate.wireSha256)
              fail("history-mismatch");
          } catch (caught) {
            return fail(caught instanceof NativePersistenceError ? caught.causeCategory : "history-io");
          }
          durable = candidate; // publication is LAST; later successful fsync can never heal poison
          return candidate;
        })
        .catch((caught) => fail(caught instanceof NativePersistenceError ? caught.causeCategory : "history-io"))
        .finally(() => {
          committing = undefined;
        });
      return committing;
    },
  });
}

function line(value: unknown): string {
  const result = JSON.stringify(value);
  if (result === undefined || Buffer.byteLength(result) > MAX_LINE) error("serialization");
  return `${result}\n`;
}
function memoryDigest(manager: SessionManager): string {
  const hash = createHash("sha256");
  hash.update(line(manager.getHeader()));
  for (const entry of manager.getEntries()) hash.update(line(entry));
  return hash.digest("hex");
}
function sameIdentity(a: NativeFrontier, b: NativeFrontier): boolean {
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.dirDev === b.dirDev &&
    a.dirIno === b.dirIno &&
    a.nativeSessionId === b.nativeSessionId
  );
}
/** Bounded full scan; strict UTF-8, v3 header, append-order IDs/parents, no native tolerant parser. */
function scan(
  path: string,
  directory: string,
  sync: boolean,
  consume?: (bytes: Buffer, value: unknown) => void,
): NativeFrontier {
  let fd: number | undefined;
  let dir: number | undefined;
  let failure: PersistenceCause | undefined;
  let result: NativeFrontier | undefined;
  try {
    if (
      resolve(directory) !== realpathSync(directory) ||
      dirname(resolve(path)) !== resolve(directory) ||
      realpathSync(path) !== resolve(path)
    )
      error("history-io");
    dir = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const ds = fstatSync(dir, { bigint: true });
    const st = fstatSync(fd, { bigint: true });
    if (
      !ds.isDirectory() ||
      !st.isFile() ||
      st.nlink !== 1n ||
      (st.mode & 0o077n) !== 0n ||
      st.size < 1n ||
      st.size > BigInt(MAX_BYTES)
    )
      error("history-io");
    const bytes = Buffer.alloc(Number(st.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, Math.min(65536, bytes.length - offset), offset);
      if (!count) error("history-io");
      offset += count;
    }
    if (bytes.at(-1) !== 10) error("history-mismatch");
    const ids = new Set<string>();
    let lastAppendId: string | null = null;
    let nativeSessionId = "";
    const hash = createHash("sha256");
    let begin = 0;
    let index = 0;
    while (begin < bytes.length) {
      const end = bytes.indexOf(10, begin);
      if (end < 0 || end - begin > MAX_LINE || index > MAX_ENTRIES) error("history-mismatch");
      const raw = bytes.subarray(begin, end + 1);
      const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
      if (!value || typeof value !== "object" || Array.isArray(value)) error("history-mismatch");
      if (index === 0) {
        if (
          value.type !== "session" ||
          value.version !== 3 ||
          typeof value.id !== "string" ||
          !value.id ||
          typeof value.cwd !== "string" ||
          typeof value.timestamp !== "string"
        )
          error("history-mismatch");
        nativeSessionId = value.id;
      } else {
        if (
          typeof value.type !== "string" ||
          value.type === "session" ||
          typeof value.id !== "string" ||
          !/^(?:[a-f0-9]{8}|[a-f0-9-]{36})$/.test(value.id) ||
          ids.has(value.id) ||
          (value.parentId !== null && !ids.has(value.parentId))
        )
          error("history-mismatch");
        ids.add(value.id);
        lastAppendId = value.id;
      }
      hash.update(line(value));
      consume?.(raw, value);
      begin = end + 1;
      index++;
    }
    const after = fstatSync(fd, { bigint: true });
    const current = lstatSync(path, { bigint: true });
    const currentDir = lstatSync(directory, { bigint: true });
    if (
      st.dev !== current.dev ||
      st.ino !== current.ino ||
      st.size !== after.size ||
      st.mtimeNs !== after.mtimeNs ||
      st.ctimeNs !== after.ctimeNs ||
      currentDir.dev !== ds.dev ||
      currentDir.ino !== ds.ino
    )
      error("history-mismatch");
    if (sync) {
      try {
        fsyncSync(fd);
      } catch {
        error("file-sync");
      }
      try {
        fsyncSync(dir);
      } catch {
        error("directory-sync");
      }
    }
    result = Object.freeze({
      nativeSessionId,
      revision: 0,
      entries: ids.size,
      lastAppendId,
      bytes: bytes.length,
      wireSha256: digest(bytes),
      valueSha256: hash.digest("hex"),
      dev: st.dev,
      ino: st.ino,
      dirDev: ds.dev,
      dirIno: ds.ino,
    });
  } catch (caught) {
    failure = caught instanceof NativePersistenceError ? caught.causeCategory : "history-io";
  } finally {
    for (const descriptor of [fd, dir])
      if (descriptor !== undefined) {
        try {
          closeSync(descriptor);
        } catch {
          failure ??= "close";
        }
      }
  }
  if (failure || !result) error(failure ?? "history-io");
  return result;
}

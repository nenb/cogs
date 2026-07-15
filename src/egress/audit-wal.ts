import { constants } from "node:fs";
import { open as fsOpen, lstat, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

const version = "cogs.egress-intent/v1alpha1";
const maxWalBytes = 1024 * 1024;
const maxWalRecords = 10_000;
const maxWalRecordBytes = 4096;
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const methods = new Set(["GET", "POST"]);
type Method = "GET" | "POST";
const keys =
  "version sequence intent_id timestamp_ms session_id integration_id route_id method credential_required".split(
    " ",
  ) as readonly (keyof EgressAuditWalRecord)[];
export interface EgressAuditWalRecord {
  readonly version: typeof version;
  readonly sequence: number;
  readonly intent_id: string;
  readonly timestamp_ms: number;
  readonly session_id: string;
  readonly integration_id: string;
  readonly route_id: string;
  readonly method: Method;
  readonly credential_required: boolean;
}
export type EgressAuditWalAppendInput = Pick<
  EgressAuditWalRecord,
  "session_id" | "integration_id" | "route_id" | "method" | "credential_required"
>;
export interface EgressAuditWal {
  readonly ready: boolean;
  readonly records: readonly EgressAuditWalRecord[];
  append(input: EgressAuditWalAppendInput, signal?: AbortSignal): Promise<EgressAuditWalRecord>;
  close(): Promise<void>;
}
export interface EgressAuditWalOptions {
  readonly path: string;
  readonly maxBytes: number;
  readonly maxRecords: number;
  readonly maxRecordBytes: number;
  readonly nowMs?: () => number;
  readonly newIntentId?: () => string;
}
export interface CogsWalStat {
  readonly kind: "file" | "directory" | "other";
  readonly mode: number;
  readonly nlink: number;
  readonly uid: number;
  readonly size: number;
  readonly symlink: boolean;
  readonly dev: number;
  readonly ino: number;
}
interface WalFile {
  stat(): Promise<CogsWalStat>;
  read(position: number, length: number): Promise<Buffer>;
  write(buffer: Buffer, offset: number, length: number): Promise<number>;
  sync(): Promise<void>;
  close(): Promise<void>;
}
export interface EgressAuditWalDeps {
  pathStat(path: string): Promise<CogsWalStat>;
  realpath(path: string): Promise<string>;
  openFile(path: string, flags: number, mode: number): Promise<WalFile>;
  syncDirectory(path: string): Promise<void>;
  euid(): number;
}
export class EgressAuditWalError extends Error {
  public readonly code = "COGS_EGRESS_AUDIT_WAL_FAILED";
  public constructor() {
    super("egress audit WAL unavailable");
    this.name = "EgressAuditWalError";
  }
}

const defaultDeps: EgressAuditWalDeps = {
  pathStat: async (path) => toStat(await lstat(path)),
  realpath,
  openFile: async (path, flags, mode) => {
    const handle = await fsOpen(path, flags, mode);
    return {
      stat: async () => toStat(await handle.stat()),
      read: async (position, length) => {
        const b = Buffer.alloc(length);
        const r = await handle.read(b, 0, length, position);
        return b.subarray(0, r.bytesRead);
      },
      write: async (buffer, offset, length) => (await handle.write(buffer, offset, length)).bytesWritten,
      sync: () => handle.sync(),
      close: () => handle.close(),
    };
  },
  syncDirectory: async (path) => {
    if (constants.O_NOFOLLOW === undefined || constants.O_DIRECTORY === undefined)
      throw new Error("directory flags unavailable");
    const handle = await fsOpen(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  },

  euid: () => process.geteuid?.() ?? process.getuid?.() ?? -1,
};

export async function openEgressAuditWal(options: EgressAuditWalOptions): Promise<EgressAuditWal> {
  return openEgressAuditWalWithDeps(options, defaultDeps);
}
export async function openEgressAuditWalWithDeps(
  options: EgressAuditWalOptions,
  deps: EgressAuditWalDeps,
): Promise<EgressAuditWal> {
  let file: WalFile | undefined;
  try {
    const captured = Object.freeze({ ...options });
    validateOptions(captured);
    if (constants.O_NOFOLLOW === undefined) throw new Error("nofollow unavailable");
    const path = resolve(captured.path);
    if (!isAbsolute(captured.path) || path !== captured.path) throw new Error("bad path");
    const parent = dirname(path);
    const euid = integer(deps.euid(), 0);
    await verifyParent(parent, deps, euid);
    file = await deps.openFile(
      path,
      constants.O_CREAT | constants.O_RDWR | constants.O_APPEND | constants.O_NOFOLLOW,
      0o600,
    );
    const stat = await verifyFile(await file.stat(), euid);
    await deps.syncDirectory(parent);
    const records = await recover(file, stat.size, captured.maxBytes, captured.maxRecords, captured.maxRecordBytes);
    return new Wal(file, stat, captured, records, stat.size, euid);
  } catch {
    if (file !== undefined) await file.close().catch(() => undefined);
    throw new EgressAuditWalError();
  }
}

class Wal implements EgressAuditWal {
  readonly #ids = new Set<string>();
  readonly #file: WalFile;
  readonly #id: CogsWalStat;
  readonly #options: EgressAuditWalOptions;
  readonly #current: EgressAuditWalRecord[];
  readonly #euid: number;
  #bytes: number;
  #next: Promise<unknown> = Promise.resolve();
  #poisoned = false;
  #closing = false;
  #closed = false;
  #closePromise: Promise<void> | undefined;
  public constructor(
    file: WalFile,
    id: CogsWalStat,
    options: EgressAuditWalOptions,
    current: EgressAuditWalRecord[],
    bytes: number,
    euid: number,
  ) {
    this.#file = file;
    this.#id = id;
    this.#options = options;
    this.#current = current;
    this.#bytes = bytes;
    this.#euid = euid;
    for (const r of current) this.#ids.add(r.intent_id);
  }
  public get ready(): boolean {
    return !this.#poisoned && !this.#closing && !this.#closed;
  }
  public get records(): readonly EgressAuditWalRecord[] {
    return deepFreeze(this.#current.map((r) => ({ ...r })));
  }
  public append(input: EgressAuditWalAppendInput, signal?: AbortSignal): Promise<EgressAuditWalRecord> {
    let captured: EgressAuditWalAppendInput;
    try {
      captured = {
        session_id: input.session_id,
        integration_id: input.integration_id,
        route_id: input.route_id,
        method: input.method,
        credential_required: input.credential_required,
      };
    } catch {
      return Promise.reject(new EgressAuditWalError());
    }
    const run = this.#next.then(() => this.#append(captured, signal));
    this.#next = run.catch(() => undefined);
    return run;
  }
  async #append(input: EgressAuditWalAppendInput, signal?: AbortSignal): Promise<EgressAuditWalRecord> {
    if (signal?.aborted) throw new EgressAuditWalError();
    try {
      if (!this.ready) throw new Error("unready");
      const record = validateRecord({
        version,
        sequence: this.#current.length,
        intent_id: validOpaque(this.#options.newIntentId?.() ?? crypto.randomUUID()),
        timestamp_ms: timestamp(this.#options.nowMs?.() ?? Date.now()),
        session_id: input.session_id,
        integration_id: input.integration_id,
        route_id: input.route_id,
        method: input.method,
        credential_required: input.credential_required,
      });
      if (this.#ids.has(record.intent_id)) throw new Error("duplicate intent");
      const line = Buffer.from(`${canonical(record)}\n`);
      if (
        line.length > this.#options.maxRecordBytes ||
        this.#current.length >= this.#options.maxRecords ||
        this.#bytes + line.length > this.#options.maxBytes
      )
        throw new Error("full");
      await writeAll(this.#file, line);
      await this.#file.sync();
      const stat = await verifyFile(await this.#file.stat(), this.#euid, this.#id, this.#bytes + line.length);
      this.#bytes = stat.size;
      this.#current.push(record);
      this.#ids.add(record.intent_id);
      return deepFreeze({ ...record });
    } catch {
      this.#poisoned = true;
      throw new EgressAuditWalError();
    }
  }
  public close(): Promise<void> {
    this.#closePromise ??= this.#close();
    return this.#closePromise;
  }
  async #close(): Promise<void> {
    if (this.#closed) return;
    this.#closing = true;
    await this.#next.catch(() => undefined);
    let failed = false;
    try {
      await this.#file.sync();
    } catch {
      failed = true;
    }
    try {
      await this.#file.close();
    } catch {
      failed = true;
    }
    this.#closed = true;
    if (failed) {
      this.#poisoned = true;
      throw new EgressAuditWalError();
    }
  }
}

async function recover(file: WalFile, size: number, maxBytes: number, maxRecords: number, maxRecordBytes: number) {
  if (size > maxBytes) throw new Error("too large");
  const chunks: Buffer[] = [];
  let total = 0;
  while (total <= maxBytes) {
    const want = Math.min(64 * 1024, maxBytes + 1 - total);
    const chunk = await file.read(total, want);
    if (!Number.isSafeInteger(chunk.length) || chunk.length < 0 || chunk.length > want) throw new Error("bad read");
    if (chunk.length === 0) break;
    chunks.push(chunk);
    total += chunk.length;
  }
  if (total !== size || total > maxBytes) throw new Error("bad size");
  const text = Buffer.concat(chunks, total).toString("utf8");
  if (text.length > 0 && !text.endsWith("\n")) throw new Error("partial");
  const lines = text.length === 0 ? [] : text.slice(0, -1).split("\n");
  if (lines.length > maxRecords) throw new Error("too many");
  const seen = new Set<string>();
  return lines.map((line, sequence) => {
    if (Buffer.byteLength(`${line}\n`) > maxRecordBytes) throw new Error("record too large");
    const r = validateRecord(JSON.parse(line) as unknown);
    if (r.sequence !== sequence || seen.has(r.intent_id)) throw new Error("bad sequence");
    seen.add(r.intent_id);
    return r;
  });
}
function validateRecord(value: unknown): EgressAuditWalRecord {
  const r = object(value);
  exactKeys(r);
  if (r.version !== version) throw new Error("bad version");
  return deepFreeze({
    version,
    sequence: integer(r.sequence, 0),
    intent_id: validOpaque(r.intent_id),
    timestamp_ms: timestamp(r.timestamp_ms),
    session_id: validOpaque(r.session_id),
    integration_id: validOpaque(r.integration_id),
    route_id: validOpaque(r.route_id),
    method: method(r.method),
    credential_required: bool(r.credential_required),
  });
}
function canonical(r: EgressAuditWalRecord): string {
  return `{${keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(r[k])}`).join(",")}}`;
}
async function writeAll(file: WalFile, buffer: Buffer): Promise<void> {
  for (let o = 0; o < buffer.length; ) {
    const n = await file.write(buffer, o, buffer.length - o);
    if (!Number.isSafeInteger(n) || n < 1 || n > buffer.length - o) throw new Error("short write");
    o += n;
  }
}
function validateOptions(o: EgressAuditWalOptions): void {
  bound(o.maxBytes, 1, maxWalBytes);
  bound(o.maxRecords, 1, maxWalRecords);
  bound(o.maxRecordBytes, 1, maxWalRecordBytes);
  if (o.maxRecordBytes > o.maxBytes) throw new Error("bad bounds");
}
async function verifyParent(path: string, deps: EgressAuditWalDeps, euid: number): Promise<void> {
  const s = await deps.pathStat(path);
  if (
    s.kind !== "directory" ||
    s.symlink ||
    (s.mode & 0o777) !== 0o700 ||
    s.uid !== euid ||
    (await deps.realpath(path)) !== path
  )
    throw new Error("bad parent");
}
async function verifyFile(
  stat: CogsWalStat,
  euid: number,
  id?: Pick<CogsWalStat, "dev" | "ino">,
  size?: number,
): Promise<CogsWalStat> {
  if (
    stat.kind !== "file" ||
    stat.symlink ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== 0o600 ||
    stat.uid !== euid ||
    (id && (stat.dev !== id.dev || stat.ino !== id.ino)) ||
    (size !== undefined && stat.size !== size)
  )
    throw new Error("bad file");
  return stat;
}
function toStat(s: import("node:fs").Stats): CogsWalStat {
  return {
    kind: s.isFile() ? "file" : s.isDirectory() ? "directory" : "other",
    mode: s.mode,
    nlink: s.nlink,
    uid: s.uid,
    size: s.size,
    dev: s.dev,
    ino: s.ino,
    symlink: s.isSymbolicLink(),
  };
}
function object(v: unknown): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("bad object");
  const p = Object.getPrototypeOf(v);
  if (p !== Object.prototype && p !== null) throw new Error("bad prototype");
  return v as Record<string, unknown>;
}
function exactKeys(r: Record<string, unknown>): void {
  const present = Object.keys(r).sort();
  const expected = [...keys].sort();
  if (present.length !== expected.length || present.some((k, i) => k !== expected[i])) throw new Error("bad keys");
}
function validOpaque(v: unknown): string {
  if (typeof v !== "string" || !opaque.test(v)) throw new Error("bad opaque");
  return v;
}
function timestamp(v: unknown): number {
  if (!Number.isSafeInteger(v) || (v as number) < 0) throw new Error("bad timestamp");
  return v as number;
}
function integer(v: unknown, min: number): number {
  if (!Number.isSafeInteger(v) || (v as number) < min) throw new Error("bad integer");
  return v as number;
}
function bound(v: unknown, min: number, max: number): number {
  const n = integer(v, min);
  if (n > max) throw new Error("bad bound");
  return n;
}
function method(v: unknown): Method {
  if (typeof v !== "string" || !methods.has(v)) throw new Error("bad method");
  return v as Method;
}
function bool(v: unknown): boolean {
  if (typeof v !== "boolean") throw new Error("bad boolean");
  return v;
}
function deepFreeze<T>(v: T): T {
  if (typeof v === "object" && v !== null && !Object.isFrozen(v)) {
    Object.freeze(v);
    for (const n of Object.values(v)) deepFreeze(n);
  }
  return v;
}

import { constants } from "node:fs";
import { link, lstat, open, realpath, rm, unlink } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { type LauncherProfile, normalizeProfile } from "./contract.ts";

export const cliOperations = [
  "create",
  "reset",
  "status",
  "start",
  "run",
  "abort",
  "history",
  "export",
  "shutdown",
  "destroy",
  "smoke",
  "s3-09",
] as const;
export type CliOperation = (typeof cliOperations)[number];
export type CliRequest = Readonly<{
  op: CliOperation;
  profile: LauncherProfile;
  state: string;
  timeoutMs?: number;
  json?: true;
  promptFile?: string;
  after?: string;
  limit?: number;
  out?: string;
}>;

const opSet = new Set<string>(cliOperations);
const stateRe = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const relRe = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+){0,15}$/u;
const cursorRe = /^[A-Za-z0-9_-]{1,768}\.[A-Za-z0-9_-]{32,256}$/u;
const flagSets: Record<CliOperation, readonly string[]> = Object.freeze({
  create: ["timeout-ms"],
  reset: ["timeout-ms"],
  status: ["timeout-ms", "json"],
  start: ["timeout-ms"],
  run: ["timeout-ms", "prompt-file"],
  abort: ["timeout-ms"],
  history: ["timeout-ms", "after", "limit"],
  export: ["timeout-ms", "out"],
  shutdown: ["timeout-ms"],
  destroy: ["timeout-ms"],
  smoke: ["timeout-ms"],
  "s3-09": ["timeout-ms"],
});

export function parseLauncherArgs(argv: readonly string[]): CliRequest {
  const args = snapshotArgv(argv);
  if (args[0] !== "--profile" || args[2] !== "--state") throw new Error("invalid launcher arguments");
  const profile = normalizeProfile(args[1]);
  const state = args[3];
  const op = args[4];
  if (!state || !stateRe.test(state) || !op || !opSet.has(op)) throw new Error("invalid launcher arguments");
  const allowed = new Set(flagSets[op as CliOperation]);
  const seen = new Map<string, string | true>();
  for (let i = 5; i < args.length; i += 1) {
    const item = args[i];
    if (!item?.startsWith("--") || item === "--" || item.includes("=")) throw new Error("invalid launcher arguments");
    const key = item.slice(2);
    if (!allowed.has(key) || seen.has(key)) throw new Error("invalid launcher arguments");
    if (key === "json") {
      seen.set(key, true);
      continue;
    }
    const value = args[++i];
    if (!value || value.startsWith("--")) throw new Error("invalid launcher arguments");
    seen.set(key, value);
  }
  const out: Record<string, unknown> = { op, profile, state };
  if (seen.has("timeout-ms")) out.timeoutMs = parseTimeout(req(seen, "timeout-ms"));
  if (seen.get("json") === true) out.json = true;
  if (seen.has("prompt-file")) out.promptFile = parseRel(req(seen, "prompt-file"));
  if (seen.has("after")) {
    const after = req(seen, "after");
    if (after.length > 1024 || !cursorRe.test(after)) throw new Error("invalid launcher arguments");
    out.after = after;
  }
  if (seen.has("limit")) out.limit = parseLimit(req(seen, "limit"));
  if (seen.has("out")) out.out = parseRel(req(seen, "out"));
  if (op === "run" && !out.promptFile) throw new Error("invalid launcher arguments");
  if (op === "export" && !out.out) throw new Error("invalid launcher arguments");
  return Object.freeze(out) as CliRequest;
}

export async function readPromptFile(repoRoot: string, relPath: string, maxBytes = 16 * 1024): Promise<string> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 16 * 1024)
    throw new Error("invalid launcher prompt");
  const root = await ownedDir(repoRoot, 0o777);
  if (root !== repoRoot) throw new Error("invalid launcher prompt");
  const path = await contained(root, parseRel(relPath));
  await validateParents(root, dirname(path), 0o777);
  const before = await lstat(path);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (
      before.dev !== stat.dev ||
      before.ino !== stat.ino ||
      !stat.isFile() ||
      stat.nlink !== 1 ||
      (stat.mode & 0o022) !== 0 ||
      stat.size < 1 ||
      stat.size > maxBytes
    )
      throw new Error("invalid launcher prompt");
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid())
      throw new Error("invalid launcher prompt");
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const buf = Buffer.alloc(Math.min(4096, maxBytes + 1 - total));
      const read = await handle.read(buf, 0, buf.length, null);
      if (read.bytesRead === 0) break;
      total += read.bytesRead;
      if (total > maxBytes) throw new Error("invalid launcher prompt");
      chunks.push(buf.subarray(0, read.bytesRead));
    }
    const after = await handle.stat();
    if (
      after.dev !== stat.dev ||
      after.ino !== stat.ino ||
      !after.isFile() ||
      after.nlink !== 1 ||
      (after.mode & 0o022) !== 0 ||
      after.size !== stat.size ||
      total !== after.size ||
      after.size > maxBytes ||
      (typeof process.geteuid === "function" && after.uid !== process.geteuid())
    )
      throw new Error("invalid launcher prompt");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
    if (text.length < 1 || text.length > 8192 || hasBadPromptControl(text)) throw new Error("invalid launcher prompt");
    await handle.close();
    return text;
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

export async function writeSensitiveExport(
  root: string,
  relPath: string,
  value: unknown,
  maxBytes = 1024 * 1024,
): Promise<string> {
  const base = await ownedDir(root, 0o700);
  if (base !== root) throw new Error("invalid launcher export");
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 1024 * 1024)
    throw new Error("invalid launcher export");
  const path = await contained(base, parseRel(relPath));
  await validateParents(base, dirname(path), 0o700);
  const json = canonicalSensitive(value, maxBytes);
  const bytes = Buffer.from(json);
  if (bytes.length < 1 || bytes.length > maxBytes) throw new Error("invalid launcher export");
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  const handle = await open(
    tmp,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(bytes);
    await handle.sync();
    const tempStat = await handle.stat();
    if (
      !tempStat.isFile() ||
      (tempStat.mode & 0o777) !== 0o600 ||
      tempStat.nlink !== 1 ||
      tempStat.size !== bytes.length ||
      (typeof process.geteuid === "function" && tempStat.uid !== process.geteuid())
    )
      throw new Error("invalid launcher export");
    await handle.close();
    await lstat(path).then(
      () => {
        throw new Error("invalid launcher export");
      },
      (e: NodeJS.ErrnoException) => {
        if (e.code !== "ENOENT") throw e;
      },
    );
    await link(tmp, path);
    await unlink(tmp);
    const finalStat = await lstat(path);
    if (
      finalStat.dev !== tempStat.dev ||
      finalStat.ino !== tempStat.ino ||
      !finalStat.isFile() ||
      (finalStat.mode & 0o777) !== 0o600 ||
      finalStat.nlink !== 1 ||
      finalStat.size !== bytes.length ||
      (typeof process.geteuid === "function" && finalStat.uid !== process.geteuid())
    )
      throw new Error("invalid launcher export");
    const parent = await open(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      await parent.sync();
      await parent.close();
    } catch (error) {
      await parent.close().catch(() => undefined);
      throw error;
    }
    return path;
  } catch (error) {
    await handle.close().catch(() => undefined);
    await rm(tmp, { force: true }).catch(() => undefined);
    throw error;
  }
}

function snapshotArgv(argv: readonly string[]): string[] {
  if (!Array.isArray(argv) || Object.getPrototypeOf(argv) !== Array.prototype)
    throw new Error("invalid launcher arguments");
  const d = Object.getOwnPropertyDescriptors(argv);
  const len = Object.getOwnPropertyDescriptor(argv, "length")?.value;
  if (typeof len !== "number" || !Number.isSafeInteger(len) || len < 5 || len > 32)
    throw new Error("invalid launcher arguments");
  const out: string[] = [];
  for (let i = 0; i < len; i += 1) {
    const v = d[String(i)];
    if (!v || !("value" in v) || v.enumerable !== true || typeof v.value !== "string")
      throw new Error("invalid launcher arguments");
    out.push(v.value);
  }
  if (Reflect.ownKeys(d).some((k) => typeof k !== "string" || (k !== "length" && !/^\d+$/u.test(k))))
    throw new Error("invalid launcher arguments");
  return out;
}
function req(map: Map<string, string | true>, key: string): string {
  const value = map.get(key);
  if (typeof value !== "string") throw new Error("invalid launcher arguments");
  return value;
}
function parseTimeout(value: string): number {
  if (!/^[1-9]\d{0,5}$/u.test(value)) throw new Error("invalid launcher arguments");
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n > 900_000) throw new Error("invalid launcher arguments");
  return n;
}
function parseLimit(value: string): number {
  if (!/^[1-9]\d?$/u.test(value) && value !== "100") throw new Error("invalid launcher arguments");
  return Number(value);
}
function parseRel(value: string): string {
  if (!relRe.test(value) || value.includes("..")) throw new Error("invalid launcher arguments");
  return value;
}
async function ownedDir(path: string, mode: number): Promise<string> {
  const real = await realpath(path);
  const stat = await lstat(real);
  if (
    !stat.isDirectory() ||
    (mode !== 0o777 && (stat.mode & 0o777) !== mode) ||
    (typeof process.geteuid === "function" && stat.uid !== process.geteuid())
  )
    throw new Error("invalid launcher path");
  if ((stat.mode & 0o022) !== 0) throw new Error("invalid launcher path");
  return real;
}
async function contained(root: string, relPath: string): Promise<string> {
  const path = resolve(root, relPath);
  const rel = relative(root, path);
  if (rel.startsWith("..") || rel.includes(`..${sep}`) || path === root) throw new Error("invalid launcher path");
  return path;
}
async function validateParents(root: string, parent: string, mode: number): Promise<void> {
  if (!parent.startsWith(`${root}${sep}`) && parent !== root) throw new Error("invalid launcher path");
  for (let cur = parent; cur !== root; cur = dirname(cur)) {
    if ((await realpath(cur)) !== cur) throw new Error("invalid launcher path");
    await ownedDir(cur, mode);
  }
}
function canonicalSensitive(value: unknown, maxBytes: number): string {
  const clean = json(value, new WeakSet(), 0, { n: 0, bytes: 0, maxBytes });
  if (!clean || typeof clean !== "object" || Array.isArray(clean)) throw new Error("invalid launcher export");
  const object = clean as Record<string, unknown>;
  if (
    Object.keys(object).sort().join(",") !== "bundle,sensitive,version" ||
    object.version !== "cogs.export-response/v1alpha1" ||
    object.sensitive !== true
  )
    throw new Error("invalid launcher export");
  return JSON.stringify(clean);
}
function json(
  value: unknown,
  seen: WeakSet<object>,
  depth: number,
  count: { n: number; bytes: number; maxBytes: number },
): unknown {
  count.n += 1;
  if (depth > 32 || count.n > 4096) throw new Error("invalid launcher export");
  if (value === null) return budget(count, 4, null);
  if (typeof value === "string") return budget(count, Buffer.byteLength(value) + 2, value);
  if (typeof value === "boolean") return budget(count, value ? 4 : 5, value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("invalid launcher export");
    return budget(count, Buffer.byteLength(String(value)), value);
  }
  if (!value || typeof value !== "object" || seen.has(value)) throw new Error("invalid launcher export");
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length !== 0)
        throw new Error("invalid launcher export");
      const length = Object.getOwnPropertyDescriptor(value, "length")?.value;
      if (!Number.isSafeInteger(length) || length < 0 || length > 1000) throw new Error("invalid launcher export");
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const keys = Reflect.ownKeys(descriptors).filter((key) => key !== "length");
      if (
        keys.length !== length ||
        keys.some((key) => typeof key !== "string" || !/^\d+$/u.test(key) || Number(key) >= length)
      )
        throw new Error("invalid launcher export");
      budget(count, 2 + Math.max(0, length - 1), undefined);
      const out: unknown[] = [];
      for (let i = 0; i < length; i += 1) {
        const d = descriptors[String(i)];
        if (!d || !("value" in d) || d.enumerable !== true) throw new Error("invalid launcher export");
        out.push(json(d.value, seen, depth + 1, count));
      }
      return out;
    }
    const proto = Object.getPrototypeOf(value);
    if ((proto !== Object.prototype && proto !== null) || Object.getOwnPropertySymbols(value).length !== 0)
      throw new Error("invalid launcher export");
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== "string")) throw new Error("invalid launcher export");
    const names = (keys as string[]).sort();
    budget(count, 2 + Math.max(0, names.length - 1), undefined);
    const out = Object.create(null) as Record<string, unknown>;
    for (const key of names) {
      if (key === "__proto__" || key === "prototype" || key === "constructor")
        throw new Error("invalid launcher export");
      const d = descriptors[key];
      if (!d || !("value" in d) || d.enumerable !== true || d.value === undefined)
        throw new Error("invalid launcher export");
      if (Buffer.byteLength(key) + 1 > count.maxBytes - count.bytes) throw new Error("invalid launcher export");
      budget(count, Buffer.byteLength(JSON.stringify(key)) + 1, undefined);
      out[key] = json(d.value, seen, depth + 1, count);
    }
    return out;
  } finally {
    seen.delete(value);
  }
}
function budget<T>(count: { bytes: number; maxBytes: number }, bytes: number, value: T): T {
  count.bytes += bytes;
  if (count.bytes > count.maxBytes) throw new Error("invalid launcher export");
  return value;
}
function hasBadPromptControl(value: string): boolean {
  for (const c of value) {
    const code = c.codePointAt(0) ?? 0;
    if ((code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) || code === 0x7f) return true;
  }
  return false;
}

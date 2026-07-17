import { randomBytes } from "node:crypto";
import posix from "node:path/posix";
import { type CogsSftpPort, CogsSftpStatusError } from "../ssh/connection.ts";
import type { CogsSkillBundleHandle } from "./bundle.ts";
import { verifyCogsSkillBundle } from "./bundle.ts";

export interface CogsSftpMaterializedBundle {
  readonly digest: `sha256:${string}`;
  readonly guestRoot: "/shared/skills" | "/user/skills";
  readonly guestSubtree: string;
  readonly bundlePath: string;
  readonly files: readonly { readonly bundlePath: string; readonly guestPath: string; readonly bytes: number }[];
  readonly fileCount: number;
  readonly byteCount: number;
  readonly readOnlyEnforced: false;
}

export class CogsSkillSftpMaterializerError extends Error {
  public readonly code = "COGS_SKILL_SFTP_MATERIALIZATION_FAILED";
  public constructor() {
    super("invalid skill SFTP materialization");
    this.name = "CogsSkillSftpMaterializerError";
  }
}

type CleanupOwnership = {
  readonly root: string;
  readonly files: readonly string[];
  readonly dirs: readonly string[];
  cleaned: boolean;
};
const CLEANUP_OWNERS = new WeakMap<CogsSftpMaterializedBundle, CleanupOwnership>();

type RequiredSftp = CogsSftpPort & {
  mkdir: (path: string, mode: number, signal: AbortSignal) => Promise<void>;
  setMode: (path: string, mode: number, signal: AbortSignal) => Promise<void>;
  rmdir: (path: string, signal: AbortSignal) => Promise<void>;
};

export async function materializeCogsSkillBundleToGuest(input: {
  readonly sftp: CogsSftpPort;
  readonly bundle: CogsSkillBundleHandle;
  readonly guestRoot: "/shared/skills" | "/user/skills";
  readonly signal: AbortSignal;
}): Promise<CogsSftpMaterializedBundle> {
  let sftp: RequiredSftp | undefined;
  let signal: AbortSignal | undefined;
  let staging = "";
  let finalRoot = "";
  const dirs: string[] = [];
  const files: string[] = [];
  let finalPublished = false;
  try {
    sftp = requireDirectorySftp(input.sftp);
    signal = validateSignal(input.signal);
    const root = validateGuestRoot(input.guestRoot);
    const bundle = verifyCogsSkillBundle(input.bundle.copyBytes());
    if (bundle.digest !== input.bundle.digest) throw new CogsSkillSftpMaterializerError();
    if (bundle.files.some((file) => file.path === ".cogs-skills-bundle.json"))
      throw new CogsSkillSftpMaterializerError();
    const digestHex = bundle.digest.slice("sha256:".length);
    staging = `${root}/.cogs-stage-${digestHex}-${randomBytes(12).toString("hex")}`;
    finalRoot = `${root}/${digestHex}`;
    throwIfAborted(signal);
    await assertRootDirectory(sftp, root, signal);
    await assertMissing(sftp, finalRoot, signal);
    await mkdirTracked(sftp, staging, 0o700, dirs, signal);
    dirs.pop();
    await writeOne(sftp, `${staging}/.cogs-skills-bundle.json`, bundle.copyBytes(), 0o444, files, signal);
    const stagedBundle = await readFile(sftp, `${staging}/.cogs-skills-bundle.json`, bundle.byteLength, signal);
    const verified = verifyCogsSkillBundle(stagedBundle);
    if (verified.digest !== bundle.digest) throw new CogsSkillSftpMaterializerError();
    const materialized: { bundlePath: string; guestPath: string; bytes: number }[] = [];
    for (const file of bundle.files) {
      const target = `${staging}/${file.path}`;
      await ensureParentDirs(sftp, staging, file.path, dirs, signal);
      const bytes = bundle.copyFile(file.path);
      if (bytes.length !== file.size) throw new CogsSkillSftpMaterializerError();
      await writeOne(sftp, target, bytes, file.executable ? 0o555 : 0o444, files, signal);
      materialized.push(
        Object.freeze({ bundlePath: file.path, guestPath: `${finalRoot}/${file.path}`, bytes: bytes.length }),
      );
    }
    await assertMissing(sftp, finalRoot, signal);
    await sftp.posixRename(staging, finalRoot, signal);
    finalPublished = true;
    await sftp.setMode(finalRoot, 0o555, signal);
    for (const dir of [...dirs].reverse()) await sftp.setMode(dir.replace(staging, finalRoot), 0o555, signal);
    const finalBundle = await readFile(sftp, `${finalRoot}/.cogs-skills-bundle.json`, bundle.byteLength, signal);
    if (verifyCogsSkillBundle(finalBundle).digest !== bundle.digest) throw new CogsSkillSftpMaterializerError();
    const result = Object.freeze({
      digest: bundle.digest,
      guestRoot: root,
      guestSubtree: finalRoot,
      bundlePath: `${finalRoot}/.cogs-skills-bundle.json`,
      files: Object.freeze(materialized),
      fileCount: bundle.fileCount,
      byteCount: bundle.decodedByteLength,
      readOnlyEnforced: false,
    });
    CLEANUP_OWNERS.set(result, {
      root: finalRoot,
      files: Object.freeze(files.map((p) => p.replace(staging, finalRoot))),
      dirs: Object.freeze(dirs.map((p) => p.replace(staging, finalRoot))),
      cleaned: false,
    });
    return result;
  } catch (error) {
    if (sftp !== undefined && (finalPublished ? finalRoot : staging) !== "") {
      const cleanupSignal = new AbortController().signal;
      await cleanupKnown(
        sftp,
        finalPublished ? finalRoot : staging,
        files.map((p) => (finalPublished ? p.replace(staging, finalRoot) : p)),
        dirs.map((p) => (finalPublished ? p.replace(staging, finalRoot) : p)),
        cleanupSignal,
      ).catch(() => {
        throw new CogsSkillSftpMaterializerError();
      });
    }
    if (error instanceof CogsSkillSftpMaterializerError) throw error;
    throw new CogsSkillSftpMaterializerError();
  }
}

function requireDirectorySftp(port: CogsSftpPort): RequiredSftp {
  if (port.mkdir === undefined || port.setMode === undefined || port.rmdir === undefined)
    throw new CogsSkillSftpMaterializerError();
  return port as RequiredSftp;
}

async function assertRootDirectory(sftp: CogsSftpPort, path: string, signal: AbortSignal): Promise<void> {
  await assertDirectory(sftp, path, signal);
  if ((await sftp.realpath(path, signal)) !== path) throw new CogsSkillSftpMaterializerError();
}

async function assertDirectory(sftp: CogsSftpPort, path: string, signal: AbortSignal): Promise<void> {
  const stat = await sftp.lstat(path, signal);
  if (stat.type !== "directory") throw new CogsSkillSftpMaterializerError();
}

async function assertMissing(sftp: CogsSftpPort, path: string, signal: AbortSignal): Promise<void> {
  try {
    await sftp.lstat(path, signal);
  } catch (error) {
    if (isNoSuch(error)) return;
    throw new CogsSkillSftpMaterializerError();
  }
  throw new CogsSkillSftpMaterializerError();
}

async function mkdirTracked(sftp: RequiredSftp, path: string, mode: number, dirs: string[], signal: AbortSignal) {
  await sftp.mkdir(path, mode, signal);
  dirs.push(path);
  await assertDirectory(sftp, path, signal);
}

async function ensureParentDirs(
  sftp: RequiredSftp,
  root: string,
  relativeFile: string,
  dirs: string[],
  signal: AbortSignal,
) {
  const parent = posix.dirname(relativeFile);
  if (parent === ".") return;
  let current = root;
  for (const part of parent.split("/")) {
    current = `${current}/${part}`;
    try {
      await assertDirectory(sftp, current, signal);
    } catch (error) {
      if (!isNoSuch(error)) throw new CogsSkillSftpMaterializerError();
      await mkdirTracked(sftp, current, 0o700, dirs, signal);
    }
  }
}

async function writeOne(
  sftp: RequiredSftp,
  path: string,
  bytes: Buffer,
  mode: 0o444 | 0o555,
  files: string[],
  signal: AbortSignal,
) {
  const handle = await sftp.open(path, "wx", signal);
  files.push(path);
  let closed = false;
  try {
    let offset = 0;
    while (offset < bytes.length) {
      throwIfAborted(signal);
      const length = Math.min(32 * 1024, bytes.length - offset);
      await sftp.write(handle, bytes, offset, length, offset, signal);
      offset += length;
    }
    const stat = await sftp.fstat(handle, signal);
    if (stat.type !== "file" || stat.size !== bytes.length) throw new CogsSkillSftpMaterializerError();
    await sftp.fsync(handle, signal);
    await sftp.closeHandle(handle, signal);
    closed = true;
    await sftp.setMode(path, mode, signal);
    const reread = await readFile(sftp, path, bytes.length, signal);
    if (!reread.equals(bytes)) throw new CogsSkillSftpMaterializerError();
  } finally {
    if (!closed) await sftp.closeHandle(handle, signal).catch(() => undefined);
  }
}

async function readFile(sftp: CogsSftpPort, path: string, maxBytes: number, signal: AbortSignal): Promise<Buffer> {
  const before = await sftp.lstat(path, signal);
  if (
    before.type !== "file" ||
    !Number.isSafeInteger(before.size) ||
    before.size < 0 ||
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 0 ||
    before.size !== maxBytes
  )
    throw new CogsSkillSftpMaterializerError();
  const handle = await sftp.open(path, "r", signal);
  const chunks: Buffer[] = [];
  let closed = false;
  try {
    const opened = await sftp.fstat(handle, signal);
    if (opened.type !== "file" || opened.size !== before.size) throw new CogsSkillSftpMaterializerError();
    let pos = 0;
    while (pos < opened.size) {
      const length = Math.min(32 * 1024, opened.size - pos);
      const buf = Buffer.alloc(length);
      const read = await sftp.read(handle, buf, 0, length, pos, signal);
      if (
        read.buffer !== buf ||
        read.position !== pos ||
        !Number.isSafeInteger(read.bytesRead) ||
        read.bytesRead < 0 ||
        read.bytesRead > length
      )
        throw new CogsSkillSftpMaterializerError();
      if (read.bytesRead === 0) throw new CogsSkillSftpMaterializerError();
      chunks.push(Buffer.from(buf.subarray(0, read.bytesRead)));
      pos += read.bytesRead;
      if (pos > maxBytes) throw new CogsSkillSftpMaterializerError();
    }
    const extra = Buffer.alloc(1);
    const extraRead = await sftp.read(handle, extra, 0, 1, pos, signal);
    if (
      extraRead.buffer !== extra ||
      extraRead.position !== pos ||
      !Number.isSafeInteger(extraRead.bytesRead) ||
      extraRead.bytesRead < 0 ||
      extraRead.bytesRead > 1 ||
      extraRead.bytesRead !== 0
    )
      throw new CogsSkillSftpMaterializerError();
    const after = await sftp.fstat(handle, signal);
    if (after.type !== "file" || after.size !== opened.size) throw new CogsSkillSftpMaterializerError();
    await sftp.closeHandle(handle, signal);
    closed = true;
    const out = Buffer.concat(chunks);
    if (out.length !== opened.size) throw new CogsSkillSftpMaterializerError();
    return out;
  } finally {
    if (!closed) await sftp.closeHandle(handle, signal).catch(() => undefined);
  }
}

export async function cleanupCogsSkillMaterializedBundle(
  port: CogsSftpPort,
  item: CogsSftpMaterializedBundle,
  signal: AbortSignal,
): Promise<void> {
  const ownership = CLEANUP_OWNERS.get(item);
  if (ownership === undefined) throw new CogsSkillSftpMaterializerError();
  if (ownership.cleaned) return;
  const sftp = requireDirectorySftp(port);
  await cleanupKnown(sftp, ownership.root, ownership.files, ownership.dirs, signal);
  ownership.cleaned = true;
}

async function cleanupKnown(
  sftp: RequiredSftp,
  root: string,
  files: readonly string[],
  dirs: readonly string[],
  signal: AbortSignal,
) {
  const failures: unknown[] = [];
  await cleanupAttempt(failures, () => sftp.setMode(root, 0o700, signal));
  for (const dir of dirs) await cleanupAttempt(failures, () => sftp.setMode(dir, 0o700, signal));
  for (const file of [...files].reverse()) await cleanupAttempt(failures, () => sftp.unlink(file, signal));
  for (const dir of [...dirs].reverse()) await cleanupAttempt(failures, () => sftp.rmdir(dir, signal));
  await cleanupAttempt(failures, () => sftp.rmdir(root, signal));
  if (failures.length > 0) throw new CogsSkillSftpMaterializerError();
}
async function cleanupAttempt(failures: unknown[], operation: () => Promise<void>) {
  try {
    await operation();
  } catch (error) {
    if (!isNoSuch(error)) failures.push(error);
  }
}
function validateSignal(signal: AbortSignal): AbortSignal {
  if (!(signal instanceof AbortSignal)) throw new CogsSkillSftpMaterializerError();
  return signal;
}
function validateGuestRoot(root: string): "/shared/skills" | "/user/skills" {
  if (root !== "/shared/skills" && root !== "/user/skills") throw new CogsSkillSftpMaterializerError();
  return root;
}
function isNoSuch(error: unknown): boolean {
  return error instanceof CogsSftpStatusError && error.status === "no_such_file";
}
function throwIfAborted(signal: AbortSignal) {
  if (signal.aborted) throw new CogsSkillSftpMaterializerError();
}

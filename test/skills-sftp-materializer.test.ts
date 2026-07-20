import assert from "node:assert/strict";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  rmdir,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { buildCogsSkillBundle } from "../src/skills/bundle.ts";
import {
  cleanupCogsSkillMaterializedBundle,
  materializeCogsSkillBundleToGuest,
} from "../src/skills/sftp-materializer.ts";
import { type CogsSftpPort, type CogsSftpStats, CogsSftpStatusError } from "../src/ssh/connection.ts";

class LocalSftp implements CogsSftpPort {
  readonly #handles = new Map<string, Awaited<ReturnType<typeof open>>>();
  public failFsync = false;
  public corruptAfterRename = false;
  public badExtraTuple = false;
  public failCleanup = false;
  public modes = new Map<string, number>();
  public constructor(private readonly root: string) {}
  public async lstat(p: string): Promise<CogsSftpStats> {
    try {
      const stat = await lstat(this.#map(p));
      return {
        size: Number(stat.size),
        type: stat.isFile() ? "file" : stat.isDirectory() ? "directory" : stat.isSymbolicLink() ? "symlink" : "unknown",
      };
    } catch (error) {
      if ((error as { code?: unknown }).code === "ENOENT") throw new CogsSftpStatusError("no_such_file");
      throw error;
    }
  }
  public async realpath(p: string): Promise<string> {
    await lstat(this.#map(p));
    return p;
  }
  public async open(p: string, mode: "r" | "wx"): Promise<Buffer> {
    const handle = await open(this.#map(p), mode, 0o600);
    const id = Buffer.from(`${this.#handles.size + 1}`);
    this.#handles.set(id.toString("hex"), handle);
    return id;
  }
  public async read(handle: Buffer, buffer: Buffer, offset: number, length: number, position: number) {
    const result = await this.#handle(handle).read(buffer, offset, length, position);
    if (this.badExtraTuple && length === 1) return { bytesRead: 0, buffer: Buffer.alloc(1), position };
    return { bytesRead: result.bytesRead, buffer, position };
  }
  public async write(handle: Buffer, buffer: Buffer, offset: number, length: number, position: number) {
    await this.#handle(handle).write(buffer, offset, length, position);
  }
  public async fstat(handle: Buffer): Promise<CogsSftpStats> {
    const stat = await this.#handle(handle).stat();
    return { size: Number(stat.size), type: stat.isFile() ? "file" : "unknown" };
  }
  public async closeHandle(handle: Buffer) {
    const key = handle.toString("hex");
    const value = this.#handles.get(key);
    if (value !== undefined) {
      this.#handles.delete(key);
      await value.close();
    }
  }
  public async unlink(p: string) {
    if (this.failCleanup) throw new Error("cleanup failed");
    await unlink(this.#map(p));
  }
  public async mkdir(p: string, mode: number) {
    await mkdir(this.#map(p), { mode });
  }
  public async setMode(p: string, mode: number) {
    this.modes.set(p, mode);
    await chmod(this.#map(p), mode);
  }
  public async rmdir(p: string) {
    if (this.failCleanup) throw new Error("cleanup failed");
    await rmdir(this.#map(p));
  }
  public async fsync(handle: Buffer) {
    if (this.failFsync) throw new Error("fsync failed");
    await this.#handle(handle).sync();
  }
  public async posixRename(source: string, target: string) {
    await rename(this.#map(source), this.#map(target));
    if (this.corruptAfterRename) {
      const bundlePath = path.join(this.#map(target), ".cogs-skills-bundle.json");
      await chmod(bundlePath, 0o600);
      await writeFile(bundlePath, "corrupt");
    }
  }
  public map(p: string): string {
    return this.#map(p);
  }
  #handle(handle: Buffer) {
    const value = this.#handles.get(handle.toString("hex"));
    if (value === undefined) throw new Error("bad handle");
    return value;
  }
  #map(p: string): string {
    if (!p.startsWith("/")) throw new Error("bad path");
    return path.join(this.root, ...p.slice(1).split("/"));
  }
}

test("SFTP skill materializer writes digest subtree, exact bundle, readonly modes, and cleanup", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "cogs-sftp-skills-"));
  try {
    await mkdir(path.join(root, "shared/skills"), { recursive: true });
    const sftp = new LocalSftp(root);
    const bundle = buildCogsSkillBundle({
      entries: [
        { path: "SKILL.md", executable: false, content: Buffer.from("---\nname: a\ndescription: b\n---\n# A\n") },
      ],
    });
    const materialized = await materializeCogsSkillBundleToGuest({
      sftp,
      bundle,
      guestRoot: "/shared/skills",
      signal: new AbortController().signal,
    });
    assert.equal(materialized.guestSubtree, `/shared/skills/${bundle.digest.slice("sha256:".length)}`);
    assert.equal(
      await readFile(sftp.map(`${materialized.guestSubtree}/.cogs-skills-bundle.json`), "utf8"),
      bundle.copyBytes().toString("utf8"),
    );
    assert.equal(
      await readFile(sftp.map(`${materialized.guestSubtree}/SKILL.md`), "utf8"),
      bundle.copyFile("SKILL.md").toString("utf8"),
    );
    assert.equal((await stat(sftp.map(`${materialized.guestSubtree}/SKILL.md`))).mode & 0o777, 0o444);
    await cleanupCogsSkillMaterializedBundle(sftp, materialized, new AbortController().signal);
    await assert.rejects(lstat(sftp.map(materialized.guestSubtree)), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("SFTP materializer debug markers are fixed scoped write milestones", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "cogs-sftp-skills-markers-"));
  const previous = process.env.COGS_LAUNCHER_DEBUG_STAGE;
  const previousWrite = process.stderr.write;
  const lines: string[] = [];
  try {
    await mkdir(path.join(root, "user/skills"), { recursive: true });
    process.env.COGS_LAUNCHER_DEBUG_STAGE = "1";
    process.stderr.write = ((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    const bundle = buildCogsSkillBundle({
      entries: [
        { path: "SKILL.md", executable: false, content: Buffer.from("---\nname: u\ndescription: u\n---\n# U\n") },
      ],
    });
    const sftp = new LocalSftp(root);
    const materialized = await materializeCogsSkillBundleToGuest({
      sftp,
      bundle,
      guestRoot: "/user/skills",
      signal: new AbortController().signal,
    });
    await cleanupCogsSkillMaterializedBundle(sftp, materialized, new AbortController().signal);
    const markers = lines.join("").trim().split(/\n/u);
    for (const marker of [
      "launcher-debug-stage:sftp-user-write-signal-active",
      "launcher-debug-stage:sftp-user-write-open-returned",
      "launcher-debug-stage:sftp-user-write-bytes-written",
      "launcher-debug-stage:sftp-user-write-fstat-accepted",
      "launcher-debug-stage:sftp-user-write-fsync-returned",
      "launcher-debug-stage:sftp-user-write-close-returned",
      "launcher-debug-stage:sftp-user-write-chmod-returned",
      "launcher-debug-stage:sftp-user-write-reread-accepted",
    ]) {
      assert(markers.includes(marker));
    }
    assert(!markers.some((marker) => marker.includes("/user/skills") || marker.includes(bundle.digest)));
  } finally {
    process.stderr.write = previousWrite;
    if (previous === undefined) delete process.env.COGS_LAUNCHER_DEBUG_STAGE;
    else process.env.COGS_LAUNCHER_DEBUG_STAGE = previous;
    await rm(root, { recursive: true, force: true });
  }
});

test("SFTP materializer rejects forged handles, reserved paths, fsync/read faults, and cleans tracked paths", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "cogs-sftp-skills-fault-"));
  try {
    await mkdir(path.join(root, "shared/skills"), { recursive: true });
    const good = buildCogsSkillBundle({
      entries: [
        { path: "bin/SKILL.md", executable: true, content: Buffer.from("---\nname: e\ndescription: e\n---\n# E\n") },
      ],
    });
    const forged = { ...good, files: [{ ...good.files[0], path: "../escape" }] };
    const forgedSftp = new LocalSftp(root);
    const forgedMaterialized = await materializeCogsSkillBundleToGuest({
      sftp: forgedSftp,
      bundle: forged as typeof good,
      guestRoot: "/shared/skills",
      signal: new AbortController().signal,
    });
    assert.equal(await lstat(path.join(root, "escape")).catch((error) => (error as { code?: string }).code), "ENOENT");
    await cleanupCogsSkillMaterializedBundle(forgedSftp, forgedMaterialized, new AbortController().signal);

    const reserved = buildCogsSkillBundle({
      entries: [{ path: ".cogs-skills-bundle.json", executable: false, content: Buffer.from("x") }],
    });
    await assert.rejects(
      materializeCogsSkillBundleToGuest({
        sftp: new LocalSftp(root),
        bundle: reserved,
        guestRoot: "/shared/skills",
        signal: new AbortController().signal,
      }),
    );

    const fsyncSftp = new LocalSftp(root);
    fsyncSftp.failFsync = true;
    await assert.rejects(
      materializeCogsSkillBundleToGuest({
        sftp: fsyncSftp,
        bundle: good,
        guestRoot: "/shared/skills",
        signal: new AbortController().signal,
      }),
    );
    assert.deepEqual(await readdirSafe(path.join(root, "shared/skills")), []);

    const badRead = new LocalSftp(root);
    badRead.badExtraTuple = true;
    await assert.rejects(
      materializeCogsSkillBundleToGuest({
        sftp: badRead,
        bundle: good,
        guestRoot: "/shared/skills",
        signal: new AbortController().signal,
      }),
    );
    assert.deepEqual(await readdirSafe(path.join(root, "shared/skills")), []);

    const corrupt = new LocalSftp(root);
    corrupt.corruptAfterRename = true;
    await assert.rejects(
      materializeCogsSkillBundleToGuest({
        sftp: corrupt,
        bundle: good,
        guestRoot: "/shared/skills",
        signal: new AbortController().signal,
      }),
    );
    assert.deepEqual(await readdirSafe(path.join(root, "shared/skills")), []);

    const ok = new LocalSftp(root);
    const materialized = await materializeCogsSkillBundleToGuest({
      sftp: ok,
      bundle: good,
      guestRoot: "/shared/skills",
      signal: new AbortController().signal,
    });
    assert.equal((await stat(ok.map(`${materialized.guestSubtree}/bin/SKILL.md`))).mode & 0o777, 0o555);
    const victim = "/shared/skills/victim.txt";
    await writeFile(ok.map(victim), "do not delete");
    let mutationCount = 0;
    const originalUnlink = ok.unlink.bind(ok);
    const originalSetMode = ok.setMode.bind(ok);
    ok.unlink = async (p: string) => {
      mutationCount += 1;
      await originalUnlink(p);
    };
    ok.setMode = async (p: string, mode: number) => {
      mutationCount += 1;
      await originalSetMode(p, mode);
    };
    await assert.rejects(
      cleanupCogsSkillMaterializedBundle(
        ok,
        Object.freeze({
          ...materialized,
          guestSubtree: "/shared/skills",
          cleanupFiles: Object.freeze([victim]),
        }) as never,
        new AbortController().signal,
      ),
    );
    assert.equal(await readFile(ok.map(victim), "utf8"), "do not delete");
    assert.equal(mutationCount, 0);
    ok.failCleanup = true;
    await assert.rejects(cleanupCogsSkillMaterializedBundle(ok, materialized, new AbortController().signal));
    ok.failCleanup = false;
    await cleanupCogsSkillMaterializedBundle(ok, materialized, new AbortController().signal);
  } finally {
    await chmodTree(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }
});

async function readdirSafe(dir: string): Promise<string[]> {
  const { readdir } = await import("node:fs/promises");
  return readdir(dir).catch(() => []);
}
async function chmodTree(target: string): Promise<void> {
  const { readdir } = await import("node:fs/promises");
  await chmod(target, 0o700).catch(() => undefined);
  for (const entry of await readdir(target, { withFileTypes: true }).catch(() => [])) {
    const child = path.join(target, entry.name);
    if (entry.isDirectory()) await chmodTree(child);
    else await chmod(child, 0o600).catch(() => undefined);
  }
}

test("SFTP skill materializer rejects stale final subtree, symlink roots, and missing directory methods", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "cogs-sftp-skills-bad-"));
  try {
    await mkdir(path.join(root, "shared/skills"), { recursive: true });
    const sftp = new LocalSftp(root);
    const bundle = buildCogsSkillBundle({ entries: [] });
    await mkdir(path.join(root, "shared/skills", bundle.digest.slice("sha256:".length)));
    await assert.rejects(
      materializeCogsSkillBundleToGuest({
        sftp,
        bundle,
        guestRoot: "/shared/skills",
        signal: new AbortController().signal,
      }),
    );
    await rm(path.join(root, "shared/skills", bundle.digest.slice("sha256:".length)), { recursive: true });
    await rm(path.join(root, "shared/skills"), { recursive: true });
    await symlink(path.join(root, "elsewhere"), path.join(root, "shared/skills"));
    await assert.rejects(
      materializeCogsSkillBundleToGuest({
        sftp,
        bundle,
        guestRoot: "/shared/skills",
        signal: new AbortController().signal,
      }),
    );
    const partial: CogsSftpPort = {
      lstat: sftp.lstat.bind(sftp),
      realpath: sftp.realpath.bind(sftp),
      open: sftp.open.bind(sftp),
      read: sftp.read.bind(sftp),
      write: sftp.write.bind(sftp),
      fstat: sftp.fstat.bind(sftp),
      closeHandle: sftp.closeHandle.bind(sftp),
      unlink: sftp.unlink.bind(sftp),
      fsync: sftp.fsync.bind(sftp),
      posixRename: sftp.posixRename.bind(sftp),
    };
    await assert.rejects(
      materializeCogsSkillBundleToGuest({
        sftp: partial,
        bundle,
        guestRoot: "/shared/skills",
        signal: new AbortController().signal,
      }),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

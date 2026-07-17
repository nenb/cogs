import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, open, rename, rm, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import type { LaunchConfig } from "../src/launch/config.ts";
import { buildCogsSkillBundle } from "../src/skills/bundle.ts";
import { createCogsSkillSessionPreparer } from "../src/skills/session-preparer.ts";
import { type CogsSftpPort, type CogsSftpStats, CogsSftpStatusError } from "../src/ssh/connection.ts";

class LocalSftp implements CogsSftpPort {
  readonly #handles = new Map<string, Awaited<ReturnType<typeof open>>>();
  public constructor(
    private readonly root: string,
    public agents: Buffer | undefined = undefined,
  ) {}
  public async lstat(p: string): Promise<CogsSftpStats> {
    if (p === "/workspace/AGENTS.md" && this.agents !== undefined) return { size: this.agents.length, type: "file" };
    try {
      const s = await lstat(this.map(p));
      return {
        size: Number(s.size),
        type: s.isFile() ? "file" : s.isDirectory() ? "directory" : s.isSymbolicLink() ? "symlink" : "unknown",
      };
    } catch (error) {
      if ((error as { code?: unknown }).code === "ENOENT") throw new CogsSftpStatusError("no_such_file");
      throw error;
    }
  }
  public async realpath(p: string) {
    await this.lstat(p);
    return p;
  }
  public async open(p: string, mode: "r" | "wx") {
    if (p === "/workspace/AGENTS.md" && mode === "r" && this.agents !== undefined) {
      const f = await open(this.map("/workspace/.agents-tmp"), "w+");
      await f.writeFile(this.agents);
      const id = Buffer.from(`${this.#handles.size + 1}`);
      this.#handles.set(id.toString("hex"), f);
      return id;
    }
    const f = await open(this.map(p), mode, 0o600);
    const id = Buffer.from(`${this.#handles.size + 1}`);
    this.#handles.set(id.toString("hex"), f);
    return id;
  }
  #h(h: Buffer) {
    const f = this.#handles.get(h.toString("hex"));
    if (!f) throw new Error("bad handle");
    return f;
  }
  public async read(h: Buffer, b: Buffer, o: number, l: number, p: number) {
    const r = await this.#h(h).read(b, o, l, p);
    return { bytesRead: r.bytesRead, buffer: b, position: p };
  }
  public async write(h: Buffer, b: Buffer, o: number, l: number, p: number) {
    await this.#h(h).write(b, o, l, p);
  }
  public async fstat(h: Buffer): Promise<CogsSftpStats> {
    const s = await this.#h(h).stat();
    return { size: Number(s.size), type: s.isFile() ? "file" : "unknown" };
  }
  public async closeHandle(h: Buffer) {
    const k = h.toString("hex");
    const f = this.#handles.get(k);
    if (f) {
      this.#handles.delete(k);
      await f.close();
    }
  }
  public async unlink(p: string) {
    await unlink(this.map(p));
  }
  public async mkdir(p: string, mode: number) {
    await mkdir(this.map(p), { mode });
  }
  public async setMode(p: string, mode: number) {
    await chmod(this.map(p), mode);
  }
  public async rmdir(p: string) {
    await rmdir(this.map(p));
  }
  public async fsync(h: Buffer) {
    await this.#h(h).sync();
  }
  public async posixRename(a: string, b: string) {
    await rename(this.map(a), this.map(b));
  }
  public map(p: string) {
    return path.join(this.root, ...p.slice(1).split("/"));
  }
}

function launch(shared: string, user: string): LaunchConfig {
  return {
    version: "cogs.dev/v1alpha1",
    user_id: "user-1",
    session_id: "s",
    workspace_id: "w",
    sandbox: {
      ssh_endpoint: "x:22",
      ssh_host_key: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      client_key_path: "/k",
      proxy_auth_handle: "p",
    },
    model: { provider: "anthropic", id: "claude-sonnet-4-5", credential_handle: "users/user-1/model" },
    skills: { shared_revision: shared, shared_path: "/shared/skills", user_revision: user, user_path: "/user/skills" },
    integrations: [],
    limits: { cpu: 1, memory_bytes: 1, tool_timeout_seconds: 1, max_tool_output_bytes: 1 },
  };
}

test("session preparer option getters are not invoked", () => {
  assert.throws(() =>
    createCogsSkillSessionPreparer(
      Object.defineProperty({}, "ssh", {
        enumerable: true,
        get() {
          throw new Error("getter escaped");
        },
      }) as never,
    ),
  );
});

function skillFile(name: string, description = "desc", body = "body") {
  return Buffer.from(`---\nname: ${name}\ndescription: ${description}\n---\n# ${body}\n`);
}

async function withFixture(
  sharedEntries: readonly { path: string; content: Buffer }[],
  userEntries: readonly { path: string; content: Buffer }[],
  run: (fixture: {
    root: string;
    sftp: LocalSftp;
    preparer: ReturnType<typeof createCogsSkillSessionPreparer>;
    launch: LaunchConfig;
    sharedBundle: ReturnType<typeof buildCogsSkillBundle>;
    userBundle: ReturnType<typeof buildCogsSkillBundle>;
    sftpCalls: { count: number };
  }) => Promise<void>,
  agents?: Buffer,
  sftpFactory: (root: string, agents: Buffer | undefined) => LocalSftp = (r, a) => new LocalSftp(r, a),
) {
  const root = await mkdtemp(path.join(tmpdir(), "cogs-preparer-fixture-"));
  try {
    await mkdir(path.join(root, "shared/skills"), { recursive: true });
    await mkdir(path.join(root, "user/skills"), { recursive: true });
    await mkdir(path.join(root, "workspace"), { recursive: true });
    const sftp = sftpFactory(root, agents);
    const sharedBundle = buildCogsSkillBundle({
      entries: sharedEntries.map((entry) => ({ ...entry, executable: false })),
    });
    const userBundle = buildCogsSkillBundle({ entries: userEntries.map((entry) => ({ ...entry, executable: false })) });
    const sftpCalls = { count: 0 };
    const preparer = createCogsSkillSessionPreparer({
      ssh: {
        withSftp: async (_i: unknown, op: (p: CogsSftpPort, s: AbortSignal) => Promise<unknown>) => {
          sftpCalls.count += 1;
          return op(sftp, new AbortController().signal);
        },
      } as never,
      sharedResolver: {
        resolve: async () => ({
          scope: "shared",
          manifestDigest: `sha256:${"a".repeat(64)}`,
          bundleDigest: sharedBundle.digest,
          manifestBytes: 1,
          bundleBytes: sharedBundle.byteLength,
          configBytes: 2,
          fileCount: sharedBundle.fileCount,
          decodedByteLength: sharedBundle.decodedByteLength,
          bundle: sharedBundle,
        }),
      },
      privateStore: {
        snapshot: async (input) => ({
          scope: "user",
          userNamespace: `sha256:${"b".repeat(64)}`,
          digest: input.expectedDigest,
          byteLength: userBundle.byteLength,
          decodedByteLength: userBundle.decodedByteLength,
          fileCount: userBundle.fileCount,
          bundle: userBundle,
        }),
        resolve: async () => {
          throw new Error("must not resolve");
        },
      },
    });
    await run({
      root,
      sftp,
      preparer,
      launch: launch(`sha256:${"a".repeat(64)}`, userBundle.digest),
      sharedBundle,
      userBundle,
      sftpCalls,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("session preparer snapshots private, materializes guest paths, eager full text, agents, and cleanup", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "cogs-preparer-"));
  try {
    await mkdir(path.join(root, "shared/skills"), { recursive: true });
    await mkdir(path.join(root, "user/skills"), { recursive: true });
    await mkdir(path.join(root, "workspace"), { recursive: true });
    const sftp = new LocalSftp(root, Buffer.from("untrusted agents"));
    const sharedBundle = buildCogsSkillBundle({
      entries: [
        {
          path: "root.md",
          executable: false,
          content: Buffer.from("---\nname: shared-root\ndescription: shared desc\n---\n# Shared exact\n"),
        },
      ],
    });
    const userBundle = buildCogsSkillBundle({
      entries: [
        {
          path: "nested/SKILL.md",
          executable: false,
          content: Buffer.from("---\nname: user-nested\ndescription: user desc\n---\n# User exact\n"),
        },
      ],
    });
    let snapshotUser = "";
    const preparer = createCogsSkillSessionPreparer({
      ssh: {
        withSftp: async (_i: unknown, op: (p: CogsSftpPort, s: AbortSignal) => Promise<unknown>) =>
          op(sftp, new AbortController().signal),
      } as never,
      sharedResolver: {
        resolve: async () => ({
          scope: "shared",
          manifestDigest: `sha256:${"a".repeat(64)}`,
          bundleDigest: sharedBundle.digest,
          manifestBytes: 1,
          bundleBytes: sharedBundle.byteLength,
          configBytes: 2,
          fileCount: sharedBundle.fileCount,
          decodedByteLength: sharedBundle.decodedByteLength,
          bundle: sharedBundle,
        }),
      },
      privateStore: {
        snapshot: async (input) => {
          snapshotUser = input.userId;
          return {
            scope: "user",
            userNamespace: `sha256:${"b".repeat(64)}`,
            digest: userBundle.digest,
            byteLength: userBundle.byteLength,
            decodedByteLength: userBundle.decodedByteLength,
            fileCount: userBundle.fileCount,
            bundle: userBundle,
          };
        },
        resolve: async () => {
          throw new Error("must not resolve");
        },
      },
    });
    const prepared = await preparer.prepare({ launch: launch(`sha256:${"a".repeat(64)}`, userBundle.digest) });
    assert.equal(snapshotUser, "user-1");
    assert.equal(prepared.piSkills.length, 2);
    assert.match(prepared.eagerTrustedSkillPrompt, /Shared exact/);
    assert.match(prepared.eagerTrustedSkillPrompt, /User exact/);
    assert.doesNotMatch(prepared.eagerTrustedSkillPrompt, /var\/folders|cogs-preparer/);
    assert.equal(prepared.agentsFiles[0]?.content, "untrusted agents");
    assert.ok(
      prepared.piSkills.every(
        (skill) => skill.filePath.startsWith("/shared/skills/") || skill.filePath.startsWith("/user/skills/"),
      ),
    );
    await prepared.dispose();
    await assert.rejects(lstat(sftp.map(prepared.metadata.shared.guestSubtree)), { code: "ENOENT" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("session preparer rejects malformed skill markdown, duplicates, count, aggregate, and UTF-8", async () => {
  const cases: Array<{
    name: string;
    shared: readonly { path: string; content: Buffer }[];
    user: readonly { path: string; content: Buffer }[];
  }> = [
    {
      name: "missing-description",
      shared: [{ path: "bad.md", content: Buffer.from("---\nname: bad\n---\n# bad\n") }],
      user: [],
    },
    {
      name: "duplicate-shared-user-name",
      shared: [{ path: "a.md", content: skillFile("dupe") }],
      user: [{ path: "SKILL.md", content: skillFile("dupe") }],
    },
    {
      name: "thirty-three-skills",
      shared: Array.from({ length: 33 }, (_, i) => ({ path: `s${i}.md`, content: skillFile(`skill-${i}`) })),
      user: [],
    },
    {
      name: "aggregate-over-256kib",
      shared: Array.from({ length: 5 }, (_, i) => ({
        path: `big${i}.md`,
        content: skillFile(`big-${i}`, "desc", "x".repeat(60 * 1024)),
      })),
      user: [],
    },
    {
      name: "invalid-utf8",
      shared: [{ path: "SKILL.md", content: Buffer.from([0xff, 0xfe, 0xfd]) }],
      user: [],
    },
  ];
  for (const one of cases) {
    await withFixture(one.shared, one.user, async ({ preparer, launch, sftpCalls }) => {
      await assert.rejects(preparer.prepare({ launch }), /invalid skill preparation/, one.name);
      assert.equal(sftpCalls.count, 0, one.name);
    });
  }
});

class AgentStatusSftp extends LocalSftp {
  public mode: "missing" | "invalid-utf8" | "oversize" | "permission" = "missing";
  public override async lstat(p: string): Promise<CogsSftpStats> {
    if (p === "/workspace/AGENTS.md") {
      if (this.mode === "missing") throw new CogsSftpStatusError("no_such_file");
      if (this.mode === "permission") throw new CogsSftpStatusError("permission_denied");
      const size = this.mode === "oversize" ? 32 * 1024 + 1 : 1;
      return { size, type: "file" };
    }
    return super.lstat(p);
  }
  public override async open(p: string, mode: "r" | "wx") {
    if (p === "/workspace/AGENTS.md" && mode === "r") {
      this.agents = this.mode === "invalid-utf8" ? Buffer.from([0xff]) : Buffer.alloc(32 * 1024 + 1);
    }
    return super.open(p, mode);
  }
}

test("session preparer reports bounded AGENTS statuses", async () => {
  for (const [mode, status] of [
    ["missing", "missing"],
    ["invalid-utf8", "invalid"],
    ["oversize", "oversize"],
    ["permission", "permission_denied"],
  ] as const) {
    await withFixture(
      [{ path: "ok.md", content: skillFile(`agent-${mode}`) }],
      [],
      async ({ preparer, launch }) => {
        const prepared = await preparer.prepare({ launch });
        assert.equal(prepared.metadata.agentsStatus, status);
        await prepared.dispose();
      },
      undefined,
      (root) => {
        const sftp = new AgentStatusSftp(root);
        sftp.mode = mode;
        return sftp;
      },
    );
  }
});

test("session preparer eager prompt is stable after guest mutation, dispose is once, and cleanup errors reject", async () => {
  class WritableSftp extends LocalSftp {
    public override async setMode(_p: string, _mode: number) {}
  }
  const writable = (root: string, agents: Buffer | undefined) => new WritableSftp(root, agents);
  await withFixture(
    [{ path: "stable.md", content: skillFile("stable", "desc", "ORIGINAL") }],
    [],
    async ({ sftp, preparer, launch }) => {
      const prepared = await preparer.prepare({ launch });
      const firstSkill = prepared.piSkills[0];
      assert.ok(firstSkill);
      await writeFile(sftp.map(firstSkill.filePath), skillFile("stable", "desc", "MUTATED"));
      assert.match(prepared.eagerTrustedSkillPrompt, /ORIGINAL/);
      assert.doesNotMatch(prepared.eagerTrustedSkillPrompt, /MUTATED/);
      let rmdirCalls = 0;
      const originalRmdir = sftp.rmdir.bind(sftp);
      const originalUnlink = sftp.unlink.bind(sftp);
      sftp.unlink = async (p: string) => {
        await chmod(path.dirname(sftp.map(p)), 0o700).catch(() => undefined);
        await originalUnlink(p);
      };
      sftp.rmdir = async (p: string) => {
        rmdirCalls += 1;
        await originalRmdir(p);
      };
      await prepared.dispose();
      await prepared.dispose();
      assert.ok(rmdirCalls > 0);
      const afterSecond = rmdirCalls;
      await prepared.dispose();
      assert.equal(rmdirCalls, afterSecond);
    },
    undefined,
    writable,
  );

  await withFixture(
    [{ path: "cleanup.md", content: skillFile("cleanup") }],
    [],
    async ({ sftp, preparer, launch }) => {
      const prepared = await preparer.prepare({ launch });
      sftp.rmdir = async () => {
        throw new Error("remote cleanup failed");
      };
      await assert.rejects(prepared.dispose(), /invalid skill preparation/);
    },
    undefined,
    writable,
  );
});

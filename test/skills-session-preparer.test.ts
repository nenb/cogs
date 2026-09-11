import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs, { chmod, lstat, mkdir, mkdtemp, open, rename, rm, rmdir, unlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { mock } from "node:test";
import ssh2 from "ssh2";
import type { LaunchConfig } from "../src/launch/config.ts";
import { createAuthenticatedCogsPiSession } from "../src/pi/session.ts";
import { buildCogsSkillBundle } from "../src/skills/bundle.ts";
import { createCogsSkillSessionPreparer } from "../src/skills/session-preparer.ts";
import {
  type CogsSkillSnapshotReceipt,
  type CogsSnapshotSftpPort,
  createCogsMountedSkillSessionPreparer,
  isRuntimeReadOnlySkillSet,
  parseCogsSkillSnapshotReceipt,
  verifyCogsMountedSkillBundle,
  withSnapshotSftp,
} from "../src/skills/snapshot-session-preparer.ts";
import { type CogsSftpPort, type CogsSftpStats, CogsSftpStatusError } from "../src/ssh/connection.ts";

const { Server, utils } = ssh2;

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
    limits: { cpu: 1, memory_bytes: 1, tool_timeout_seconds: 1, turn_timeout_seconds: 61, max_tool_output_bytes: 1 },
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

type SnapshotNode = { mode: number; data?: Buffer };
function mountedFixture(
  executable = false,
  scope: "shared" | "user" = "shared",
  empty = false,
  payload = Buffer.from([0, 1, 2, 255]),
) {
  const bundle = buildCogsSkillBundle({
    entries: empty
      ? []
      : [
          { path: "nested/SKILL.md", content: skillFile(scope), executable: false },
          { path: "nested/bin", content: payload, executable },
        ],
  });
  const root = `/${scope}/skills/${bundle.digest.slice(7)}`;
  const nodes = new Map<string, SnapshotNode>([
    [root, { mode: 0o40555 }],
    [`${root}/.cogs-skills-bundle.json`, { mode: 0o100444, data: bundle.copyBytes() }],
  ]);
  for (const file of bundle.files) {
    nodes.set(`${root}/nested`, { mode: 0o40555 });
    nodes.set(`${root}/${file.path}`, {
      mode: file.executable ? 0o100555 : 0o100444,
      data: bundle.copyFile(file.path),
    });
  }
  const stat = async (p: string): Promise<CogsSftpStats> => {
    const n = nodes.get(p);
    if (!n) throw new Error("missing");
    return {
      mode: n.mode,
      size: n.data?.length ?? 0,
      type: n.data ? "file" : "directory",
      ...{ uid: 1000, gid: 1000, mtime: 1 },
    };
  };
  const port: { -readonly [K in keyof CogsSnapshotSftpPort]: CogsSnapshotSftpPort[K] } = {
    lstat: stat,
    fstat: (h) => stat(h.toString()),
    realpath: async (p) => p,
    open: async (p, mode) => {
      assert.equal(mode, "r");
      await stat(p);
      return Buffer.from(p);
    },
    closeHandle: async () => undefined,
    read: async (h, buffer, offset, length, position) => {
      const data = nodes.get(h.toString())?.data;
      assert.ok(data);
      const bytesRead = data.copy(buffer, offset, position, Math.min(data.length, position + length));
      return { bytesRead, buffer, position };
    },
    list: async (p) => [...nodes.keys()].filter((n) => path.posix.dirname(n) === p).map((n) => path.posix.basename(n)),
  };
  return { bundle, root, nodes, port };
}
function receiptFor(shared = mountedFixture(), user = mountedFixture(false, "user", true)): CogsSkillSnapshotReceipt {
  const mount = (f: ReturnType<typeof mountedFixture>, inode: string) => ({
    source_device: "1",
    source_inode: inode,
    destination: f.root,
    bundle_digest: f.bundle.digest,
    read_only: true as const,
  });
  return {
    version: "cogs.skill-snapshot-receipt/v1",
    generation: "1".repeat(32),
    consumer_id: "2".repeat(32),
    session_id: "s",
    launch_digest: `sha256:${"c".repeat(64)}`,
    worker_id: "a".repeat(64),
    sandbox_id: "b".repeat(64),
    sandbox_mount_namespace: "mnt:[42]",
    shared: mount(shared, "101"),
    user: mount(user, "102"),
  };
}
function canonicalSnapshot(value: unknown): string {
  const sorted = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(sorted)
      : v && typeof v === "object"
        ? Object.fromEntries(
            Object.entries(v)
              .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
              .map(([k, v]) => [k, sorted(v)]),
          )
        : v;
  return `${JSON.stringify(sorted(value))}\n`;
}

test("mounted receipt is closed canonical bounded data, not runtime authority", () => {
  const receipt = receiptFor();
  const bytes = Buffer.from(canonicalSnapshot(receipt));
  const parsed = parseCogsSkillSnapshotReceipt(bytes);
  assert.deepEqual(parsed, receipt);
  assert.equal(Object.isFrozen(parsed.shared), true);
  assert.equal(isRuntimeReadOnlySkillSet(parsed.shared), false);
  assert.equal(isRuntimeReadOnlySkillSet(Object.freeze({ ...parsed.shared, readOnlyEnforced: true })), false);
  for (const bad of [
    bytes.subarray(0, -1),
    Buffer.concat([Buffer.from("\ufeff"), bytes]),
    Buffer.from([255]),
    Buffer.alloc(8193),
    Buffer.from(` ${bytes}`),
    Buffer.from(bytes.toString().replace('"generation":', '"generation":"wrong","generation":')),
  ])
    assert.throws(() => parseCogsSkillSnapshotReceipt(bad), /invalid skill preparation/);
  const mutations = [
    { version: "other" },
    { generation: "a".repeat(31) },
    { worker_id: receipt.sandbox_id },
    { extra: true },
    { sandbox_mount_namespace: "mnt:[0]" },
    { consumer_id: "F".repeat(32) },
    ...[
      { read_only: false },
      { destination: "/shared/skills" },
      { source_inode: "01" },
      { bundle_digest: `sha256:${"A".repeat(64)}` },
      { extra: true },
    ].map((m) => ({ shared: { ...receipt.shared, ...m } })),
  ];
  for (const mutation of mutations)
    assert.throws(() => parseCogsSkillSnapshotReceipt(Buffer.from(canonicalSnapshot({ ...receipt, ...mutation }))));
});

test("mounted SFTP verifies retained exact bytes twice, including empty and executable inventories, without authority or mutations", async () => {
  for (const empty of [false, true])
    for (const executable of [false, true]) {
      const f = mountedFixture(executable, "shared", empty);
      const before = structuredClone(f.nodes);
      assert.equal(
        await verifyCogsMountedSkillBundle(f.port, f.bundle, "/shared/skills", new AbortController().signal),
        undefined,
      );
      assert.deepEqual(structuredClone(f.nodes), before);
      assert.equal(isRuntimeReadOnlySkillSet(f.bundle), false);
    }
});

test("mounted verifier rejects hostile inventory, attributes, hashes, read tuples, EOF and unstable observations", async () => {
  const cases: Array<(f: ReturnType<typeof mountedFixture>) => void> = [
    (f) => {
      f.nodes.delete(`${f.root}/.cogs-skills-bundle.json`);
    },
    (f) => {
      f.nodes.set(`${f.root}/foreign`, { mode: 0o100444, data: Buffer.from("foreign") });
    },
    (f) => {
      Object.assign(f.nodes.get(f.root) ?? assert.fail(), { mode: 0o40755 });
    },
    (f) => {
      Object.assign(f.nodes.get(`${f.root}/nested/bin`) ?? assert.fail(), { mode: 0o104444 });
    },
    (f) => {
      Object.assign(f.nodes.get(`${f.root}/nested/bin`) ?? assert.fail(), { mode: 0o100644 });
    },
    (f) => {
      Object.assign(f.nodes.get(`${f.root}/nested/bin`) ?? assert.fail(), { data: Buffer.from([0, 2, 1, 255]) });
    },
    (f) => {
      Object.assign(f.nodes.get(`${f.root}/nested/bin`) ?? assert.fail(), { data: Buffer.from([0]) });
    },
    (f) => {
      const original = f.port.lstat;
      f.port.lstat = async (p, s) => ({ ...(await original(p, s)), type: "symlink" });
    },
    (f) => {
      const original = f.port.lstat;
      f.port.lstat = async (p, s) => {
        const { mode: _mode, ...stat } = await original(p, s);
        return stat;
      };
    },
    (f) => {
      f.port.realpath = async (p) => `${p}/alias`;
    },
    (f) => {
      const original = f.port.list;
      f.port.list = async (p, m, s) => {
        const names = await original(p, m, s);
        return [...names, names[0] ?? "foreign"];
      };
    },
    (f) => {
      f.port.read = async (_h, b, _o, _l, p) => ({ bytesRead: 0, buffer: b, position: p });
    },
    (f) => {
      f.port.read = async (_h, b, _o, l, p) => ({ bytesRead: l + 1, buffer: b, position: p });
    },
    (f) => {
      const original = f.port.read;
      f.port.read = async (...args) => ({ ...(await original(...args)), position: -1 });
    },
    (f) => {
      const original = f.port.read;
      f.port.read = async (...args) => {
        const r = await original(...args);
        return { ...r, bytesRead: r.bytesRead || 1 };
      };
    },
    (f) => {
      let calls = 0;
      const original = f.port.fstat;
      f.port.fstat = async (...args) => ({ ...(await original(...args)), ...{ mtime: ++calls } });
    },
    (f) => {
      let calls = 0;
      const original = f.port.list;
      f.port.list = async (...args) => (++calls > 2 ? ["foreign"] : original(...args));
    },
  ];
  for (const [index, mutate] of cases.entries()) {
    const f = mountedFixture();
    mutate(f);
    await assert.rejects(
      verifyCogsMountedSkillBundle(f.port, f.bundle, "/shared/skills", new AbortController().signal),
      /invalid skill preparation/,
      `case ${index}`,
    );
  }
  const f = mountedFixture();
  await assert.rejects(verifyCogsMountedSkillBundle(f.port, f.bundle, "/shared/skills", AbortSignal.abort()));
});

async function snapshotSshServer(nodes: Map<string, SnapshotNode>, root: string) {
  const host = utils.generateKeyPairSync("ed25519"),
    client = utils.generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "client-key");
  await writeFile(keyPath, client.private, { mode: 0o600 });
  const hostParsed = utils.parseKey(host.private);
  assert.ok(!(hostParsed instanceof Error) && !Array.isArray(hostParsed));
  const hostPin = `SHA256:${createHash("sha256").update(hostParsed.getPublicSSH()).digest("base64").replace(/=+$/, "")}`;
  let mutationCalls = 0,
    live = 0,
    reads = 0;
  let onRead = () => {};
  const server = new Server({ hostKeys: [host.private] }, (connection) => {
    live++;
    connection.on("error", () => undefined);
    connection.on("close", () => live--);
    connection.on("authentication", (ctx) => ctx.accept());
    connection.on("ready", () =>
      connection.on("session", (accept) =>
        accept().on("sftp", (acceptSftp) => {
          const sftp = acceptSftp();
          const directories = new Set<string>();
          const attrs = (p: string) => {
            const n = nodes.get(p);
            return n && { mode: n.mode, size: n.data?.length ?? 0, uid: 1000, gid: 1000, atime: 1, mtime: 1 };
          };
          for (const event of ["LSTAT", "FSTAT"] as const)
            sftp.on(event, (id: number, p: string | Buffer) => {
              const a = attrs(p.toString());
              a ? sftp.attrs(id, a) : sftp.status(id, 2);
            });
          sftp.on("REALPATH", (id, p) =>
            sftp.name(id, [{ filename: p, longname: p, attrs: attrs(p) ?? assert.fail("missing path") }]),
          );
          sftp.on("OPEN", (id, p, flags) => {
            if (flags !== 1) {
              mutationCalls++;
              sftp.status(id, 3);
            } else sftp.handle(id, Buffer.from(p));
          });
          sftp.on("READ", (id, h, position, length) => {
            reads++;
            onRead();
            const data = nodes.get(h.toString())?.data;
            if (!data || position >= data.length) sftp.status(id, 1);
            else sftp.data(id, data.subarray(position, position + length));
          });
          sftp.on("OPENDIR", (id, p) => {
            directories.delete(p);
            sftp.handle(id, Buffer.from(p));
          });
          sftp.on("READDIR", (id, h) => {
            const p = h.toString();
            if (directories.has(p)) return sftp.status(id, 1);
            directories.add(p);
            const names = [...nodes.keys()].filter((n) => path.posix.dirname(n) === p);
            if (names.length === 0) return sftp.status(id, 1);
            sftp.name(
              id,
              names.map((n) => ({
                filename: path.posix.basename(n),
                longname: n,
                attrs: attrs(n) ?? assert.fail("missing path"),
              })),
            );
          });
          sftp.on("CLOSE", (id) => sftp.status(id, 0));
          for (const event of ["WRITE", "REMOVE", "MKDIR", "RMDIR", "RENAME", "SETSTAT", "FSETSTAT"] as const)
            sftp.on(event, (id: number) => {
              mutationCalls++;
              sftp.status(id, 3);
            });
        }),
      ),
    );
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return {
    sandbox: {
      ssh_endpoint: `127.0.0.1:${address.port}`,
      ssh_host_key: hostPin,
      client_key_path: keyPath,
      proxy_auth_handle: "p",
    },
    state: () => ({ mutationCalls, live, reads }),
    onRead: (hook: () => void) => {
      onRead = hook;
    },
    close: () => new Promise<void>((done) => server.close(() => done())),
  };
}

async function observedRetired(predicate: () => boolean) {
  for (let i = 0; i < 100 && !predicate(); i++) await new Promise((r) => setTimeout(r, 5));
  assert.equal(predicate(), true, "peer retirement observed before fixture teardown");
}

test("actual pinned SFTP performs bounded READDIR and EOF verification and retires its dedicated connection", async () => {
  const root = await fs.realpath(await mkdtemp(path.join(tmpdir(), "cogs-snapshot-ssh-")));
  const f = mountedFixture(true);
  const server = await snapshotSshServer(f.nodes, root);
  try {
    const document = { ...launch(`sha256:${"a".repeat(64)}`, f.bundle.digest), sandbox: server.sandbox };
    await withSnapshotSftp(document, new AbortController().signal, (port, signal) =>
      verifyCogsMountedSkillBundle(port, f.bundle, "/shared/skills", signal),
    );
    await observedRetired(() => server.state().live === 0);
    assert.equal(server.state().mutationCalls, 0);
    assert.equal(server.state().live, 0);
    assert.ok(server.state().reads > 0);
    const reads = server.state().reads;
    await assert.rejects(
      withSnapshotSftp(
        { ...document, sandbox: { ...server.sandbox, ssh_host_key: `SHA256:${"A".repeat(43)}` } },
        new AbortController().signal,
        async () => assert.fail("untrusted SSH"),
      ),
    );
    assert.equal(server.state().reads, reads);
  } finally {
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

async function withSupervisor(
  run: (f: {
    preparer: ReturnType<typeof createCogsMountedSkillSessionPreparer>;
    workerRoot: string;
    document: LaunchConfig;
    requests: Array<Record<string, unknown>>;
    sockets: Set<Socket>;
    lost: Promise<void>;
    losses: () => number;
    shared: ReturnType<typeof mountedFixture>;
    server: Awaited<ReturnType<typeof snapshotSshServer>>;
  }) => Promise<void>,
  mode = "ok",
  spoofRootCustody = true,
) {
  const root = await fs.realpath(await mkdtemp(path.join(tmpdir(), "cogs-snapshot-lease-")));
  const shared = mountedFixture(),
    user = mountedFixture(false, "user", true);
  const ssh = await snapshotSshServer(new Map([...shared.nodes, ...user.nodes]), root);
  const receiptPath = path.join(root, "receipt.json"),
    socketPath = path.join(root, "control.sock");
  const document = {
    ...launch(`sha256:${"a".repeat(64)}`, user.bundle.digest),
    sandbox: ssh.sandbox,
    limits: {
      cpu: 1,
      memory_bytes: 536870912,
      tool_timeout_seconds: 1,
      turn_timeout_seconds: 61,
      max_tool_output_bytes: 4096,
    },
  };
  const receipt = {
    ...receiptFor(shared, user),
    launch_digest: `sha256:${createHash("sha256").update(canonicalSnapshot(document)).digest("hex")}`,
  };
  await writeFile(receiptPath, canonicalSnapshot(receipt), { mode: 0o440 });
  const requests: Array<Record<string, unknown>> = [],
    sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => undefined);
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      if (!buffer.endsWith("\n")) return;
      const request = JSON.parse(buffer) as Record<string, unknown>;
      requests.push(request);
      buffer = "";
      if (mode === "silent" || (mode === "heartbeat-lost" && request.op === "ping")) return;
      if (mode === "release-lost" && request.op === "release") {
        socket.destroy();
        return;
      }
      const reply: Record<string, unknown> = {
        ...request,
        op: request.op === "acquire" ? "leased" : request.op === "ping" ? "alive" : "released",
      };
      if (request.op === "acquire") {
        if (mode === "wrong-nonce") reply.nonce = "0".repeat(32);
        if (mode === "wrong-receipt") reply.receipt_digest = `sha256:${"0".repeat(64)}`;
        if (mode === "oversize") {
          socket.write("X".repeat(1025));
          return;
        }
      }
      const response = canonicalSnapshot(reply);
      socket.write(mode === "duplicate" ? response.repeat(2) : response);
    });
  });
  await new Promise<void>((done) => server.listen(socketPath, done));
  await chmod(socketPath, 0o660);
  if (mode === "missing-receipt") await unlink(receiptPath);
  if (mode === "receipt-mode") await chmod(receiptPath, 0o600);
  if (mode === "socket-mode") await chmod(socketPath, 0o666);
  if (mode === "receipt-link") await fs.link(receiptPath, path.join(root, "linked"));
  if (mode === "receipt-symlink") {
    await rename(receiptPath, `${receiptPath}.original`);
    await fs.symlink(`${receiptPath}.original`, receiptPath);
  }
  if (mode === "launch-mismatch") {
    await chmod(receiptPath, 0o600);
    await writeFile(receiptPath, canonicalSnapshot({ ...receipt, launch_digest: `sha256:${"0".repeat(64)}` }));
    await chmod(receiptPath, 0o440);
  }
  // Portable protocol units model root metadata, NOT host/mount qualification.
  // Production has no uid/path-capture override; same-uid unmocked custody rejects.
  const parents = new Set<string>([receiptPath, socketPath]);
  for (let p = root; ; p = path.dirname(p)) {
    parents.add(p);
    if (p === "/") break;
  }
  const originalStat = fs.lstat,
    originalOpen = fs.open;
  const spoof = <T extends Awaited<ReturnType<typeof fs.lstat>>>(stat: T, p: string): T => {
    if (!spoofRootCustody || !parents.has(p)) return stat;
    const big = typeof stat.uid === "bigint";
    Object.assign(stat, { uid: big ? 0n : 0 });
    if (stat.isDirectory())
      Object.assign(stat, {
        mode: big ? 0o40755n : 0o40755,
        size: big ? 0n : 0,
        nlink: big ? 2n : 2,
        mtimeNs: 1n,
        ctimeNs: 1n,
      });
    return stat;
  };
  if (spoofRootCustody) {
    mock.method(fs, "lstat", async (...args: Parameters<typeof fs.lstat>) =>
      spoof(await originalStat(...args), String(args[0])),
    );
    mock.method(fs, "open", async (...args: Parameters<typeof fs.open>) => {
      const handle = await originalOpen(...args),
        original = handle.stat.bind(handle);
      mock.method(handle, "stat", async (...statArgs: Parameters<typeof handle.stat>) =>
        spoof(await original(...statArgs), String(args[0])),
      );
      return handle;
    });
  }
  syncBuiltinESMExports();
  let losses = 0;
  const lost = Promise.withResolvers<void>();
  const preparer = createCogsMountedSkillSessionPreparer({
    receiptPath,
    controlSocketPath: socketPath,
    onLost: () => {
      losses++;
      lost.resolve();
    },
    sharedResolver: {
      resolve: async () => ({
        manifestDigest: document.skills.shared_revision,
        bundleDigest: shared.bundle.digest,
        bundle: shared.bundle,
      }),
    } as never,
    privateStore: { snapshot: async () => ({ digest: user.bundle.digest, bundle: user.bundle }) } as never,
    ssh: {
      withSftp: async (_options: unknown, op: (port: CogsSftpPort, signal: AbortSignal) => Promise<unknown>) =>
        op(
          {
            lstat: async () => {
              throw new CogsSftpStatusError("no_such_file");
            },
          } as never,
          new AbortController().signal,
        ),
    } as never,
  });
  try {
    await run({
      preparer,
      workerRoot: root,
      document,
      requests,
      sockets,
      lost: lost.promise,
      losses: () => losses,
      shared,
      server: ssh,
    });
  } finally {
    mock.restoreAll();
    syncBuiltinESMExports();
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((done) => server.close(() => done()));
    await ssh.close();
    await rm(root, { recursive: true, force: true });
  }
}

test("mounted consumer needs runtime custody plus canonical live admission, releases once and preserves publication", async () => {
  await withSupervisor(async (f) => {
    const before = structuredClone(f.shared.nodes);
    const prepared = await f.preparer.prepare({ launch: f.document });
    assert.equal(prepared.metadata.shared.readOnlyEnforced, true);
    assert.equal(prepared.metadata.user.readOnlyEnforced, true);
    assert.equal(isRuntimeReadOnlySkillSet(prepared.metadata.shared), true);
    assert.equal(isRuntimeReadOnlySkillSet(Object.freeze({ ...prepared.metadata.shared })), false);
    assert.equal(prepared.metadata.agentsStatus, "missing");
    assert.equal(prepared.piSkills.length, 1);
    assert.match(prepared.eagerTrustedSkillPrompt, /shared/);
    await assert.rejects(f.preparer.prepare({ launch: f.document }), /invalid skill preparation/);
    await Promise.all([prepared.dispose(), prepared.dispose()]);
    assert.equal(isRuntimeReadOnlySkillSet(prepared.metadata.shared), false);
    assert.equal(f.requests.filter((r) => r.op === "release").length, 1);
    assert.equal(f.requests[0]?.pid, process.pid);
    assert.match(String(f.requests[0]?.nonce), /^[a-f0-9]{32}$/);
    assert.equal(f.losses(), 0);
    assert.equal(f.server.state().mutationCalls, 0);
    assert.deepEqual(structuredClone(f.shared.nodes), before);
    await observedRetired(() => f.sockets.size === 0);
    assert.equal(f.sockets.size, 0, "lease retired before fixture teardown");
    assert.equal(f.server.state().live, 0);
  });
});

test("bounded short reads, receipt custody and launch/bundle mismatches fail without authority", async () => {
  const f = mountedFixture(false, "shared", false, Buffer.alloc(32 * 1024));
  const read = f.port.read;
  let reads = 0;
  f.port.read = (h, b, o, _l, p, s) => {
    reads++;
    return read(h, b, o, 1, p, s);
  };
  await assert.rejects(verifyCogsMountedSkillBundle(f.port, f.bundle, "/shared/skills", new AbortController().signal));
  assert.ok(reads > 100 && reads < 8192);
  for (const mode of [
    "missing-receipt",
    "receipt-mode",
    "socket-mode",
    "receipt-link",
    "receipt-symlink",
    "launch-mismatch",
  ])
    await withSupervisor(async (f) => {
      await assert.rejects(f.preparer.prepare({ launch: f.document }));
      assert.equal(f.requests.length, 0, mode);
      assert.equal(f.server.state().reads, 0, mode);
    }, mode);
  await withSupervisor(async (f) => {
    f.shared.bundle = buildCogsSkillBundle({ entries: [] });
    await assert.rejects(f.preparer.prepare({ launch: f.document }));
    assert.deepEqual(
      f.requests.map((r) => r.op),
      ["acquire", "release"],
    );
    assert.equal(f.server.state().reads, 0);
  });
});

test("supervisor loss during SFTP aborts preparation and retires the in-flight reader", async () => {
  await withSupervisor(async (f) => {
    f.server.onRead(() => {
      for (const socket of f.sockets) socket.destroy();
    });
    await assert.rejects(f.preparer.prepare({ launch: f.document }));
    await f.lost;
    await observedRetired(() => f.server.state().live === 0);
    assert.equal(f.losses(), 1);
    assert.equal(f.server.state().mutationCalls, 0);
  });
});

test("runtime read-only identity survives authenticated and native Pi admission without model network", async () => {
  await withSupervisor(async (f) => {
    const cwd = path.join(f.workerRoot, "workspace"),
      agentDir = path.join(f.workerRoot, "agent");
    await mkdir(cwd);
    await mkdir(agentDir);
    const unused = async () => {
      throw new Error("no tool work authorized");
    };
    let modelReads = 0;
    const prepared = await f.preparer.prepare({ launch: f.document });
    // Exercise the two SDK admission layers; portable SSH used a temporary key above.
    const launchDocument = {
      ...f.document,
      sandbox: {
        ...f.document.sandbox,
        client_key_path: "/run/cogs/ssh/fixture",
        proxy_auth_handle: "sessions/s/proxy",
      },
    };
    const pi = await createAuthenticatedCogsPiSession({
      cwd,
      agentDir,
      sessionRoot: path.join(f.workerRoot, "sessions"),
      launchDocument,
      skillPreparer: Object.freeze({ prepare: async () => prepared }),
      modelApiKeys: {
        withApiKey: async (_request, consume) => {
          modelReads++;
          await consume("synthetic-model-key");
        },
      },
      toolPorts: { read: unused, write: unused, edit: unused, bash: unused },
      emit: () => true,
      onFatal: () => assert.fail("unexpected Pi failure"),
    });
    try {
      assert.equal(modelReads, 1);
      assert.equal(pi.skillMetadata()?.shared.readOnlyEnforced, true);
      assert.equal(pi.skillMetadata()?.user.readOnlyEnforced, true);
    } finally {
      await pi.dispose();
    }
    await observedRetired(() => f.sockets.size === 0 && f.server.state().live === 0);
    assert.equal(f.losses(), 0);
  });
});

test("same-uid receipt/socket cannot supply production authority", async () => {
  await withSupervisor(
    async (f) => {
      await assert.rejects(f.preparer.prepare({ launch: f.document }));
      assert.equal(f.requests.length, 0);
      assert.equal(f.server.state().reads, 0);
    },
    "ok",
    false,
  );
});

test("missing, mismatched, duplicate, oversized and absent live admissions fail before SFTP", async () => {
  for (const mode of ["wrong-nonce", "wrong-receipt", "duplicate", "oversize", "silent"])
    await withSupervisor(async (f) => {
      await assert.rejects(f.preparer.prepare({ launch: f.document }));
      assert.equal(f.losses(), 1, mode);
      assert.equal(f.server.state().reads, 0, mode);
      assert.equal(f.server.state().mutationCalls, 0, mode);
    }, mode);
});

test("supervisor death, heartbeat expiry and lost release fail closed without removing publication", async () => {
  for (const mode of ["death", "heartbeat-lost", "release-lost"])
    await withSupervisor(async (f) => {
      const prepared = await f.preparer.prepare({ launch: f.document });
      const before = structuredClone(f.shared.nodes);
      if (mode === "death") for (const socket of f.sockets) socket.destroy();
      if (mode === "release-lost") await assert.rejects(prepared.dispose());
      await f.lost;
      assert.equal(f.losses(), 1);
      assert.equal(isRuntimeReadOnlySkillSet(prepared.metadata.shared), false);
      await assert.rejects(prepared.dispose());
      assert.deepEqual(structuredClone(f.shared.nodes), before);
      assert.equal(f.server.state().mutationCalls, 0);
    }, mode);
});

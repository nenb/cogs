import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore } from "ajv";
import { createCogsGitMapStore } from "../src/session/git-map.ts";
import { createCogsJsonlHistoryStore } from "../src/session/jsonl-history.ts";
import { createCogsLocalExporter } from "../src/session/local-export.ts";
import type { CogsPreparedSkillMetadata } from "../src/skills/session-preparer.ts";

const require = createRequire(import.meta.url);
const Ajv = require("ajv/dist/2020") as new (options?: Record<string, unknown>) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;

const shared = `sha256:${"a".repeat(64)}` as const;
const user = `sha256:${"b".repeat(64)}` as const;

function header(id = "session-1") {
  return { type: "session", version: 3, id, timestamp: "2026-07-17T00:00:00.000Z", cwd: "/workspace" };
}
function entry(id: string, parentId: string | null, text = "hello") {
  return {
    type: "message",
    id,
    parentId,
    timestamp: "2026-07-17T00:00:00.000Z",
    message: { role: "user", content: text },
  };
}
function jsonl(lines: readonly unknown[]) {
  return `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`;
}
function metadata(): CogsPreparedSkillMetadata {
  return Object.freeze({
    shared: Object.freeze({
      scope: "shared",
      revision: shared,
      bundleDigest: shared,
      guestRoot: "/shared/skills",
      guestSubtree: "/shared/skills/x",
      fileCount: 1,
      byteCount: 1,
      readOnlyEnforced: false,
    }),
    user: Object.freeze({
      scope: "user",
      revision: user,
      bundleDigest: user,
      guestRoot: "/user/skills",
      guestSubtree: "/user/skills/y",
      fileCount: 1,
      byteCount: 1,
      readOnlyEnforced: false,
    }),
    agentsStatus: "missing",
    skillCount: 0,
  });
}
function sha(bytes: Buffer) {
  return createHash("sha256").update(bytes).digest("hex");
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function assertStillPending<T>(promise: Promise<T>): Promise<void> {
  const sentinel = Symbol("pending");
  assert.equal(
    await Promise.race([
      promise.then(
        () => "settled",
        () => "settled",
      ),
      new Promise((done) => setTimeout(done, 50, sentinel)),
    ]),
    sentinel,
  );
}

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "cogs-local-export-"));
  const sessionFile = join(root, "session.jsonl");
  const prefix = jsonl([header(), entry("aaaaaaaa", null)]);
  await writeFile(sessionFile, prefix);
  const history = createCogsJsonlHistoryStore({ sessionFile, sessionDir: root });
  await history.initialize();
  const gitMap = await createCogsGitMapStore({ sessionDir: root });
  await gitMap.append({
    version: "cogs.git-mapping/v1alpha1",
    repo: "repo",
    commit: "c".repeat(40),
    session: "session-1",
    entry: "aaaaaaaa",
    turn: 1,
    observed_at: "2026-07-17T00:00:00.000Z",
    confidence: "exact",
  });
  return { root, sessionFile, prefix, history, gitMap };
}

test("local export writes deterministic raw bundle, hashes, schema, modes, and durable-prefix bytes", async () => {
  const t = await setup();
  try {
    await writeFile(t.sessionFile, `${t.prefix}${JSON.stringify(entry("bbbbbbbb", "aaaaaaaa", "secret-chat-ok"))}\n`);
    await t.gitMap.append({
      version: "cogs.git-mapping/v1alpha1",
      repo: "repo",
      commit: "d".repeat(40),
      session: "session-1",
      entry: "bbbbbbbb",
      turn: 2,
      observed_at: "2026-07-17T00:00:00.000Z",
      confidence: "exact",
    });
    const colonSessionExporter = createCogsLocalExporter({
      sessionDir: t.root,
      sessionId: "session:colon",
      history: t.history,
      gitMap: t.gitMap,
      skillMetadata: metadata,
    });
    const colonDescriptor = await colonSessionExporter.createExport();
    assert.equal(colonDescriptor.bundle, "cogs-session-session:colon");
    assert.equal(
      await readFile(join(t.root, "exports", "cogs-session-session:colon", "session.jsonl"), "utf8"),
      t.prefix,
    );
    await colonSessionExporter.dispose();
    await rm(join(t.root, "exports", "cogs-session-session:colon"), { recursive: true });
    const exporter = createCogsLocalExporter({
      sessionDir: t.root,
      sessionId: "session-1",
      history: t.history,
      gitMap: t.gitMap,
      skillMetadata: metadata,
      model: { provider: "test", id: "model" },
    });
    const first = await exporter.createExport();
    const second = await exporter.createExport();
    assert.deepEqual(second, first);
    assert.equal(first.bundle, "cogs-session-session-1");
    assert.equal(first.sensitive, true);
    assert.equal(first.sanitized, false);
    const bundle = join(t.root, "exports", first.bundle);
    assert.deepEqual((await readdir(bundle)).sort(), [
      "git-map.json",
      "manifest.json",
      "session.jsonl",
      "skills.json",
      "transform-report.json",
      "warnings.json",
    ]);
    assert.equal(await readFile(join(bundle, "session.jsonl"), "utf8"), t.prefix);
    for (const name of await readdir(bundle)) assert.equal((await lstat(join(bundle, name))).mode & 0o777, 0o600);
    assert.equal((await lstat(bundle)).mode & 0o777, 0o700);
    const git = JSON.parse(await readFile(join(bundle, "git-map.json"), "utf8"));
    assert.equal(git.records.length, 1);
    assert.equal(git.records[0].entry, "aaaaaaaa");
    const warnings = JSON.parse(await readFile(join(bundle, "warnings.json"), "utf8"));
    assert.deepEqual(warnings.warnings, [{ code: "git_mapping_beyond_durable_prefix", count: 1 }]);
    const manifestPath = join(bundle, "manifest.json");
    const originalManifest = await readFile(manifestPath, "utf8");
    const tampered = JSON.parse(originalManifest);
    tampered.files[0].sha256 = "0".repeat(64);
    await writeFile(manifestPath, `${JSON.stringify(tampered)}\n`);
    await assert.rejects(exporter.createExport(), /local export unavailable/);
    assert.equal(await readFile(manifestPath, "utf8"), `${JSON.stringify(tampered)}\n`);
    await writeFile(manifestPath, originalManifest);
    await t.history.flushSettled();
    await t.gitMap.append({
      version: "cogs.git-mapping/v1alpha1",
      repo: "repo",
      commit: "e".repeat(40),
      session: "session-1",
      entry: "bbbbbbbb",
      turn: 3,
      observed_at: "2026-07-17T00:00:00.000Z",
      confidence: "exact",
    });
    const later = await exporter.createExport();
    assert.notEqual(later.manifest_sha256, first.manifest_sha256);
    assert.match(await readFile(join(bundle, "session.jsonl"), "utf8"), /secret-chat-ok/);
    assert.deepEqual((await readdir(join(t.root, "exports"))).sort(), ["cogs-session-session-1"]);
    const skills = JSON.parse(await readFile(join(bundle, "skills.json"), "utf8"));
    assert.deepEqual(skills, { version: "cogs.skills-export/v1alpha1", shared_revision: shared, user_revision: user });
    const report = JSON.parse(await readFile(join(bundle, "transform-report.json"), "utf8"));
    assert.equal(report.mode, "raw");
    assert.equal(report.sanitized, false);
    assert.equal(report.anonymized, false);
    const manifestBytes = await readFile(join(bundle, "manifest.json"));
    assert.equal(sha(manifestBytes), later.manifest_sha256);
    const manifest = JSON.parse(manifestBytes.toString("utf8"));
    assert.equal(manifest.cogs_version, "0.0.0");
    assert.equal(manifest.pi_version, "0.80.6");
    assert.equal(manifest.mode, "raw");
    assert.equal(manifest.attachments_included, false);
    assert.deepEqual(
      manifest.files.map((f: { path: string }) => f.path),
      ["git-map.json", "session.jsonl", "skills.json", "transform-report.json", "warnings.json"],
    );
    for (const file of manifest.files) assert.equal(file.sha256, sha(await readFile(join(bundle, file.path))));
    const ajv = new Ajv({ strict: true });
    addFormats(ajv);
    const schema = JSON.parse(
      await readFile(join(import.meta.dirname, "../schemas/export-manifest-v1alpha1.json"), "utf8"),
    );
    assert.equal(ajv.validate(schema, manifest), true, ajv.errorsText());
    const sidecars =
      ["git-map.json", "skills.json", "warnings.json", "transform-report.json", "manifest.json"].join("\n") +
      (await Promise.all(
        ["git-map.json", "skills.json", "warnings.json", "transform-report.json", "manifest.json"].map((name) =>
          readFile(join(bundle, name), "utf8"),
        ),
      ));
    assert.equal(sidecars.includes("secret-chat-ok"), false);
    await exporter.dispose();
  } finally {
    await rm(t.root, { recursive: true, force: true });
  }
});

test("local export rejects absent or hostile skills and hostile preexisting final without deleting it", async () => {
  const t = await setup();
  try {
    const absentSkills = createCogsLocalExporter({
      sessionDir: t.root,
      sessionId: "session-1",
      history: t.history,
      gitMap: t.gitMap,
      skillMetadata: () => undefined,
    });
    await assert.rejects(absentSkills.createExport(), /local export unavailable/);
    const hostileSkills = createCogsLocalExporter({
      sessionDir: t.root,
      sessionId: "session-1",
      history: t.history,
      gitMap: t.gitMap,
      skillMetadata: () =>
        Object.freeze({
          ...metadata(),
          shared: Object.freeze({ ...metadata().shared, revision: "not-a-digest" }),
        }) as unknown as CogsPreparedSkillMetadata,
    });
    await assert.rejects(hostileSkills.createExport(), /local export unavailable/);
    const exportsRoot = join(t.root, "exports");
    await mkdir(exportsRoot, { mode: 0o700, recursive: true });
    await mkdir(join(exportsRoot, ".tmp-cogs-session-session-1-deadbeef"), { mode: 0o700 });
    const exporter = createCogsLocalExporter({
      sessionDir: t.root,
      sessionId: "session-1",
      history: t.history,
      gitMap: t.gitMap,
      skillMetadata: metadata,
    });
    await assert.rejects(exporter.createExport(), /local export unavailable/);
    await rm(join(exportsRoot, ".tmp-cogs-session-session-1-deadbeef"), { recursive: true });
    await symlink(t.root, join(exportsRoot, "cogs-session-session-1"));
    await assert.rejects(exporter.createExport(), /local export unavailable/);
    assert.equal((await lstat(join(exportsRoot, "cogs-session-session-1"))).isSymbolicLink(), true);
    await rm(join(exportsRoot, "cogs-session-session-1"));
    const hostile = join(exportsRoot, "cogs-session-session-1");
    await mkdir(hostile, { mode: 0o700 });
    for (const name of ["session.jsonl", "git-map.json", "skills.json", "warnings.json", "transform-report.json"]) {
      await writeFile(join(hostile, name), "{}\n", { mode: 0o600 });
    }
    await writeFile(
      join(hostile, "manifest.json"),
      JSON.stringify({ version: "cogs.export/v1alpha1", session_id: "session-1", extra: true }),
      { mode: 0o600 },
    );
    await assert.rejects(exporter.createExport(), /local export unavailable/);
    assert.equal(
      await readFile(join(hostile, "manifest.json"), "utf8"),
      JSON.stringify({ version: "cogs.export/v1alpha1", session_id: "session-1", extra: true }),
    );
  } finally {
    await rm(t.root, { recursive: true, force: true });
  }
});

test("local export dispose joins late owned callback and rejects after deadline without false success", async () => {
  const t = await setup();
  try {
    const entered = deferred();
    const release = deferred();
    let callbackEntered = false;
    const exporter = createCogsLocalExporter({
      sessionDir: t.root,
      sessionId: "session-1",
      history: t.history,
      gitMap: t.gitMap,
      skillMetadata: metadata,
      onOwnedExportBundle: async () => {
        callbackEntered = true;
        entered.resolve();
        await release.promise;
      },
    });
    const exporting = exporter.createExport();
    await entered.promise;
    assert.equal(callbackEntered, true);
    const disposing = exporter.dispose(Date.now() + 25);
    await assertStillPending(disposing);
    await assertStillPending(exporting);
    const namesBefore = (await readdir(join(t.root, "exports", "cogs-session-session-1"))).sort();
    release.resolve();
    await assert.rejects(disposing, /local export unavailable/i);
    await exporting;
    assert.deepEqual((await readdir(join(t.root, "exports", "cogs-session-session-1"))).sort(), namesBefore);
  } finally {
    await rm(t.root, { recursive: true, force: true });
  }
});

test("local export serializes concurrency, observes cancellation/dispose, and rejects source races", async () => {
  const t = await setup();
  try {
    const exporter = createCogsLocalExporter({
      sessionDir: t.root,
      sessionId: "session-1",
      history: t.history,
      gitMap: t.gitMap,
      skillMetadata: metadata,
    });
    const [a, b] = await Promise.all([exporter.createExport(), exporter.createExport()]);
    assert.deepEqual(a, b);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(exporter.createExport({ signal: controller.signal }), /local export unavailable/);
    await chmod(t.sessionFile, 0o600);
    await writeFile(t.sessionFile, "bad\n");
    await assert.rejects(exporter.createExport(), /local export unavailable/);
    await exporter.dispose();
    await assert.rejects(exporter.createExport(), /local export unavailable/);
  } finally {
    await rm(t.root, { recursive: true, force: true });
  }
});

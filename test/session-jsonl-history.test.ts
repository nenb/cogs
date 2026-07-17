import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import { createCogsJsonlHistoryStore } from "../src/session/jsonl-history.ts";

function header(id = "s") {
  return { type: "session", version: 3, id, timestamp: "2026-07-17T00:00:00.000Z", cwd: "/workspace" };
}
function entry(id: string, parentId: string | null, extra: Record<string, unknown> = {}) {
  return {
    type: "message",
    id,
    parentId,
    timestamp: "2026-07-17T00:00:00.000Z",
    message: { role: "user", content: "x" },
    ...extra,
  };
}
function jsonl(lines: readonly unknown[]) {
  return `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`;
}

test("JSONL history initializes resumed durable boundary and pages native Pi-compatible entries", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-"));
  try {
    const file = join(root, "session.jsonl");
    const lines = [header(), entry("aaaaaaaa", null), entry("bbbbbbbb", "aaaaaaaa", { __proto__: "safe" })];
    await writeFile(file, jsonl(lines));
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    assert.equal(store.durableBytes(), Buffer.byteLength(jsonl(lines)));
    assert.equal(jsonlLineCount(await readText(file)), 3);
    const first = await store.entries({ after: undefined, limit: 1 });
    assert.equal(first.entries.length, 1);
    assert.equal(first.nextAfter, "aaaaaaaa");
    const second = await store.entries({ after: first.nextAfter, limit: 10 });
    assert.equal(second.entries.length, 1);
    assert.equal((second.entries[0] as { id?: unknown }).id, "bbbbbbbb");
    assert.equal(Object.getPrototypeOf(second.entries[0]), Object.prototype);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history new session has zero durable boundary until Pi creates a valid file", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-new-"));
  try {
    const file = join(root, "new.jsonl");
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    assert.equal(store.durableBytes(), 0);
    assert.deepEqual(await store.entries({ after: undefined, limit: 10 }), { entries: [] });
    await assert.rejects(store.flushSettled(), /invalid session history/);
    await writeFile(file, jsonl([header(), entry("aaaaaaaa", null)]));
    await store.flushSettled();
    assert.equal((await store.entries({ after: undefined, limit: 10 })).entries.length, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history exposes only previous durable prefix during mutable run", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-prefix-"));
  try {
    const file = join(root, "session.jsonl");
    const prefix = jsonl([header(), entry("aaaaaaaa", null)]);
    await writeFile(file, prefix);
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    await writeFile(file, `${prefix}${JSON.stringify(entry("bbbbbbbb", "aaaaaaaa"))}\n`);
    assert.equal((await store.entries({ after: undefined, limit: 10 })).entries.length, 1);
    await store.flushSettled();
    assert.equal((await store.entries({ after: undefined, limit: 10 })).entries.length, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history rejects malformed, truncated, oversize, symlink, cursor, race, and cancellation cases", async () => {
  const cases: Array<{ name: string; content: Buffer | string }> = [
    { name: "bad-json", content: "{bad}\n" },
    { name: "no-newline", content: JSON.stringify(header()) },
    { name: "bad-utf8", content: Buffer.from([0xff, 0x0a]) },
    { name: "bad-header", content: jsonl([{ type: "session", version: 2, id: "s" }]) },
    { name: "bad-entry-id", content: jsonl([header(), entry("nothex", null)]) },
    { name: "missing-parent", content: jsonl([header(), entry("bbbbbbbb", "aaaaaaaa")]) },
    { name: "oversize-line", content: `${JSON.stringify(header())}\n${"x".repeat(1024 * 1024 + 1)}\n` },
  ];
  for (const one of cases) {
    const root = await mkdtemp(join(tmpdir(), `cogs-jsonl-history-${one.name}-`));
    try {
      const file = join(root, "session.jsonl");
      await writeFile(file, one.content);
      const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
      await assert.rejects(store.initialize(), /invalid session history/, one.name);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }

  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-hostile-"));
  try {
    const target = join(root, "target.jsonl");
    const link = join(root, "link.jsonl");
    await writeFile(target, jsonl([header(), entry("aaaaaaaa", null)]));
    await symlink(target, link);
    await assert.rejects(createCogsJsonlHistoryStore({ sessionFile: link, sessionDir: root }).initialize());

    const store = createCogsJsonlHistoryStore({ sessionFile: target, sessionDir: root });
    await store.initialize();
    await assert.rejects(store.entries({ after: "ffffffff", limit: 1 }), /unknown history cursor/);
    await assert.rejects(store.entries({ after: "../bad", limit: 1 }), /invalid session history/);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      store.entries({ after: undefined, limit: 1, signal: controller.signal }),
      /invalid session history/,
    );

    await writeFile(target, jsonl([header(), entry("aaaaaaaa", null), entry("bbbbbbbb", "aaaaaaaa")]));
    await chmod(target, 0o000).catch(() => undefined);
    await assert.rejects(store.flushSettled(), /invalid session history/);
    await chmod(target, 0o600).catch(() => undefined);
  } finally {
    await chmod(root, 0o700).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history rejects replacement by a different regular inode after durable marker", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-replace-"));
  try {
    const file = join(root, "session.jsonl");
    await writeFile(file, jsonl([header(), entry("aaaaaaaa", null)]));
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    const replacement = join(root, "replacement.jsonl");
    await writeFile(replacement, jsonl([header(), entry("aaaaaaaa", null), entry("bbbbbbbb", "aaaaaaaa")]));
    await rename(replacement, file);
    await assert.rejects(store.entries({ after: undefined, limit: 10 }), /invalid session history/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history rejects same-size valid regular-file replacement after durable marker", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-same-size-replace-"));
  try {
    const file = join(root, "session.jsonl");
    const content = jsonl([header(), entry("aaaaaaaa", null)]);
    await writeFile(file, content);
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    const replacement = join(root, "replacement.jsonl");
    await writeFile(replacement, content);
    await rename(replacement, file);
    await assert.rejects(store.flushSettled(), /invalid session history/);
    await assert.rejects(store.entries({ after: undefined, limit: 10 }), /invalid session history/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history rejects new-session directory replacement before first durable file", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-new-dir-root-"));
  const sessionDir = join(root, "session-dir");
  const movedDir = join(root, "session-dir-old");
  try {
    await mkdir(sessionDir);
    const file = join(sessionDir, "session.jsonl");
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir });
    await store.initialize();
    await rename(sessionDir, movedDir);
    await mkdir(sessionDir);
    await writeFile(file, jsonl([header(), entry("aaaaaaaa", null)]));
    await assert.rejects(store.flushSettled(), /invalid session history/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history allows active-run appends while serving only the durable inode prefix", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-active-append-"));
  try {
    const file = join(root, "session.jsonl");
    const prefix = jsonl([header(), entry("aaaaaaaa", null)]);
    await writeFile(file, prefix);
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    await writeFile(file, `${prefix}${JSON.stringify(entry("bbbbbbbb", "aaaaaaaa"))}\n`);
    const page = await store.entries({ after: undefined, limit: 10 });
    assert.equal(page.entries.length, 1);
    assert.equal((page.entries[0] as { id?: unknown }).id, "aaaaaaaa");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history accepts UUID collision-fallback entry IDs and cursors", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-uuid-"));
  try {
    const file = join(root, "session.jsonl");
    const uuid = "123e4567-e89b-12d3-a456-426614174000";
    await writeFile(file, jsonl([header(), entry("aaaaaaaa", null), entry(uuid, "aaaaaaaa")]));
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    assert.equal((await store.entries({ after: "aaaaaaaa", limit: 10 })).entries.length, 1);
    assert.equal((await store.entries({ after: uuid, limit: 10 })).entries.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history validates multibyte UTF-8 split across scanner chunks", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-utf8-split-"));
  try {
    const file = join(root, "session.jsonl");
    const first = `${JSON.stringify(header())}\n`;
    let content = "";
    for (let size = 0; size < 4096; size += 1) {
      const candidate = "a".repeat(size);
      const line = `${JSON.stringify(entry("aaaaaaaa", null, { message: { role: "user", content: `${candidate}😄` } }))}\n`;
      if ((Buffer.byteLength(first) + Buffer.byteLength(line) - Buffer.byteLength('😄"}}\n')) % 4096 === 4095) {
        content = line;
        break;
      }
    }
    assert.notEqual(content, "");
    await writeFile(file, `${first}${content}`);
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    assert.equal((await store.entries({ after: undefined, limit: 10 })).entries.length, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history validates large histories while retaining only bounded pages", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-large-"));
  try {
    const file = join(root, "session.jsonl");
    const lines: unknown[] = [header()];
    let parent: string | null = null;
    for (let index = 0; index < 2500; index += 1) {
      const id = index.toString(16).padStart(8, "0");
      lines.push(entry(id, parent, { message: { role: "user", content: "x".repeat(128) } }));
      parent = id;
    }
    await writeFile(file, jsonl(lines));
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    const page = await store.entries({ after: undefined, limit: 100 });
    assert.equal(page.entries.length, 100);
    assert.equal(page.nextAfter, "00000063");
    assert.equal((await store.entries({ after: "000009c3", limit: 100 })).entries.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JSONL history rejects directory replacement after durable marker", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-dir-replace-root-"));
  const sessionDir = join(root, "session-dir");
  const movedDir = join(root, "session-dir-old");
  try {
    await mkdir(sessionDir);
    const file = join(sessionDir, "session.jsonl");
    await writeFile(file, jsonl([header(), entry("aaaaaaaa", null)]));
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir });
    await store.initialize();
    await rename(sessionDir, movedDir);
    await mkdir(sessionDir);
    await writeFile(file, jsonl([header(), entry("aaaaaaaa", null)]));
    await assert.rejects(store.entries({ after: undefined, limit: 10 }), /invalid session history/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("pinned Pi SessionManager JSONL remains readable by the history store", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-jsonl-history-pi-"));
  try {
    const manager = SessionManager.create("/workspace", root, { id: "pi-session" });
    manager.appendMessage({ role: "user", content: "hello", timestamp: Date.now() } as never);
    manager.appendMessage({
      role: "assistant",
      content: [{ type: "text", text: "hi" }],
      api: "anthropic-messages",
      provider: "anthropic",
      model: "claude-sonnet-4-5",
      usage: {
        input: 1,
        output: 1,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 2,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "stop",
      timestamp: Date.now(),
    } as never);
    const file = manager.getSessionFile();
    assert.ok(file);
    const store = createCogsJsonlHistoryStore({ sessionFile: file, sessionDir: root });
    await store.initialize();
    const page = await store.entries({ after: undefined, limit: 10 });
    assert.equal(page.entries.length, 2);
    assert.equal(jsonlLineCount(await readText(file)), 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

async function readText(path: string): Promise<string> {
  const { readFile } = await import("node:fs/promises");
  return readFile(path, "utf8");
}

function jsonlLineCount(text: string): number {
  return text.split("\n").filter((line) => line.length > 0).length;
}

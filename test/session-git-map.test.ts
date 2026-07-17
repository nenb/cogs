import assert from "node:assert/strict";
import { chmod, link, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { type CogsGitMapRecord, createCogsGitMapStore } from "../src/session/git-map.ts";

const A = "a".repeat(40);
const B = "b".repeat(40);
const C = "c".repeat(64);

function rec(overrides: Partial<CogsGitMapRecord> = {}): CogsGitMapRecord {
  return {
    version: "cogs.git-mapping/v1alpha1",
    repo: "repo-1",
    commit: A,
    session: "session-1",
    entry: "1234abcd",
    turn: 1,
    observed_at: "2026-07-17T00:00:00.000Z",
    confidence: "exact",
    ...overrides,
  } as CogsGitMapRecord;
}

function canonical(record: CogsGitMapRecord): string {
  const ordered: Record<string, unknown> = {
    version: record.version,
    repo: record.repo,
    commit: record.commit,
    session: record.session,
    entry: record.entry,
    turn: record.turn,
    observed_at: record.observed_at,
    confidence: record.confidence,
  };
  if (record.confidence === "checkpoint") ordered.checkpoint_ref = record.checkpoint_ref;
  return JSON.stringify(ordered);
}

async function makeRoot(prefix = "cogs-git-map-"): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

async function writeSidecar(root: string, records: readonly CogsGitMapRecord[]): Promise<string> {
  const file = join(root, "git-map.jsonl");
  await writeFile(file, `${records.map(canonical).join("\n")}${records.length === 0 ? "" : "\n"}`, { mode: 0o600 });
  await chmod(file, 0o600);
  return file;
}

test("Git map creates a private append-only sidecar, fsyncs, and exposes frozen snapshots", async () => {
  const root = await makeRoot();
  try {
    const store = await createCogsGitMapStore({ sessionDir: root });
    const first = await store.append(rec());
    assert.deepEqual(first, rec());
    assert.ok(Object.isFrozen(first));
    const checkpoint = rec({
      commit: B,
      entry: "2222bbbb",
      turn: 2,
      confidence: "checkpoint",
      checkpoint_ref: "refs/cogs/sessions/session-1/2",
    });
    await store.append(checkpoint);
    const records = store.records();
    assert.ok(Object.isFrozen(records));
    assert.ok(Object.isFrozen(records[0]));
    assert.equal(records.length, 2);
    assert.equal(
      await readFile(join(root, "git-map.jsonl"), "utf8"),
      `${canonical(rec())}\n${canonical(checkpoint)}\n`,
    );
    assert.doesNotMatch(JSON.stringify(records), /\/tmp|git-map\.jsonl|secret|credential|authorization/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Git map resumes canonical existing sidecar and rejects malformed existing content", async () => {
  const malformed = [
    {
      name: "noncanonical",
      body: `${JSON.stringify({ repo: "repo-1", version: "cogs.git-mapping/v1alpha1", commit: A, session: "session-1", entry: "1234abcd", turn: 1, observed_at: "2026-07-17T00:00:00.000Z", confidence: "exact" })}\n`,
    },
    { name: "duplicate", body: `${canonical(rec())}\n${canonical(rec())}\n` },
    { name: "truncated", body: canonical(rec()) },
    { name: "bad-json", body: "{bad}\n" },
    { name: "uuid-entry", body: `${canonical(rec({ entry: "123e4567-e89b-12d3-a456-426614174000" as never }))}\n` },
    { name: "inferred", body: `${canonical(rec({ confidence: "inferred-ancestor" as never }))}\n` },
  ];
  for (const item of malformed) {
    const root = await makeRoot(`cogs-git-map-${item.name}-`);
    try {
      await writeFile(join(root, "git-map.jsonl"), item.body, { mode: 0o600 });
      await chmod(join(root, "git-map.jsonl"), 0o600);
      await assert.rejects(createCogsGitMapStore({ sessionDir: root }), /invalid git map/, item.name);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }

  const root = await makeRoot("cogs-git-map-resume-");
  try {
    await writeSidecar(root, [rec(), rec({ commit: B, entry: "2222bbbb", turn: 2 })]);
    const store = await createCogsGitMapStore({ sessionDir: root });
    assert.equal(store.records().length, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Git map rejects symlink, hardlink, unsafe mode, replacement, truncation, and directory replacement", async () => {
  const root = await makeRoot();
  try {
    const file = await writeSidecar(root, [rec()]);
    await chmod(file, 0o644);
    await assert.rejects(createCogsGitMapStore({ sessionDir: root }), /invalid git map/);
    await chmod(file, 0o400);
    await assert.rejects(createCogsGitMapStore({ sessionDir: root }), /invalid git map/);
    await chmod(file, 0o600);
    await link(file, join(root, "hardlink"));
    await assert.rejects(createCogsGitMapStore({ sessionDir: root }), /invalid git map/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }

  const linkRoot = await makeRoot("cogs-git-map-link-");
  try {
    await writeFile(join(linkRoot, "target"), `${canonical(rec())}\n`, { mode: 0o600 });
    await symlink(join(linkRoot, "target"), join(linkRoot, "git-map.jsonl"));
    await assert.rejects(createCogsGitMapStore({ sessionDir: linkRoot }), /invalid git map/);
  } finally {
    await rm(linkRoot, { recursive: true, force: true });
  }

  const replaceRoot = await makeRoot("cogs-git-map-replace-");
  try {
    const store = await createCogsGitMapStore({ sessionDir: replaceRoot });
    await store.append(rec());
    const replacement = join(replaceRoot, "replacement.jsonl");
    await writeFile(
      replacement,
      `${canonical(rec())}\n${canonical(rec({ commit: B, entry: "2222bbbb", turn: 2 }))}\n`,
      {
        mode: 0o600,
      },
    );
    await chmod(replacement, 0o600);
    await rename(replacement, join(replaceRoot, "git-map.jsonl"));
    await assert.rejects(store.append(rec({ commit: C, entry: "3333cccc", turn: 3 })), /invalid git map/);
    await assert.rejects(store.append(rec({ commit: C, entry: "4444dddd", turn: 4 })), /invalid git map/);
  } finally {
    await rm(replaceRoot, { recursive: true, force: true });
  }

  const dirRoot = await makeRoot("cogs-git-map-dir-");
  const sessionDir = join(dirRoot, "session");
  try {
    await mkdir(sessionDir);
    const store = await createCogsGitMapStore({ sessionDir });
    await rename(sessionDir, join(dirRoot, "old"));
    await mkdir(sessionDir);
    await assert.rejects(store.append(rec()), /invalid git map/);
  } finally {
    await rm(dirRoot, { recursive: true, force: true });
  }
});

test("Git map rejects and poisons raced sidecar creation before first append", async () => {
  const root = await makeRoot();
  try {
    const store = await createCogsGitMapStore({ sessionDir: root });
    await writeSidecar(root, [rec()]);
    await assert.rejects(store.append(rec({ commit: B, entry: "22222222", turn: 2 })), /invalid git map/);
    assert.throws(() => store.records(), /invalid git map/);
    assert.equal(
      (
        await store.resolve({
          repo: "repo-1",
          session: "session-1",
          commit: A,
          nearestAncestor: async () => assert.fail(),
        })
      ).kind,
      "unavailable",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }

  const seamRoot = await makeRoot("cogs-git-map-create-fault-");
  try {
    let armed = true;
    const store = await createCogsGitMapStore(
      { sessionDir: seamRoot },
      {
        fs: {
          open: (async (...args: Parameters<typeof import("node:fs/promises").open>) => {
            if (String(args[0]).endsWith("git-map.jsonl") && armed) {
              armed = false;
              await writeFile(String(args[0]), "", { mode: 0o600 });
              throw new Error("hostile create fault");
            }
            return import("node:fs/promises").then((fs) => fs.open(...args));
          }) as never,
        },
      },
    );
    await assert.rejects(store.append(rec()), /invalid git map/);
    assert.throws(() => store.records(), /invalid git map/);
  } finally {
    await rm(seamRoot, { recursive: true, force: true });
  }
});

test("Git map validates strict append inputs without getters, extras, symbols, bad checkpoint refs, or uppercase commits", async () => {
  const root = await makeRoot();
  try {
    const store = await createCogsGitMapStore({ sessionDir: root });
    const hostile = Object.create(null);
    Object.assign(hostile, rec());
    await assert.rejects(store.append(hostile), /invalid git map/);
    const withGetter = { ...rec() };
    Object.defineProperty(withGetter, "repo", { get: () => "repo-1", enumerable: true });
    await assert.rejects(store.append(withGetter), /invalid git map/);
    await assert.rejects(store.append({ ...rec(), extra: true }), /invalid git map/);
    const nonEnumerable = { ...rec() };
    Object.defineProperty(nonEnumerable, "extra", { value: true, enumerable: false });
    await assert.rejects(store.append(nonEnumerable), /invalid git map/);
    await assert.rejects(store.append({ ...rec(), [Symbol.for("x")]: true }), /invalid git map/);
    await assert.rejects(store.append({ ...rec(), commit: A.toUpperCase() }), /invalid git map/);
    await assert.rejects(store.append({ ...rec(), entry: "123e4567-e89b-12d3-a456-426614174000" }), /invalid git map/);
    await assert.rejects(
      store.append({ ...rec(), confidence: "checkpoint", checkpoint_ref: "refs/cogs/sessions/session-1/2" }),
      /invalid git map/,
    );
    await assert.rejects(store.append({ ...rec(), observed_at: "2026-07-17T00:00:00Z" }), /invalid git map/);
    const hostileProxy = new Proxy(rec() as unknown as Record<string, unknown>, {
      ownKeys() {
        throw new Error("hostile ownKeys leak");
      },
    });
    await assert.rejects(store.append(hostileProxy), (error: unknown) => {
      assert.match(String(error), /invalid git map/);
      assert.doesNotMatch(String(error), /hostile ownKeys leak/);
      return true;
    });
    let getCalled = false;
    const descriptorSource = rec({ commit: B, entry: "22222222", turn: 2 });
    const descriptorProxy = new Proxy(
      {},
      {
        getPrototypeOf: () => Object.prototype,
        ownKeys: () => Reflect.ownKeys(descriptorSource),
        getOwnPropertyDescriptor: (_target, key) => Object.getOwnPropertyDescriptor(descriptorSource, key),
        get() {
          getCalled = true;
          throw new Error("get trap must not run");
        },
      },
    );
    await store.append(descriptorProxy);
    assert.equal(getCalled, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Git map serializes concurrent appends deterministically and observes pre-mutation abort", async () => {
  const root = await makeRoot();
  try {
    const store = await createCogsGitMapStore({ sessionDir: root });
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(store.append(rec(), { signal: controller.signal }), /invalid git map/);
    await Promise.all([
      store.append(rec({ commit: A, entry: "11111111", turn: 1 })),
      store.append(rec({ commit: B, entry: "22222222", turn: 2 })),
      store.append(rec({ commit: C, entry: "33333333", turn: 3 })),
    ]);
    assert.deepEqual(
      store.records().map((record) => record.turn),
      [1, 2, 3],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Git map poisons after uncertain partial append through the FS seam", async () => {
  for (const fault of ["short", "reject"] as const) {
    const root = await makeRoot(`cogs-git-map-partial-${fault}-`);
    try {
      let partial = true;
      const store = await createCogsGitMapStore(
        { sessionDir: root },
        {
          fs: {
            open: (async (...args: Parameters<typeof import("node:fs/promises").open>) => {
              const handle = await import("node:fs/promises").then((fs) => fs.open(...args));
              if (String(args[0]).endsWith("git-map.jsonl") && partial) {
                partial = false;
                return new Proxy(handle, {
                  get(target, prop, receiver) {
                    if (prop === "write") {
                      return async () => {
                        if (fault === "reject") {
                          await target.write(Buffer.from("x"), 0, 1, null);
                          throw new Error("write rejected after partial mutation");
                        }
                        return { bytesWritten: 1, buffer: Buffer.alloc(0) };
                      };
                    }
                    return Reflect.get(target, prop, receiver);
                  },
                }) as never;
              }
              return handle;
            }) as never,
          },
        },
      );
      await assert.rejects(store.append(rec()), /invalid git map/);
      assert.throws(() => store.records(), /invalid git map/);
      assert.equal(
        (
          await store.resolve({
            repo: "repo-1",
            session: "session-1",
            commit: A,
            nearestAncestor: async () => assert.fail(),
          })
        ).kind,
        "unavailable",
      );
      await assert.rejects(store.append(rec({ commit: B, entry: "22222222", turn: 2 })), /invalid git map/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("Git map poisons when post-write sync or close fails", async () => {
  for (const fault of ["sync", "close"] as const) {
    const root = await makeRoot(`cogs-git-map-${fault}-fault-`);
    try {
      let armed = true;
      const store = await createCogsGitMapStore(
        { sessionDir: root },
        {
          fs: {
            open: (async (...args: Parameters<typeof import("node:fs/promises").open>) => {
              const handle = await import("node:fs/promises").then((fs) => fs.open(...args));
              if (String(args[0]).endsWith("git-map.jsonl") && armed) {
                armed = false;
                return new Proxy(handle, {
                  get(target, prop, receiver) {
                    if (prop === "sync" && fault === "sync") return async () => Promise.reject(new Error(fault));
                    if (prop === "close" && fault === "close")
                      return async () => {
                        await target.close();
                        throw new Error(fault);
                      };
                    return Reflect.get(target, prop, receiver);
                  },
                }) as never;
              }
              return handle;
            }) as never,
          },
        },
      );
      await assert.rejects(store.append(rec()), /invalid git map/);
      assert.throws(() => store.records(), /invalid git map/);
      assert.equal(
        (
          await store.resolve({
            repo: "repo-1",
            session: "session-1",
            commit: A,
            nearestAncestor: async () => assert.fail(),
          })
        ).kind,
        "unavailable",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("Git map resolve bounds ancestor candidates before invoking callback", async () => {
  const root = await makeRoot();
  try {
    const records: CogsGitMapRecord[] = [];
    for (let index = 0; index < 257; index += 1) {
      records.push(
        rec({ commit: index.toString(16).padStart(40, "0"), entry: index.toString(16).padStart(8, "0"), turn: index }),
      );
    }
    await writeSidecar(root, records);
    const store = await createCogsGitMapStore({ sessionDir: root });
    const resolved = await store.resolve({
      repo: "repo-1",
      session: "session-1",
      commit: C,
      nearestAncestor: async () => assert.fail(),
    });
    assert.deepEqual(resolved, { kind: "unavailable", repo: "repo-1", session: "session-1", requested_commit: C });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Git map resolve returns exact latest, pre-cogs, inferred ancestor, and unavailable without fabricating mappings", async () => {
  const root = await makeRoot();
  try {
    const store = await createCogsGitMapStore({ sessionDir: root });
    assert.deepEqual(
      await store.resolve({ repo: "repo-1", session: "session-1", commit: A, nearestAncestor: async () => null }),
      {
        kind: "pre-cogs",
        repo: "repo-1",
        session: "session-1",
        requested_commit: A,
      },
    );
    await store.append(rec({ commit: A, entry: "11111111", turn: 1 }));
    await assert.rejects(store.append(rec({ commit: A, entry: "11111111", turn: 1 })), /invalid git map/);
    await store.append(rec({ commit: A, entry: "22222222", turn: 2, observed_at: "2026-07-17T00:00:01.000Z" }));
    await store.append(
      rec({
        commit: B,
        entry: "33333333",
        turn: 3,
        confidence: "checkpoint",
        checkpoint_ref: "refs/cogs/sessions/session-1/3",
      }),
    );
    const exact = await store.resolve({
      repo: "repo-1",
      session: "session-1",
      commit: A,
      nearestAncestor: async () => assert.fail(),
    });
    assert.equal(exact.kind, "mapped");
    assert.equal(exact.kind === "mapped" ? exact.mapping.entry : "", "22222222");
    let callbackInput: unknown;
    const inferred = await store.resolve({
      repo: "repo-1",
      session: "session-1",
      commit: C,
      nearestAncestor: async (input) => {
        callbackInput = input;
        return B;
      },
    });
    assert.equal(inferred.kind, "mapped");
    assert.equal(inferred.kind === "mapped" ? inferred.mapping.confidence : "", "inferred-ancestor");
    assert.equal(inferred.kind === "mapped" ? inferred.mapping.commit : "", C);
    assert.equal(inferred.kind === "mapped" ? inferred.ancestor_commit : "", B);
    assert.equal(inferred.kind === "mapped" ? inferred.source_mapping?.commit : "", B);
    assert.equal(inferred.kind === "mapped" && "checkpoint_ref" in inferred.mapping, false);
    assert.deepEqual(callbackInput, { requested: C, candidates: [B, A] });
    assert.equal(
      (
        await store.resolve({
          repo: "repo-1",
          session: "session-1",
          commit: C,
          nearestAncestor: async () => "d".repeat(40),
        })
      ).kind,
      "unavailable",
    );
    assert.equal(
      (
        await store.resolve({
          repo: "repo-1",
          session: "session-1",
          commit: C,
          nearestAncestor: async () => {
            throw new Error("boom");
          },
        })
      ).kind,
      "unavailable",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

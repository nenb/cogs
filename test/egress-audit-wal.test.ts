import assert from "node:assert/strict";
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  type CogsWalStat,
  type EgressAuditWalAppendInput,
  type EgressAuditWalDeps,
  EgressAuditWalError,
  type EgressAuditWalRecord,
  openEgressAuditWal,
  openEgressAuditWalWithDeps,
} from "../src/egress/audit-wal.ts";

const baseInput: EgressAuditWalAppendInput = Object.freeze({
  session_id: "session-1",
  integration_id: "github",
  route_id: "route-1",
  method: "GET",
  credential_required: true,
});

function options(path: string, extra: Partial<Parameters<typeof openEgressAuditWal>[0]> = {}) {
  return {
    path,
    maxBytes: 4096,
    maxRecords: 8,
    maxRecordBytes: 512,
    nowMs: () => 1_234,
    newIntentId: () => "intent-1",
    ...extra,
  };
}

async function withDir(run: (dir: string) => Promise<void>): Promise<void> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "cogs-wal-test-")));
  await chmod(dir, 0o700);
  try {
    await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function line(record: Partial<Record<keyof EgressAuditWalRecord | "extra", unknown>>): string {
  return JSON.stringify(record).replace(
    /\{.*\}/,
    `{${[
      "version",
      "sequence",
      "intent_id",
      "timestamp_ms",
      "session_id",
      "integration_id",
      "route_id",
      "method",
      "credential_required",
    ]
      .map((key) => `${JSON.stringify(key)}:${JSON.stringify(record[key as keyof EgressAuditWalRecord])}`)
      .join(",")}}`,
  );
}

function record(sequence: number, intent = `intent-${sequence}`, timestamp = 1000 + sequence): EgressAuditWalRecord {
  return {
    version: "cogs.egress-intent/v1alpha1",
    sequence,
    intent_id: intent,
    timestamp_ms: timestamp,
    session_id: "session-1",
    integration_id: "github",
    route_id: "route-1",
    method: "GET",
    credential_required: true,
  };
}

test("WAL appends canonical metadata only, syncs before success, recovers, freezes, and closes once", async () => {
  await withDir(async (dir) => {
    const path = join(dir, "audit.wal");
    let mutableId = 1;
    const mutableOptions = options(path, { newIntentId: () => `intent-${mutableId++}` });
    const wal = await openEgressAuditWal(mutableOptions);
    (mutableOptions as { maxRecords: number; newIntentId: () => string }).maxRecords = 1;
    (mutableOptions as { maxRecords: number; newIntentId: () => string }).newIntentId = () => "mutated-id";
    assert.deepEqual(Object.keys(wal), []);
    const appended = await wal.append(baseInput);
    assert.deepEqual(appended, record(0, "intent-1", 1234));
    assert.equal(Object.isFrozen(appended), true);
    assert.equal(JSON.stringify(appended).includes("path"), false);
    assert.equal(JSON.stringify(appended).includes("query"), false);
    assert.equal(JSON.stringify(appended).includes("authorization"), false);
    assert.equal(JSON.stringify(appended).includes("credential_handle"), false);
    assert.equal(await readFile(path, "utf8"), `${line(record(0, "intent-1", 1234))}\n`);
    assert.equal((await wal.append({ ...baseInput, route_id: "route-2" })).intent_id, "intent-2");
    await Promise.all([wal.close(), wal.close()]);
    await assert.rejects(() => wal.append(baseInput), EgressAuditWalError);

    const recovered = await openEgressAuditWal(options(path, { newIntentId: () => "intent-3" }));
    assert.deepEqual(recovered.records, [
      record(0, "intent-1", 1234),
      { ...record(1, "intent-2", 1234), route_id: "route-2" },
    ]);
    assert.equal(Object.isFrozen(recovered.records), true);
    assert.deepEqual(await recovered.append({ ...baseInput, method: "POST", credential_required: false }), {
      ...record(2, "intent-3", 1234),
      method: "POST",
      credential_required: false,
    });
    await recovered.close();
  });
});

test("WAL rejects untrusted paths, parent/file modes, symlinks, and hard links", async () => {
  await withDir(async (dir) => {
    await assert.rejects(() => openEgressAuditWal(options("relative.wal")), EgressAuditWalError);
    await chmod(dir, 0o755);
    await assert.rejects(() => openEgressAuditWal(options(join(dir, "bad-parent.wal"))), EgressAuditWalError);
    await chmod(dir, 0o700);

    const target = join(dir, "target.wal");
    await writeFile(target, "", { mode: 0o600 });
    const linkPath = join(dir, "link.wal");
    await symlink(target, linkPath);
    await assert.rejects(() => openEgressAuditWal(options(linkPath)), EgressAuditWalError);

    await chmod(target, 0o644);
    await assert.rejects(() => openEgressAuditWal(options(target)), EgressAuditWalError);
    await chmod(target, 0o600);
    const hard = join(dir, "hard.wal");
    await link(target, hard);
    await assert.rejects(() => openEgressAuditWal(options(target)), EgressAuditWalError);

    const realParent = join(dir, "real-parent");
    await mkdir(realParent, { mode: 0o700 });
    const symlinkParent = join(dir, "symlink-parent");
    await symlink(realParent, symlinkParent);
    await assert.rejects(() => openEgressAuditWal(options(join(symlinkParent, "audit.wal"))), EgressAuditWalError);
  });
});

test("WAL recovery rejects corrupt, partial, extra-key, duplicate, noncontiguous, oversized, and too-large files", async () => {
  await withDir(async (dir) => {
    const cases: Array<[string, string, Partial<ReturnType<typeof options>>?]> = [
      ["partial", line(record(0)), {}],
      ["json", "{not-json}\n", {}],
      ["extra", `${JSON.stringify({ ...record(0), extra: true })}\n`, {}],
      ["bad-version", `${line({ ...record(0), version: "bad" })}\n`, {}],
      ["negative-sequence", `${line({ ...record(0), sequence: -1 })}\n`, {}],
      ["bad-timestamp", `${line({ ...record(0), timestamp_ms: -1 })}\n`, {}],
      ["bad-id", `${line({ ...record(0), intent_id: "bad/slash" })}\n`, {}],
      ["long-id", `${line({ ...record(0), intent_id: `i${"a".repeat(128)}` })}\n`, {}],
      ["bad-method", `${line({ ...record(0), method: "PUT" })}\n`, {}],
      ["bad-bool", `${line({ ...record(0), credential_required: "true" })}\n`, {}],
      ["duplicate", `${line(record(0, "same"))}\n${line(record(1, "same"))}\n`, {}],
      ["gap", `${line(record(1))}\n`, {}],
      ["record-too-large", `${line(record(0))}\n`, { maxRecordBytes: 8 }],
      ["file-too-large", `${line(record(0))}\n`, { maxBytes: 8, maxRecordBytes: 8 }],
    ];
    for (const [name, content, extra] of cases) {
      const path = join(dir, `${name}.wal`);
      await writeFile(path, content, { mode: 0o600 });
      await assert.rejects(() => openEgressAuditWal(options(path, extra)), EgressAuditWalError, name);
    }
  });
});

test("WAL snapshots options during gated open and validates euid", async () => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const file: FakeFile = { data: Buffer.alloc(0), syncs: 0, closes: 0 };
  const base = fakeDeps(file);
  let originalId = 1;
  const mutable = options("/trusted/audit.wal", { maxRecords: 2, newIntentId: () => `original-${originalId++}` });
  const opening = openEgressAuditWalWithDeps(mutable, {
    ...base,
    pathStat: async (path) => {
      await gate;
      return base.pathStat(path);
    },
  });
  mutable.maxRecords = 1;
  mutable.newIntentId = () => "mutated-id";
  release();
  const wal = await opening;
  assert.equal((await wal.append(baseInput)).intent_id, "original-1");
  assert.equal((await wal.append({ ...baseInput, route_id: "route-2" })).intent_id, "original-2");
  await assert.rejects(() => wal.append({ ...baseInput, route_id: "route-3" }), EgressAuditWalError);
  await wal.close().catch(() => undefined);

  await assert.rejects(
    () =>
      openEgressAuditWalWithDeps(
        Object.defineProperty({ ...options("/trusted/getter.wal") }, "path", {
          get() {
            throw new Error("hostile getter");
          },
        }) as ReturnType<typeof options>,
        fakeDeps({ data: Buffer.alloc(0), syncs: 0, closes: 0 }),
      ),
    EgressAuditWalError,
  );

  await assert.rejects(
    () =>
      openEgressAuditWalWithDeps(options("/trusted/euid.wal"), {
        ...fakeDeps({ data: Buffer.alloc(0), syncs: 0, closes: 0 }),
        euid: () => -1,
      }),
    EgressAuditWalError,
  );
});

test("WAL snapshots append input and ignores runtime reserved fields", async () => {
  const file: FakeFile = { data: Buffer.alloc(0), syncs: 0, closes: 0 };
  const wal = await openEgressAuditWalWithDeps(options("/trusted/input.wal"), fakeDeps(file));
  const input: Record<string, unknown> = {
    ...baseInput,
    sequence: 99,
    intent_id: "evil-id",
    timestamp_ms: 99,
    version: "evil",
    host: "example.com",
  };
  const promise = wal.append(input as unknown as EgressAuditWalAppendInput);
  input.session_id = "mutated-session";
  input.method = "POST";
  input.credential_required = false;
  const appended = await promise;
  assert.equal(appended.session_id, "session-1");
  assert.equal(appended.method, "GET");
  assert.equal(appended.credential_required, true);
  assert.equal(appended.sequence, 0);
  assert.equal(appended.intent_id, "intent-1");
  assert.equal(file.data.toString("utf8").includes("example.com"), false);
  await assert.rejects(
    () =>
      wal.append(
        Object.defineProperty({ ...baseInput }, "session_id", {
          get() {
            throw new Error("hostile getter");
          },
        }) as EgressAuditWalAppendInput,
      ),
    EgressAuditWalError,
  );
  await wal.close();
});

test("WAL enforces capacity before writing and serializes concurrent appends", async () => {
  await withDir(async (dir) => {
    const path = join(dir, "audit.wal");
    let id = 0;
    const wal = await openEgressAuditWal(options(path, { maxRecords: 2, newIntentId: () => `intent-${id++}` }));
    const results = await Promise.all([wal.append(baseInput), wal.append({ ...baseInput, route_id: "route-2" })]);
    assert.deepEqual(
      results.map((item) => item.sequence),
      [0, 1],
    );
    await assert.rejects(() => wal.append(baseInput), EgressAuditWalError);
    await assert.rejects(() => wal.append(baseInput), EgressAuditWalError);
    await wal.close().catch(() => undefined);
  });
});

test("WAL honors cancellation only before append begins", async () => {
  await withDir(async (dir) => {
    const path = join(dir, "audit.wal");
    const aborted = new AbortController();
    aborted.abort();
    let nextIntent = 1;
    const wal = await openEgressAuditWal(options(path, { newIntentId: () => `intent-cancel-${nextIntent++}` }));
    await assert.rejects(() => wal.append(baseInput, aborted.signal), EgressAuditWalError);
    assert.equal(wal.ready, true);
    assert.equal(await readFile(path, "utf8"), "");
    assert.equal((await wal.append(baseInput)).intent_id, "intent-cancel-1");
    await wal.close();
  });
});

interface FakeFile {
  data: Buffer;
  syncs: number;
  closes: number;
  failSync?: boolean;
  failClose?: boolean;
  maxWrite?: number;
  wrongStatSize?: boolean;
  syncDirectoryCalls?: number;
  failSyncDirectory?: boolean;
  missingBeforeOpen?: boolean;
  parentRealpath?: string;
  uid?: number;
  onWrite?: () => void;
  maxRead?: number;
  statSize?: number;
}

function fakeStats(size: number, mode = 0o600, nlink = 1, uid = 501): CogsWalStat {
  return { kind: "file", size, mode, nlink, uid, dev: 1, ino: 2, symlink: false };
}

function fakeDeps(file: FakeFile): EgressAuditWalDeps {
  return {
    pathStat: async (path) => {
      if (path.endsWith("/trusted")) {
        return {
          kind: "directory",
          size: 0,
          mode: 0o700,
          nlink: 1,
          uid: file.uid ?? 501,
          dev: 1,
          ino: 1,
          symlink: false,
        };
      }
      if (file.missingBeforeOpen) {
        file.missingBeforeOpen = false;
        throw new Error("missing");
      }
      return fakeStats(file.data.length, 0o600, 1, file.uid ?? 501);
    },
    realpath: async (path) => file.parentRealpath ?? path,
    syncDirectory: async () => {
      file.syncDirectoryCalls = (file.syncDirectoryCalls ?? 0) + 1;
      if (file.failSyncDirectory) throw new Error("directory sync failed");
    },
    euid: () => 501,
    openFile: async () => ({
      stat: async () =>
        fakeStats(file.statSize ?? file.data.length + (file.wrongStatSize ? 1 : 0), 0o600, 1, file.uid ?? 501),
      read: async (position: number, length: number) =>
        file.data.subarray(position, position + Math.min(length, file.maxRead ?? length)),
      write: async (buffer: Buffer, offset: number, length: number) => {
        file.onWrite?.();
        const bytesWritten = Math.min(length, file.maxWrite ?? length);
        file.data = Buffer.concat([file.data, buffer.subarray(offset, offset + bytesWritten)]);
        return bytesWritten;
      },
      sync: async () => {
        file.syncs += 1;
        if (file.failSync) throw new Error("sync failed");
      },
      close: async () => {
        file.closes += 1;
        if (file.failClose) throw new Error("close failed");
      },
    }),
  };
}

test("WAL injectable file port rejects parent/file identity issues and syncs parent before every readiness", async () => {
  await assert.rejects(
    () =>
      openEgressAuditWalWithDeps(
        options("/trusted/audit.wal"),
        fakeDeps({ data: Buffer.alloc(0), syncs: 0, closes: 0, parentRealpath: "/other" }),
      ),
    EgressAuditWalError,
  );
  await assert.rejects(
    () =>
      openEgressAuditWalWithDeps(
        options("/trusted/audit.wal"),
        fakeDeps({ data: Buffer.alloc(0), syncs: 0, closes: 0, uid: 502 }),
      ),
    EgressAuditWalError,
  );
  const created: FakeFile = { data: Buffer.alloc(0), syncs: 0, closes: 0, missingBeforeOpen: true };
  const wal = await openEgressAuditWalWithDeps(options("/trusted/audit.wal"), fakeDeps(created));
  assert.equal(created.syncDirectoryCalls, 1);
  await wal.close();

  const badDirectorySync: FakeFile = {
    data: Buffer.alloc(0),
    syncs: 0,
    closes: 0,
    missingBeforeOpen: true,
    failSyncDirectory: true,
  };
  await assert.rejects(
    () => openEgressAuditWalWithDeps(options("/trusted/dirsync.wal"), fakeDeps(badDirectorySync)),
    EgressAuditWalError,
  );
  assert.equal(badDirectorySync.closes, 1);

  const corrupt: FakeFile = { data: Buffer.from("partial"), syncs: 0, closes: 0 };
  await assert.rejects(
    () => openEgressAuditWalWithDeps(options("/trusted/corrupt.wal"), fakeDeps(corrupt)),
    EgressAuditWalError,
  );
  assert.equal(corrupt.closes, 1);
});

test("WAL injectable file port covers partial writes, sync poison, close failure, and bounded sentinel read", async () => {
  const partialController = new AbortController();
  const partial: FakeFile = {
    data: Buffer.alloc(0),
    syncs: 0,
    closes: 0,
    maxWrite: 3,
    onWrite: () => partialController.abort(),
  };
  const wal = await openEgressAuditWalWithDeps(options("/trusted/audit.wal"), fakeDeps(partial));
  await wal.append(baseInput, partialController.signal);
  assert.match(partial.data.toString("utf8"), /"intent_id":"intent-1"/);
  await wal.close();
  assert.equal(partial.closes, 1);

  const duplicate = await openEgressAuditWalWithDeps(
    options("/trusted/duplicate.wal", { newIntentId: () => "same" }),
    fakeDeps({ data: Buffer.alloc(0), syncs: 0, closes: 0 }),
  );
  await duplicate.append(baseInput);
  await assert.rejects(() => duplicate.append({ ...baseInput, route_id: "route-2" }), EgressAuditWalError);

  const statFile: FakeFile = { data: Buffer.alloc(0), syncs: 0, closes: 0 };
  const statMismatch = await openEgressAuditWalWithDeps(options("/trusted/stat.wal"), fakeDeps(statFile));
  statFile.wrongStatSize = true;
  await assert.rejects(() => statMismatch.append(baseInput), EgressAuditWalError);

  const clean = await openEgressAuditWalWithDeps(
    options("/trusted/clean.wal"),
    fakeDeps({ data: Buffer.alloc(0), syncs: 0, closes: 0 }),
  );
  await clean.close();
  await clean.close();
  await assert.rejects(() => clean.append(baseInput), EgressAuditWalError);

  const syncFailure: FakeFile = { data: Buffer.alloc(0), syncs: 0, closes: 0, failSync: true };
  const badSync = await openEgressAuditWalWithDeps(options("/trusted/sync.wal"), fakeDeps(syncFailure));
  await assert.rejects(() => badSync.append(baseInput), EgressAuditWalError);
  await assert.rejects(() => badSync.append(baseInput), EgressAuditWalError);

  const closeSyncFailure: FakeFile = { data: Buffer.alloc(0), syncs: 0, closes: 0, failSync: true };
  const badCloseSync = await openEgressAuditWalWithDeps(options("/trusted/close-sync.wal"), fakeDeps(closeSyncFailure));
  await assert.rejects(() => badCloseSync.close(), EgressAuditWalError);
  await assert.rejects(() => badCloseSync.close(), EgressAuditWalError);
  assert.equal(closeSyncFailure.syncs, 1);
  assert.equal(closeSyncFailure.closes, 1);

  const closeFailure: FakeFile = { data: Buffer.alloc(0), syncs: 0, closes: 0, failClose: true };
  const badClose = await openEgressAuditWalWithDeps(options("/trusted/close.wal"), fakeDeps(closeFailure));
  await assert.rejects(() => badClose.close(), EgressAuditWalError);
  await assert.rejects(() => badClose.close(), EgressAuditWalError);
  assert.equal(closeFailure.syncs, 1);
  assert.equal(closeFailure.closes, 1);
  await assert.rejects(() => badClose.append(baseInput), EgressAuditWalError);

  const shortReads = Buffer.from(`${line(record(0))}\n`);
  const recovered = await openEgressAuditWalWithDeps(
    options("/trusted/short-reads.wal"),
    fakeDeps({ data: shortReads, syncs: 0, closes: 0, maxRead: 2 }),
  );
  assert.equal(recovered.records.length, 1);
  await recovered.close();

  const growth = Buffer.alloc(10, 0x61);
  await assert.rejects(
    () =>
      openEgressAuditWalWithDeps(
        options("/trusted/growth.wal", { maxBytes: 9, maxRecordBytes: 9 }),
        fakeDeps({ data: growth, statSize: 9, syncs: 0, closes: 0 }),
      ),
    EgressAuditWalError,
  );

  const oversized: FakeFile = { data: Buffer.alloc(10, 0x61), syncs: 0, closes: 0 };
  await assert.rejects(
    () =>
      openEgressAuditWalWithDeps(
        options("/trusted/oversized.wal", { maxBytes: 9, maxRecordBytes: 9 }),
        fakeDeps(oversized),
      ),
    EgressAuditWalError,
  );
});

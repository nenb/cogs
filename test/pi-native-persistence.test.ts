import assert from "node:assert/strict";
import { appendFileSync, chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import { installNativePersistence, openStrictNativeSession } from "../src/pi/native-persistence.ts";

function fixture(t: { after(fn: () => void): void }) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "cogs-native-fence-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const pending = SessionManager.create(dir, dir);
  const path = pending.getSessionFile() as string;
  writeFileSync(path, `${JSON.stringify(pending.getHeader())}\n`, { mode: 0o600, flag: "wx" });
  const manager = openStrictNativeSession(path, dir, dir);
  return { dir, path, manager };
}
const options = () => ({ onPoison: () => {}, isAtRest: () => true, acknowledge: async () => {} });

test("native append frontier is instance-local and includes branches and compaction", async (t) => {
  const a = fixture(t),
    b = fixture(t);
  const prototype = SessionManager.prototype._persist;
  const fence = installNativePersistence(a.manager, options());
  const first = await fence.commitAtRest();
  const id = a.manager.appendCustomEntry("test", { n: 1 });
  assert.equal(fence.state().durable, first);
  a.manager.appendThinkingLevelChange("off");
  a.manager.appendModelChange("synthetic", "model");
  a.manager.appendSessionInfo("synthetic");
  a.manager.appendMessage({ role: "user", content: "synthetic", timestamp: 0 });
  a.manager.appendCustomMessageEntry("test", "synthetic", false);
  a.manager.appendLabelChange(id, "label");
  a.manager.appendCompaction("summary", id, 1);
  a.manager.branch(id);
  a.manager.branchWithSummary(id, "summary");
  a.manager.resetLeaf();
  a.manager.appendCustomEntry("root");
  const last = await fence.commitAtRest();
  assert.equal(last.entries, 10);
  assert.equal(last.revision, 10);
  assert.equal(fence.requireComplete(), last);
  assert.equal(SessionManager.prototype._persist, prototype);
  b.manager.appendCustomEntry("unaffected");
  for (const operation of [
    () => a.manager.newSession(),
    () => a.manager.setSessionFile(b.path),
    () => a.manager.createBranchedSession(id),
  ])
    assert.throws(operation);
  assert.equal(fence.requireComplete(), last);
});

for (const mode of ["before", "partial", "complete"] as const)
  test(`native ${mode} write failure poisons before caller normalization`, async (t) => {
    const { manager, path } = fixture(t);
    const native = manager._persist;
    let armed = false;
    let sealed = false;
    manager._persist = function (entry) {
      if (!armed) return native.call(this, entry);
      if (mode === "partial") appendFileSync(path, '{"type":');
      if (mode === "complete") native.call(this, entry);
      throw new Error("synthetic abort/cancel secret path");
    };
    const fence = installNativePersistence(manager, {
      ...options(),
      onPoison: () => {
        sealed = true;
      },
    });
    const first = await fence.commitAtRest();
    armed = true;
    assert.throws(() => manager.appendCustomEntry("fault"), { message: "native persistence native-write" });
    assert.equal(sealed, true);
    const count = manager.getEntries().length;
    armed = false;
    assert.throws(() => manager.appendCustomEntry("sdk-caught-error"));
    assert.equal(manager.getEntries().length, count);
    await assert.rejects(fence.commitAtRest());
    assert.throws(() => fence.requireComplete());
    assert.equal(fence.state().durable, first);
  });

for (const mode of ["shorter", "overwrite", "memory", "serialization", "owner-marker", "owner-reentrant"] as const)
  test(`sticky frontier rejects ${mode}`, async (t) => {
    const { manager, path } = fixture(t);
    let armed = false;
    const fence = installNativePersistence(manager, {
      ...options(),
      acknowledge: async () => {
        if (armed && mode === "owner-marker") throw new Error("private diagnostic");
        if (armed && mode === "owner-reentrant") fence.poison("activity");
      },
    });
    manager.appendCustomEntry("test", { value: "aaa" });
    const first = await fence.commitAtRest();
    const bytes = readFileSync(path);
    armed = true;
    if (mode === "serialization") {
      const circular: { self?: unknown } = {};
      circular.self = circular;
      assert.throws(() => manager.appendCustomEntry("bad", circular));
    } else if (mode === "shorter") {
      manager.appendCustomEntry("missing-tail");
      writeFileSync(path, bytes);
    } else if (mode === "overwrite") writeFileSync(path, bytes.toString().replace("aaa", "bbb"));
    else if (mode === "memory") Object.assign(manager.getEntries()[0] as object, { customType: "mutated" });
    else manager.appendCustomEntry("tail");
    await assert.rejects(fence.commitAtRest());
    assert.equal(fence.state().durable, first);
    writeFileSync(path, bytes);
    armed = false;
    await assert.rejects(fence.commitAtRest());
  });

test("actual activity and owner acknowledgment exclude commit/admission, no timeout proof", async (t) => {
  const { manager } = fixture(t);
  let finish!: () => void;
  const barrier = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const fence = installNativePersistence(manager, options());
  await fence.commitAtRest();
  const operation = fence.track(() => barrier);
  assert.equal(fence.state().active, 1);
  await assert.rejects(fence.commitAtRest());
  finish();
  await operation;
  assert.equal(fence.state().active, 0);
  await assert.rejects(fence.commitAtRest());
});

test("strict open excludes migration and malformed native tolerant parsing without rewriting", (t) => {
  const { path, dir } = fixture(t);
  for (const bytes of ['{"type":"session","version":2}\n', '{"type":"session","version":3}\n', "invalid\n", ""]) {
    writeFileSync(path, bytes);
    assert.throws(() => openStrictNativeSession(path, dir, dir));
    assert.equal(readFileSync(path, "utf8"), bytes);
  }
});

test("valid noncanonical v3 wire prefix is preserved on native append", async (t) => {
  const { path, dir, manager } = fixture(t);
  writeFileSync(path, `${JSON.stringify(manager.getHeader(), null, 0)}  \r\n`);
  chmodSync(path, 0o600);
  const reopened = openStrictNativeSession(path, dir, dir);
  const fence = installNativePersistence(reopened, options());
  const before = readFileSync(path);
  reopened.appendCustomEntry("tail");
  await fence.commitAtRest();
  assert.deepEqual(readFileSync(path).subarray(0, before.length), before);
});

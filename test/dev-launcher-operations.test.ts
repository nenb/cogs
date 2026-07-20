import assert from "node:assert/strict";
import type { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { ApiClient, ApiEvent } from "../dev/launcher/api-client.ts";
import { parseLauncherArgs } from "../dev/launcher/cli.ts";
import type { LauncherProfile } from "../dev/launcher/contract.ts";
import { canonicalJson } from "../dev/launcher/contract.ts";
import { beginWorkerStartup, bindWorkerChild, createApiToken, promoteWorkerReady } from "../dev/launcher/control.ts";
import {
  type LauncherOperationContext,
  type LauncherOperationSeams,
  runLauncherOperation,
} from "../dev/launcher/operations.ts";
import {
  createState,
  type LauncherState,
  readManifest,
  resolveLauncherState,
  writePhase,
} from "../dev/launcher/state.ts";

const revision = "d".repeat(40);
const parentDigest = `sha256:${"1".repeat(64)}`;
const childDigest = `sha256:${"2".repeat(64)}`;

async function roots() {
  const dir = await mkdtemp(join(tmpdir(), "cogs-ops-"));
  await chmod(dir, 0o700);
  const launcherRoot = join(await realpath(dir), "launcher");
  const exportRoot = join(await realpath(dir), "exports");
  await mkdir(launcherRoot, { mode: 0o700 });
  await mkdir(exportRoot, { mode: 0o700 });
  const ctx = Object.freeze({ launcherRoot, repoRoot: await realpath(dir), exportRoot, sourceRevision: revision });
  return { dir, ctx };
}

async function sandbox(ctx: LauncherOperationContext, name: string, profile: LauncherProfile = "linux-kvm") {
  const state = await resolveLauncherState({ root: ctx.launcherRoot, name, sourceRevision: revision });
  const manifest = await createState(state, profile);
  await writePhase(state, manifest, "sandbox-ready");
  return state;
}

async function ready(state: LauncherState) {
  await createApiToken(
    state,
    Object.freeze({ randomBytes: Object.freeze(() => Buffer.alloc(32, 7)) as typeof randomBytes, identity }),
  );
  const startup = await beginWorkerStartup(
    state,
    Object.freeze({
      randomBytes: Object.freeze(() => Buffer.alloc(32, 8)) as typeof randomBytes,
      identity,
      parentPid: 111,
    }),
  );
  await bindWorkerChild(
    state,
    Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "child-identity",
      startupDigest: startup.startup.digest(),
      pid: 222,
      pidIdentity: childDigest,
    }),
    Object.freeze({ identity }) as never,
  );
  await promoteWorkerReady(
    state,
    Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "child-ready",
      startupDigest: startup.startup.digest(),
      pid: 222,
      pidIdentity: childDigest,
      apiPort: 12345,
    }),
    Object.freeze({ identity }) as never,
  );
  startup.startup.dispose();
}

const identity = Object.freeze((pid: number) => (pid === 111 ? parentDigest : childDigest));
function client(calls: string[]): ApiClient {
  let aborted = false,
    correlation = "corr-1";
  return Object.freeze({
    request: Object.freeze(async (op: string, input?: Readonly<Record<string, unknown>>) => {
      calls.push(
        `${op}:${Object.keys(input ?? {})
          .sort()
          .join("+")}`,
      );
      if (op === "run") {
        correlation = `corr-${calls.filter((x) => x.startsWith("run:")).length}`;
        return Object.freeze({ accepted: true, duplicate: false, run_state: "running", correlation_id: correlation });
      }
      if (op === "abort") {
        aborted = true;
        return Object.freeze({ aborted: true, run_state: "aborting" });
      }
      if (op === "entries")
        return Object.freeze({ entries: [{ secret: "redacted" }], next: `cursor.${"x".repeat(32)}` });
      if (op === "export")
        return Object.freeze({ version: "cogs.export-response/v1alpha1", sensitive: true, bundle: { secret: "kept" } });
      if (op === "shutdown") return Object.freeze({ accepted: true });
      throw new Error("unexpected");
    }) as ApiClient["request"],
    events: Object.freeze(async function* () {
      calls.push(aborted ? "event:run_aborted" : "event:run_settled");
      yield Object.freeze({
        id: 8,
        data: Object.freeze({ kind: "run_settled", correlation_id: "old-corr" }),
      }) as ApiEvent;
      const data = Object.freeze({ kind: aborted ? "run_aborted" : "run_settled", correlation_id: correlation });
      yield Object.freeze({ id: 9, data }) as ApiEvent;
    }) as ApiClient["events"],
  });
}

function opSeams(calls: string[]): Partial<LauncherOperationSeams> {
  return Object.freeze({
    createSandbox: Object.freeze(
      async (o: { root: string; name: string; profile: LauncherProfile; sourceRevision: string }) => {
        const state = await sandbox(
          { launcherRoot: o.root, repoRoot: o.root, exportRoot: o.root, sourceRevision: o.sourceRevision },
          o.name,
          o.profile,
        );
        calls.push("create");
        return Object.freeze({ manifest: await readManifest(state), workerReady: false });
      },
    ) as never,
    startWorkerForState: Object.freeze(async (state: LauncherState) => {
      await realpath(state.lockDir);
      calls.push("start");
      await ready(state);
      const manifest = await readManifest(state);
      return Object.freeze({
        version: "cogs.dev-launcher-supervisor/v1alpha1",
        stateId: state.stateId,
        profile: manifest.profile,
        authority: manifest.authority,
        phase: manifest.phase,
        apiPort: 12345,
      });
    }) as never,
    stopWorkerForState: Object.freeze(async (state: LauncherState) => {
      calls.push("stop");
      const manifest = await readManifest(state);
      await writePhase(state, manifest, "sandbox-ready");
      return Object.freeze({
        version: "cogs.dev-launcher-supervisor/v1alpha1",
        stateId: state.stateId,
        profile: manifest.profile,
        authority: manifest.authority,
        phase: "sandbox-ready",
      });
    }) as never,
    launcherInventory: Object.freeze(async (state: LauncherState) => {
      const manifest = await readManifest(state);
      return Object.freeze({
        version: "cogs.dev-launcher-inventory/v1alpha1",
        stateId: state.stateId,
        profile: manifest.profile,
        authority: manifest.authority,
        phase: manifest.phase,
        descriptor: "none",
        workerLive: false,
        recovery: "absent",
        cleanupRequired: false,
        driverState: "absent",
      });
    }) as never,
    destroySandbox: Object.freeze(async () => {
      calls.push("destroy");
      return Object.freeze({ removed: true });
    }) as never,
    createApiClient: Object.freeze(() => client(calls)) as never,
    readPromptFile: Object.freeze(async () => "fixed prompt") as never,
    writeSensitiveExport: Object.freeze(async (_root: string, rel: string, value: unknown) => {
      calls.push(`write:${rel}:${canonicalJson(value).includes("kept")}`);
      return rel;
    }) as never,
  });
}

test("launcher parser accepts exact start operation only", () => {
  assert.equal(parseLauncherArgs(["--profile", "linux-kvm", "--state", "s", "start"]).op, "start");
  assert.throws(() => parseLauncherArgs(["--profile", "linux-kvm", "--state", "s", "start", "--prompt-file", "p"]));
});

test("dispatcher runs API operations under ready token and returns metadata only", async () => {
  const { dir, ctx } = await roots();
  try {
    await sandbox(ctx, "api");
    await ready(await resolveLauncherState({ root: ctx.launcherRoot, name: "api", sourceRevision: revision }));
    const calls: string[] = [];
    const seams = opSeams(calls);
    const run = await runLauncherOperation(
      Object.freeze({ op: "run", profile: "linux-kvm", state: "api", promptFile: "p.txt" }),
      ctx,
      seams,
    );
    assert.deepEqual(run, { op: "run", terminal: "run_settled", lastEventId: 9, eventCount: 2 });
    assert.equal(JSON.stringify(run).includes("fixed prompt"), false);
    assert.equal(
      (
        await runLauncherOperation(
          Object.freeze({ op: "history", profile: "linux-kvm", state: "api", limit: 1 }),
          ctx,
          seams,
        )
      ).count,
      1,
    );
    assert.equal(
      (
        await runLauncherOperation(
          Object.freeze({ op: "export", profile: "linux-kvm", state: "api", out: "x.json" }),
          ctx,
          seams,
        )
      ).written,
      true,
    );
    assert.equal(
      (await runLauncherOperation(Object.freeze({ op: "abort", profile: "linux-kvm", state: "api" }), ctx, seams))
        .aborted,
      true,
    );
    assert(calls.includes("write:x.json:true"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("fixed smoke uses dispatcher sequence and leaves metadata-only output", async () => {
  const { dir, ctx } = await roots();
  const calls: string[] = [];
  try {
    const result = await runLauncherOperation(
      Object.freeze({ op: "smoke", profile: "linux-kvm", state: "full" }),
      ctx,
      opSeams(calls),
    );
    assert.equal(result.complete, true);
    assert.deepEqual(
      calls.filter((x) => ["create", "start", "stop", "destroy"].includes(x)),
      ["create", "start", "stop", "destroy"],
    );
    assert(calls.indexOf("shutdown:") >= 0 && calls.indexOf("shutdown:") < calls.indexOf("stop"));
    assert(calls.includes("event:run_aborted"));
    assert.equal(JSON.stringify(result).includes("kept"), false);
    assert.equal(JSON.stringify(result).includes(ctx.launcherRoot), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("shutdown always awaits exact stop after graceful failure", async () => {
  const { dir, ctx } = await roots();
  try {
    await sandbox(ctx, "shut");
    await ready(await resolveLauncherState({ root: ctx.launcherRoot, name: "shut", sourceRevision: revision }));
    const calls: string[] = [];
    let awaited = false;
    const seams = Object.freeze({
      ...opSeams(calls),
      createApiClient: Object.freeze(() =>
        Object.freeze({
          request: Object.freeze(async () => {
            throw new Error("api");
          }),
        }),
      ) as never,
      stopWorkerForState: Object.freeze(async (state: LauncherState) => {
        await Promise.resolve();
        awaited = true;
        return await (opSeams(calls).stopWorkerForState as never as (s: LauncherState) => Promise<unknown>)(state);
      }) as never,
    });
    await assert.rejects(() =>
      runLauncherOperation(Object.freeze({ op: "shutdown", profile: "linux-kvm", state: "shut" }), ctx, seams),
    );
    assert.equal(awaited, true);
    assert(calls.includes("stop"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("shutdown still stops when token read fails", async () => {
  const { dir, ctx } = await roots();
  try {
    const state = await sandbox(ctx, "notoken");
    await ready(state);
    await unlink(join(state.controlDir, "api-token"));
    const calls: string[] = [];
    await assert.rejects(() =>
      runLauncherOperation(
        Object.freeze({ op: "shutdown", profile: "linux-kvm", state: "notoken" }),
        ctx,
        opSeams(calls),
      ),
    );
    assert(calls.includes("stop"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("run rejects terminal event past maximum", async () => {
  const { dir, ctx } = await roots();
  try {
    await sandbox(ctx, "many");
    await ready(await resolveLauncherState({ root: ctx.launcherRoot, name: "many", sourceRevision: revision }));
    const seams = Object.freeze({
      ...opSeams([]),
      createApiClient: Object.freeze(() =>
        Object.freeze({
          request: Object.freeze(async () => Object.freeze({ correlation_id: "corr-many" })) as ApiClient["request"],
          events: Object.freeze(async function* () {
            for (let id = 1; id <= 1001; id += 1)
              yield Object.freeze({
                id,
                data: Object.freeze({ kind: id === 1001 ? "run_settled" : "warning", correlation_id: "corr-many" }),
              }) as ApiEvent;
          }) as ApiClient["events"],
        }),
      ) as never,
    });
    await assert.rejects(() =>
      runLauncherOperation(
        Object.freeze({ op: "run", profile: "linux-kvm", state: "many", promptFile: "p.txt" }),
        ctx,
        seams,
      ),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("macos start failure has no API fallback", async () => {
  const { dir, ctx } = await roots();
  const calls: string[] = [];
  try {
    await sandbox(ctx, "mac", "macos-vm");
    const seams = Object.freeze({
      ...opSeams(calls),
      startWorkerForState: Object.freeze(async () => {
        calls.push("start-failed");
        throw new Error("missing prerequisite");
      }) as never,
    });
    await assert.rejects(() =>
      runLauncherOperation(Object.freeze({ op: "start", profile: "macos-vm", state: "mac" }), ctx, seams),
    );
    assert.deepEqual(calls, ["start-failed"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("dispatcher rejects hostile core result getters without invocation", async () => {
  const { dir, ctx } = await roots();
  let invoked = false;
  try {
    const bad = {};
    Object.defineProperty(bad, "manifest", {
      enumerable: true,
      get: () => {
        invoked = true;
        throw new Error("boom");
      },
    });
    const seams = Object.freeze({
      ...opSeams([]),
      createSandbox: Object.freeze(async () => Object.freeze(bad)) as never,
    });
    await assert.rejects(() =>
      runLauncherOperation(Object.freeze({ op: "create", profile: "linux-kvm", state: "bad" }), ctx, seams),
    );
    assert.equal(invoked, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("status inventory uncertainty does not fall back", async () => {
  const { dir, ctx } = await roots();
  try {
    await sandbox(ctx, "stat");
    const calls: string[] = [];
    const seams = Object.freeze({
      ...opSeams(calls),
      launcherInventory: Object.freeze(async () => {
        throw new Error("uncertain");
      }) as never,
    });
    await assert.rejects(() =>
      runLauncherOperation(Object.freeze({ op: "status", profile: "linux-kvm", state: "stat" }), ctx, seams),
    );
    assert.deepEqual(calls, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("dispatcher rejects hostile request and preabort before side effects", async () => {
  const { dir, ctx } = await roots();
  const calls: string[] = [];
  try {
    let invoked = false;
    const hostile = { op: "status", profile: "linux-kvm", state: "x" } as Record<string, unknown>;
    Object.defineProperty(hostile, "state", {
      enumerable: true,
      get: () => {
        invoked = true;
        throw new Error("boom");
      },
    });
    await assert.rejects(() => runLauncherOperation(Object.freeze(hostile) as never, ctx, opSeams(calls)));
    assert.equal(invoked, false);
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(() =>
      runLauncherOperation(
        Object.freeze({ op: "create", profile: "linux-kvm", state: "x" }),
        Object.freeze({ ...ctx, signal: ac.signal }),
        opSeams(calls),
      ),
    );
    assert.deepEqual(calls, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("smoke rollback attempts shutdown and destroy on intermediate failure", async () => {
  const { dir, ctx } = await roots();
  const calls: string[] = [];
  try {
    const seams = Object.freeze({
      ...opSeams(calls),
      writeSensitiveExport: Object.freeze(async () => {
        throw new Error("fail");
      }) as never,
    });
    await assert.rejects(() =>
      runLauncherOperation(Object.freeze({ op: "smoke", profile: "linux-kvm", state: "roll" }), ctx, seams),
    );
    assert(!calls.includes("shutdown:"));
    assert(calls.includes("stop"));
    assert(calls.includes("destroy"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("main uses fixed one-level private dirs without recursive traversal", async () => {
  const text = await readFile(new URL("../dev/launcher/main.ts", import.meta.url), "utf8");
  assert(!text.includes("recursive: true"));
  assert(text.includes("lstat(path)"));
});

test("dispatcher rejects hostile context without invoking getters", async () => {
  const { dir, ctx } = await roots();
  try {
    const hostile = { ...ctx } as Record<string, unknown>;
    Object.defineProperty(hostile, "repoRoot", {
      enumerable: true,
      get: () => {
        throw new Error("boom");
      },
    });
    await assert.rejects(() =>
      runLauncherOperation(
        Object.freeze({ op: "status", profile: "linux-kvm", state: "x" }),
        Object.freeze(hostile) as never,
      ),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

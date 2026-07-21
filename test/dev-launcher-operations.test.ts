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
  LAUNCHER_DETERMINISTIC_ABORT_PROMPT,
  LAUNCHER_DETERMINISTIC_NORMAL_PROMPT,
  LAUNCHER_DETERMINISTIC_S309_PROMPT,
  LAUNCHER_DETERMINISTIC_S309_PROOF_PROMPT,
  LAUNCHER_DETERMINISTIC_S309_SETUP_PROMPT,
} from "../dev/launcher/deterministic-stream.ts";
import {
  type LauncherOperationContext,
  type LauncherOperationSeams,
  runLauncherOperation,
  s309FailureStages,
  s309StageExitCode,
  s309StageFromExitCode,
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
function jsonRecord(values: Record<string, unknown> = {}): Record<string, unknown> {
  const out = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of Object.entries(values)) out[key] = value;
  return Object.freeze(out);
}
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
        calls.push(`content:${input?.content ?? ""}`);
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
        data: Object.freeze({ kind: "run_settled", correlation_id: "old-corr", payload: {} }),
      }) as ApiEvent;
      const data = Object.freeze({
        kind: aborted ? "run_aborted" : "run_settled",
        correlation_id: correlation,
        payload: {},
      });
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
    readPromptFile: Object.freeze(async () => LAUNCHER_DETERMINISTIC_NORMAL_PROMPT) as never,
    writeSensitiveExport: Object.freeze(async (_root: string, rel: string, value: unknown) => {
      calls.push(`write:${rel}:${canonicalJson(value).includes("kept")}`);
      return rel;
    }) as never,
  });
}

test("launcher parser accepts exact start operation only", () => {
  assert.equal(parseLauncherArgs(["--profile", "linux-kvm", "--state", "s", "start"]).op, "start");
  assert.equal(parseLauncherArgs(["--profile", "linux-kvm", "--state", "s", "s3-09"]).op, "s3-09");
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
    assert(calls.includes(`content:${LAUNCHER_DETERMINISTIC_NORMAL_PROMPT}`));
    assert(calls.includes(`content:${LAUNCHER_DETERMINISTIC_ABORT_PROMPT}`));
    assert.equal(JSON.stringify(result).includes("kept"), false);
    assert.equal(JSON.stringify(result).includes(ctx.launcherRoot), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("s3-09 failure stages use authentic bounded exit codes only", async () => {
  assert.deepEqual(
    s309FailureStages.map((stage) => s309StageFromExitCode(s309StageExitCode(new Error(stage)))),
    [...s309FailureStages.map(() => undefined)],
  );
  assert.deepEqual(
    s309FailureStages.map((_stage, index) => s309StageFromExitCode(40 + index)),
    [...s309FailureStages],
  );
  assert.equal(s309FailureStages.includes("s3-terminal-proof" as never), false);
  assert.equal(s309FailureStages.includes("s3-egress-proof" as never), false);
  assert.equal(s309FailureStages.includes("s3-proof-run"), true);
  assert.equal(s309FailureStages.includes("s3-proof-terminal"), true);
  assert.equal(s309FailureStages.includes("s3-egress-shape"), true);
  assert.equal(s309StageFromExitCode(40 + s309FailureStages.length), undefined);
  const forged = Object.assign(new Error("x"), { code: 40, s3ExitCode: 40, s3Stage: "s3-create" });
  assert.equal(s309StageExitCode(forged), 1);
  assert.equal(s309StageExitCode(new Proxy(new Error("x"), { get: () => 40 })), 1);
  const { dir, ctx } = await roots();
  try {
    await assert.rejects(
      () =>
        runLauncherOperation(
          Object.freeze({ op: "s3-09", profile: "linux-kvm", state: "s309create" }),
          ctx,
          Object.freeze({
            createSandbox: Object.freeze(async () => {
              throw new Error("hostile proxy secret");
            }) as never,
            destroySandbox: Object.freeze(async () => Object.freeze({ removed: true })) as never,
          }),
        ),
      (error) => s309StageFromExitCode(s309StageExitCode(error)) === "s3-create",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("s3-09 runs fixed integrated KVM scenario with metadata-only proof", async () => {
  const { dir, ctx } = await roots();
  const calls: string[] = [];
  let runCount = 0;
  let proofTerminalSent = false;
  try {
    const seams = Object.freeze({
      ...opSeams(calls),
      createApiClient: Object.freeze(() =>
        Object.freeze({
          request: Object.freeze(async (op: string, input?: Readonly<Record<string, unknown>>) => {
            calls.push(
              `${op}:${Object.keys(input ?? {})
                .sort()
                .join("+")}`,
            );
            if (op === "run") {
              runCount += 1;
              calls.push(`content:${input?.content ?? ""}`);
              return Object.freeze({
                accepted: true,
                duplicate: false,
                run_state: "running",
                correlation_id: `s309-${runCount}`,
              });
            }
            if (op === "entries") {
              const after = input?.after;
              return after === undefined
                ? Object.freeze({
                    version: "cogs.entries/v1alpha1",
                    entries: [{}, {}],
                    next: `cursor.${"x".repeat(32)}`,
                  })
                : Object.freeze({ version: "cogs.entries/v1alpha1", entries: [{}, {}] });
            }
            if (op === "export")
              return Object.freeze({
                version: "cogs.export-response/v1alpha1",
                sensitive: true,
                bundle: Object.freeze({
                  version: "cogs.export-descriptor/v1alpha1",
                  mode: "raw",
                  attachments_included: false,
                  sensitive: true,
                  sanitized: false,
                  anonymized: false,
                  raw_export_opening: Object.freeze({
                    version: "cogs.launcher.raw-export-opening/v1alpha1",
                    opened_with: "pinned-pi-session-manager",
                    session_jsonl_openable: true,
                    current_session: true,
                    content_redacted: true,
                  }),
                }),
              });
            if (op === "shutdown") return Object.freeze({ accepted: true });
            throw new Error("unexpected");
          }) as ApiClient["request"],
          events: Object.freeze(async function* (after?: number, limit?: number) {
            calls.push(`events:${after ?? 0}:${limit ?? 0}`);
            if (runCount === 2 && after === 0 && !proofTerminalSent && limit !== 1000)
              throw new Error("unexpected live limit");
            if (runCount >= 2 && after === 259 && limit !== 1000) throw new Error("unexpected proof live limit");
            if (after === 0 && proofTerminalSent) {
              const error = new Error("launcher api replay gap");
              Object.defineProperty(error, "code", { value: "COGS_LAUNCHER_API_REPLAY_GAP" });
              throw error;
            }
            if (runCount === 1) {
              yield Object.freeze({
                id: 1,
                data: Object.freeze({ kind: "run_settled", correlation_id: "s309-1", payload: {} }),
              }) as ApiEvent;
              return;
            }
            if (after === 259) {
              while (runCount < 3) await new Promise((resolve) => setTimeout(resolve, 0));
              proofTerminalSent = true;
              yield Object.freeze({
                id: 260,
                data: Object.freeze({
                  kind: "run_settled",
                  correlation_id: "s309-3",
                  payload: jsonRecord({
                    s3_09_proof: jsonRecord({
                      version: "cogs.launcher.s3-09-proof/v1alpha1",
                      scenario: "s3-09",
                      profile: "linux-kvm",
                      outcome: "pass",
                      credential_route_200: true,
                      denied_route_absent: true,
                      total_exact_expected: true,
                      fixture_ready: true,
                      fixture_baseline_captured: true,
                    }),
                  }),
                }),
              }) as ApiEvent;
              return;
            }
            yield Object.freeze({
              id: 2,
              data: Object.freeze({ kind: "git_mapping", correlation_id: "s309-2", payload: {} }),
            }) as ApiEvent;
            for (let id = 3; id <= 258; id += 1) {
              yield Object.freeze({
                id,
                data: Object.freeze({ kind: "tool_update", correlation_id: "s309-2", payload: { chunk: "metadata" } }),
              }) as ApiEvent;
            }
            yield Object.freeze({
              id: 259,
              data: Object.freeze({ kind: "run_settled", correlation_id: "s309-2", payload: {} }),
            }) as ApiEvent;
          }) as ApiClient["events"],
        }),
      ) as never,
    });
    const result = await runLauncherOperation(
      Object.freeze({ op: "s3-09", profile: "linux-kvm", state: "s309" }),
      ctx,
      seams,
    );
    assert.equal(result.complete, true);
    assert.equal(result.egressProof, true);
    assert.equal(result.liveEventCount, 259);
    assert.equal(result.liveEventCount > 32, true);
    const proofEventsIndex = calls.indexOf("events:259:1000");
    const proofRunIndex = calls.indexOf(`content:${LAUNCHER_DETERMINISTIC_S309_PROOF_PROMPT}`);
    assert(calls.includes("events:0:1000"));
    assert(proofEventsIndex >= 0 && proofRunIndex > proofEventsIndex);
    assert.deepEqual(result.history, { pages: 2, entries: 4 });
    assert.deepEqual(result.rawExport, {
      descriptorValidated: true,
      mode: "raw",
      sensitive: true,
      rawExportOpened: true,
    });
    assert(calls.includes(`content:${LAUNCHER_DETERMINISTIC_S309_SETUP_PROMPT}`));
    assert(calls.includes(`content:${LAUNCHER_DETERMINISTIC_S309_PROMPT}`));
    assert(calls.includes(`content:${LAUNCHER_DETERMINISTIC_S309_PROOF_PROMPT}`));
    assert.equal(JSON.stringify(result).includes("credential"), false);
    assert.equal(JSON.stringify(result).includes("localhost"), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("s3-09 proof path rejects live proof at or below replay capacity 32", async () => {
  const { dir, ctx } = await roots();
  let runCount = 0;
  try {
    const seams = Object.freeze({
      ...opSeams([]),
      createApiClient: Object.freeze(() =>
        Object.freeze({
          request: Object.freeze(async (op: string) => {
            if (op === "run")
              return Object.freeze({
                accepted: true,
                duplicate: false,
                run_state: "running",
                correlation_id: `s309-short-${++runCount}`,
              });
            if (op === "shutdown") return Object.freeze({ accepted: true });
            throw new Error("unexpected");
          }) as ApiClient["request"],
          events: Object.freeze(async function* () {
            if (runCount === 1) {
              yield Object.freeze({
                id: 1,
                data: Object.freeze({ kind: "run_settled", correlation_id: "s309-short-1", payload: {} }),
              }) as ApiEvent;
              return;
            }
            yield Object.freeze({
              id: 2,
              data: Object.freeze({ kind: "git_mapping", correlation_id: "s309-short-2", payload: {} }),
            }) as ApiEvent;
            yield Object.freeze({
              id: 3,
              data: Object.freeze({
                kind: "run_settled",
                correlation_id: "s309-short-2",
                payload: jsonRecord({
                  s3_09_proof: jsonRecord({
                    version: "cogs.launcher.s3-09-proof/v1alpha1",
                    scenario: "s3-09",
                    profile: "linux-kvm",
                    outcome: "pass",
                    credential_route_200: true,
                    denied_route_absent: true,
                    total_exact_expected: true,
                    fixture_ready: true,
                    fixture_baseline_captured: true,
                  }),
                }),
              }),
            }) as ApiEvent;
          }) as ApiClient["events"],
        }),
      ) as never,
    });
    await assert.rejects(
      () => runLauncherOperation(Object.freeze({ op: "s3-09", profile: "linux-kvm", state: "s309short" }), ctx, seams),
      (error) => s309StageFromExitCode(s309StageExitCode(error)) === "s3-live-count",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("s3-09 proof path fails closed on missing terminal payload", async () => {
  const { dir, ctx } = await roots();
  let runCount = 0;
  try {
    const seams = Object.freeze({
      ...opSeams([]),
      createApiClient: Object.freeze(() =>
        Object.freeze({
          request: Object.freeze(async (op: string, input?: Readonly<Record<string, unknown>>) => {
            if (op === "run")
              return Object.freeze({
                accepted: true,
                duplicate: false,
                run_state: "running",
                correlation_id: `s309-bad-${++runCount}`,
              });
            if (op === "shutdown") return Object.freeze({ accepted: true });
            if (op === "entries") return Object.freeze({ version: "cogs.entries/v1alpha1", entries: [{}, {}] });
            if (op === "export")
              return Object.freeze({ version: "cogs.export-response/v1alpha1", sensitive: true, bundle: {} });
            throw new Error(String(input));
          }) as ApiClient["request"],
          events: Object.freeze(async function* (after?: number) {
            if (after === 259) {
              while (runCount < 3) await new Promise((resolve) => setTimeout(resolve, 0));
              yield Object.freeze({
                id: 260,
                data: Object.freeze({ kind: "run_settled", correlation_id: "s309-bad-3" }),
              }) as ApiEvent;
              return;
            }
            if (runCount === 1) {
              yield Object.freeze({
                id: 1,
                data: Object.freeze({ kind: "run_settled", correlation_id: "s309-bad-1" }),
              }) as ApiEvent;
              return;
            }
            yield Object.freeze({
              id: 2,
              data: Object.freeze({ kind: "git_mapping", correlation_id: "s309-bad-2" }),
            }) as ApiEvent;
            for (let id = 3; id <= 258; id += 1) {
              yield Object.freeze({
                id,
                data: Object.freeze({
                  kind: "tool_update",
                  correlation_id: "s309-bad-2",
                  payload: { chunk: "metadata" },
                }),
              }) as ApiEvent;
            }
            yield Object.freeze({
              id: 259,
              data: Object.freeze({ kind: "run_settled", correlation_id: "s309-bad-2" }),
            }) as ApiEvent;
          }) as ApiClient["events"],
        }),
      ) as never,
    });
    await assert.rejects(
      () => runLauncherOperation(Object.freeze({ op: "s3-09", profile: "linux-kvm", state: "s309bad" }), ctx, seams),
      (error) => {
        assert.equal(s309StageFromExitCode(s309StageExitCode(error)), "s3-egress-shape");
        return true;
      },
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("s3-09 proof observation run failures use fixed stages", async () => {
  for (const fail of ["run", "terminal"] as const) {
    const { dir, ctx } = await roots();
    let runCount = 0;
    try {
      await assert.rejects(
        () =>
          runLauncherOperation(
            Object.freeze({ op: "s3-09", profile: "linux-kvm", state: `s309-${fail}` }),
            ctx,
            Object.freeze({
              ...opSeams([]),
              createApiClient: Object.freeze(() =>
                Object.freeze({
                  request: Object.freeze(async (op: string) => {
                    if (op !== "run") return Object.freeze({ accepted: true });
                    runCount += 1;
                    if (fail === "run" && runCount === 3) throw new Error("proof run failed");
                    return Object.freeze({
                      accepted: true,
                      duplicate: false,
                      run_state: "running",
                      correlation_id: `proof-${runCount}`,
                    });
                  }) as ApiClient["request"],
                  events: Object.freeze(async function* (after?: number) {
                    if (after === 35) {
                      while (runCount < 3) await new Promise((resolve) => setTimeout(resolve, 0));
                      return;
                    }
                    if (runCount === 1)
                      return yield Object.freeze({
                        id: 1,
                        data: Object.freeze({ kind: "run_settled", correlation_id: "proof-1", payload: {} }),
                      }) as ApiEvent;
                    if (runCount === 3) return;
                    yield Object.freeze({
                      id: 2,
                      data: Object.freeze({ kind: "git_mapping", correlation_id: "proof-2", payload: {} }),
                    }) as ApiEvent;
                    for (let id = 3; id <= 34; id += 1)
                      yield Object.freeze({
                        id,
                        data: Object.freeze({ kind: "tool_update", correlation_id: "proof-2", payload: {} }),
                      }) as ApiEvent;
                    yield Object.freeze({
                      id: 35,
                      data: Object.freeze({ kind: "run_settled", correlation_id: "proof-2", payload: {} }),
                    }) as ApiEvent;
                  }) as ApiClient["events"],
                }),
              ) as never,
            }),
          ),
        (error) => {
          assert.equal(
            s309StageFromExitCode(s309StageExitCode(error)),
            fail === "run" ? "s3-proof-run" : "s3-proof-terminal",
          );
          return true;
        },
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("s3-09 proof path maps fixed egress reasons and rejects hostile proof shapes", async () => {
  const failProof = (reason: string) =>
    jsonRecord({
      version: "cogs.launcher.s3-09-proof/v1alpha1",
      scenario: "s3-09",
      profile: "linux-kvm",
      outcome: "fail",
      reason,
    });
  const getterProof = Object.create(null) as Record<string, unknown>;
  Object.defineProperty(getterProof, "version", {
    enumerable: true,
    get() {
      throw new Error("getter must not run");
    },
  });
  const symbolProof = Object.create(null) as Record<string | symbol, unknown>;
  symbolProof.version = "cogs.launcher.s3-09-proof/v1alpha1";
  symbolProof.scenario = "s3-09";
  symbolProof.profile = "linux-kvm";
  symbolProof.outcome = "fail";
  symbolProof.reason = "generation";
  symbolProof[Symbol("proof")] = true;
  for (const [label, proof, expected] of [
    ["fixture-not-ready", failProof("fixture-not-ready"), "s3-egress-state"],
    ["generation", failProof("generation"), "s3-egress-state"],
    ["inflight", failProof("inflight"), "s3-egress-state"],
    ["credential-count", failProof("credential-count"), "s3-egress-credential"],
    ["denied-forwarded", failProof("denied-forwarded"), "s3-egress-denied"],
    ["total-count", failProof("total-count"), "s3-egress-total"],
    ["extra", jsonRecord({ ...failProof("total-count"), extra: true }), "s3-egress-shape"],
    ["plain", Object.freeze({ ...failProof("generation") }), "s3-egress-shape"],
    ["getter", Object.freeze(getterProof), "s3-egress-shape"],
    ["symbol", Object.freeze(symbolProof), "s3-egress-shape"],
    ["array", Object.freeze([]), "s3-egress-shape"],
  ] as const) {
    const { dir, ctx } = await roots();
    let runCount = 0;
    try {
      await assert.rejects(
        () =>
          runLauncherOperation(
            Object.freeze({ op: "s3-09", profile: "linux-kvm", state: "s309egress" }),
            ctx,
            Object.freeze({
              ...opSeams([]),
              createApiClient: Object.freeze(() =>
                Object.freeze({
                  request: Object.freeze(async (op: string) =>
                    op === "run"
                      ? Object.freeze({
                          accepted: true,
                          duplicate: false,
                          run_state: "running",
                          correlation_id: `s309-egress-${++runCount}`,
                        })
                      : Object.freeze({ accepted: true }),
                  ) as ApiClient["request"],
                  events: Object.freeze(async function* (after?: number) {
                    if (runCount === 1)
                      return yield Object.freeze({
                        id: 1,
                        data: Object.freeze({ kind: "run_settled", correlation_id: "s309-egress-1", payload: {} }),
                      }) as ApiEvent;
                    if (after === 35) {
                      while (runCount < 3) await new Promise((resolve) => setTimeout(resolve, 0));
                      return yield Object.freeze({
                        id: 36,
                        data: Object.freeze({
                          kind: "run_settled",
                          correlation_id: "s309-egress-3",
                          payload: jsonRecord({ s3_09_proof: proof }),
                        }),
                      }) as ApiEvent;
                    }
                    yield Object.freeze({
                      id: 2,
                      data: Object.freeze({ kind: "git_mapping", correlation_id: "s309-egress-2", payload: {} }),
                    }) as ApiEvent;
                    for (let id = 3; id <= 34; id += 1)
                      yield Object.freeze({
                        id,
                        data: Object.freeze({ kind: "tool_update", correlation_id: "s309-egress-2", payload: {} }),
                      }) as ApiEvent;
                    yield Object.freeze({
                      id: 35,
                      data: Object.freeze({
                        kind: "run_settled",
                        correlation_id: "s309-egress-2",
                        payload: {},
                      }),
                    }) as ApiEvent;
                  }) as ApiClient["events"],
                }),
              ) as never,
            }),
          ),
        (error) => {
          assert.equal(s309StageFromExitCode(s309StageExitCode(error)), expected, label);
          return true;
        },
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("s3-09 rejects unsupported profiles before side effects", async () => {
  const { dir, ctx } = await roots();
  const calls: string[] = [];
  try {
    await assert.rejects(() =>
      runLauncherOperation(
        Object.freeze({ op: "s3-09", profile: "insecure-container", state: "bad" }),
        ctx,
        opSeams(calls),
      ),
    );
    assert.deepEqual(calls, []);
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

test("run terminal tail preserves generic no-payload terminal handling", async () => {
  const { dir, ctx } = await roots();
  try {
    await sandbox(ctx, "generic-terminal");
    await ready(
      await resolveLauncherState({ root: ctx.launcherRoot, name: "generic-terminal", sourceRevision: revision }),
    );
    const hostilePayload = new Proxy(Object.freeze({}), {
      get() {
        throw new Error("payload touched");
      },
    });
    const seams = Object.freeze({
      ...opSeams([]),
      createApiClient: Object.freeze(() =>
        Object.freeze({
          request: Object.freeze(async () =>
            Object.freeze({ correlation_id: "corr-generic", accepted: true }),
          ) as ApiClient["request"],
          events: Object.freeze(async function* () {
            yield Object.freeze({
              id: 1,
              data: Object.freeze({ kind: "warning", correlation_id: "corr-generic", payload: hostilePayload }),
            }) as ApiEvent;
            yield Object.freeze({
              id: 2,
              data: Object.freeze({ kind: "run_aborted", correlation_id: "corr-generic" }),
            }) as ApiEvent;
          }) as ApiClient["events"],
        }),
      ) as never,
    });
    assert.deepEqual(
      await runLauncherOperation(
        Object.freeze({ op: "run", profile: "linux-kvm", state: "generic-terminal", promptFile: "p.txt" }),
        ctx,
        seams,
      ),
      { op: "run", terminal: "run_aborted", lastEventId: 2, eventCount: 2 },
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("run ignores inaccessible abort-correlated terminal events", async () => {
  const { dir, ctx } = await roots();
  try {
    await sandbox(ctx, "abortcorr");
    await ready(await resolveLauncherState({ root: ctx.launcherRoot, name: "abortcorr", sourceRevision: revision }));
    const seams = Object.freeze({
      ...opSeams([]),
      createApiClient: Object.freeze(() =>
        Object.freeze({
          request: Object.freeze(async () =>
            Object.freeze({ correlation_id: "run-corr", accepted: true }),
          ) as ApiClient["request"],
          events: Object.freeze(async function* () {
            yield Object.freeze({
              id: 1,
              data: Object.freeze({ kind: "run_aborted", correlation_id: "abort-corr" }),
            }) as ApiEvent;
            yield Object.freeze({
              id: 2,
              data: Object.freeze({ kind: "warning", correlation_id: "run-corr" }),
            }) as ApiEvent;
          }) as ApiClient["events"],
        }),
      ) as never,
    });
    await assert.rejects(() =>
      runLauncherOperation(
        Object.freeze({ op: "run", profile: "linux-kvm", state: "abortcorr", promptFile: "p.txt" }),
        ctx,
        seams,
      ),
    );
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

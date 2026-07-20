import { lstat, realpath } from "node:fs/promises";
import type { ApiClient, ApiEvent, ApiSeams } from "./api-client.ts";
import { createApiClient } from "./api-client.ts";
import type { CliRequest } from "./cli.ts";
import { readPromptFile, writeSensitiveExport } from "./cli.ts";
import { deepFreeze, type LauncherAuthority, type LauncherPhase, type LauncherProfile } from "./contract.ts";
import { readApiToken, readReadyWorkerDescriptor } from "./control.ts";
import { createSandbox, destroySandbox, type LauncherCoreOptions, resetSandbox } from "./core.ts";
import {
  LAUNCHER_DETERMINISTIC_ABORT_PROMPT,
  LAUNCHER_DETERMINISTIC_S309_PROMPT,
  LAUNCHER_DETERMINISTIC_S309_SETUP_PROMPT,
} from "./deterministic-stream.ts";
import { resolveLauncherState, withStateLock } from "./state.ts";
import { launcherInventory, startWorkerForState, stopWorkerForState } from "./supervisor.ts";

export type LauncherOperationContext = Readonly<{
  launcherRoot: string;
  repoRoot: string;
  exportRoot: string;
  sourceRevision: string;
  signal?: AbortSignal;
}>;

export type LauncherOperationSeams = Readonly<{
  createSandbox: typeof createSandbox;
  resetSandbox: typeof resetSandbox;
  destroySandbox: typeof destroySandbox;
  startWorkerForState: typeof startWorkerForState;
  stopWorkerForState: typeof stopWorkerForState;
  launcherInventory: typeof launcherInventory;
  createApiClient: typeof createApiClient;
  readPromptFile: typeof readPromptFile;
  writeSensitiveExport: typeof writeSensitiveExport;
  apiSeams?: ApiSeams;
}>;

export type LauncherOperationResult = Readonly<Record<string, unknown>>;

const defaultSeams: LauncherOperationSeams = Object.freeze({
  createSandbox,
  resetSandbox,
  destroySandbox,
  startWorkerForState,
  stopWorkerForState,
  launcherInventory,
  createApiClient,
  readPromptFile,
  writeSensitiveExport,
});
const sourceRe = /^[a-f0-9]{40}$/u;
const terminalKinds = new Set(["run_settled", "run_aborted"]);
const eventKinds = new Set([
  "pi_event",
  "tool_start",
  "tool_update",
  "tool_end",
  "usage",
  "git_mapping",
  "checkpoint",
  "approval_required",
  "warning",
  "error",
  "run_settled",
  "run_aborted",
  "shutdown_ready",
]);
const opSet = new Set([
  "create",
  "reset",
  "status",
  "start",
  "run",
  "abort",
  "history",
  "export",
  "shutdown",
  "destroy",
  "smoke",
  "s3-09",
]);
const profileSet = new Set(["insecure-container", "linux-kvm", "macos-vm"]);
const phaseSet = new Set(["creating", "sandbox-ready", "worker-ready", "cleanup-required", "destroying"]);
const authoritySet = new Set(["functional-only", "authoritative-local"]);
const stateRe = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const cursorRe = /^[A-Za-z0-9_-]{1,768}\.[A-Za-z0-9_-]{32,256}$/u;
const relRe = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+){0,15}$/u;
const abortGetter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get;

export async function runLauncherOperation(
  request: CliRequest,
  context: LauncherOperationContext,
  seams?: Partial<LauncherOperationSeams>,
): Promise<LauncherOperationResult> {
  let done: (() => void) | undefined;
  try {
    const req = captureRequest(request);
    const baseCtx = await captureContext(context);
    const scoped = deadline(baseCtx.signal, req.timeoutMs);
    done = scoped.done;
    const ctx = Object.freeze({ ...baseCtx, signal: scoped.signal, timeoutMs: scoped.timeoutMs });
    const s = captureSeams(seams);
    const options = Object.freeze({
      root: ctx.launcherRoot,
      name: req.state,
      sourceRevision: ctx.sourceRevision,
      profile: req.profile,
    }) as LauncherCoreOptions;
    const signal = ctx.signal;
    if (req.op === "create") return base("create", meta(result(await s.createSandbox(options, signal)).manifest));
    if (req.op === "reset") return base("reset", meta(result(await s.resetSandbox(options, signal)).manifest));
    if (req.op === "destroy")
      return deepFreeze({ op: "destroy", removed: bool(result(await s.destroySandbox(options, signal)).removed) });
    if (req.op === "status") return await status(options, s);
    if (req.op === "start") return await locked(options, (state) => s.startWorkerForState(state, signal));
    if (req.op === "shutdown") return await shutdown(options, signal, ctx.timeoutMs, s);
    if (req.op === "run") return await apiRun(req, options, ctx, s);
    if (req.op === "abort") return await apiRequest("abort", req, options, ctx, s);
    if (req.op === "history") return await apiRequest("history", req, options, ctx, s);
    if (req.op === "export") return await apiExport(req, options, ctx, s);
    if (req.op === "smoke") return await smoke(req, ctx, options, s);
    if (req.op === "s3-09") return await s309(req, ctx, options, s);
    throw new Error("launcher operation failed");
  } catch {
    throw new Error("launcher operation failed");
  } finally {
    done?.();
  }
}

async function status(options: LauncherCoreOptions, s: LauncherOperationSeams) {
  const state = await resolveLauncherState(stateInput(options));
  return await withStateLock(state, async () =>
    deepFreeze({ op: "status", inventory: stripInventory(await s.launcherInventory(state)) }),
  );
}

async function locked(
  options: LauncherCoreOptions,
  op: (
    state: Awaited<ReturnType<typeof resolveLauncherState>>,
  ) => Promise<{ phase: LauncherPhase; profile: LauncherProfile; authority: LauncherAuthority; apiPort?: number }>,
) {
  const state = await resolveLauncherState(stateInput(options));
  return await withStateLock(state, async () => base("start", opMeta(await op(state))));
}

async function apiRun(
  request: CliRequest,
  options: LauncherCoreOptions,
  ctx: LauncherOperationContext,
  s: LauncherOperationSeams,
) {
  if (!request.promptFile) throw new Error("launcher operation failed");
  const prompt = await s.readPromptFile(ctx.repoRoot, request.promptFile);
  const terminal = await withReadyClient(
    options,
    request,
    ctx as LauncherOperationContext & { timeoutMs: number },
    s,
    async (client, signal) => {
      const correlation = runCorrelation(await client.request("run", Object.freeze({ content: prompt }), signal));
      return await tailTerminal(client, correlation, signal);
    },
  );
  return deepFreeze({ op: "run", ...terminal });
}

async function apiRequest(
  kind: "abort" | "history",
  request: CliRequest,
  options: LauncherCoreOptions,
  ctx: LauncherOperationContext,
  s: LauncherOperationSeams,
) {
  return await withReadyClient(options, request, ctx, s, async (client, signal) => {
    if (kind === "abort") {
      const r = exactPlain(await client.request("abort", Object.freeze({}), signal));
      return deepFreeze({ op: "abort", aborted: bool(r.aborted), runState: runState(r.run_state) });
    }
    const r = exactPlain(
      await client.request(
        "entries",
        deepFreeze({ ...(request.after ? { after: request.after } : {}), limit: request.limit ?? 25 }),
        signal,
      ),
    );
    if (!Array.isArray(r.entries) || r.entries.length > 100) throw new Error("launcher operation failed");
    if (r.next !== undefined && (typeof r.next !== "string" || !cursorRe.test(r.next)))
      throw new Error("launcher operation failed");
    return deepFreeze({ op: "history", count: r.entries.length, ...(r.next ? { next: r.next } : {}) });
  });
}

async function apiExport(
  request: CliRequest,
  options: LauncherCoreOptions,
  ctx: LauncherOperationContext,
  s: LauncherOperationSeams,
) {
  if (!request.out) throw new Error("launcher operation failed");
  return await withReadyClient(options, request, ctx, s, async (client, signal) => {
    const r = exactPlain(await client.request("export", Object.freeze({}), signal));
    if (r.sensitive !== true) throw new Error("launcher operation failed");
    await s.writeSensitiveExport(ctx.exportRoot, request.out as string, r);
    return deepFreeze({ op: "export", written: true, sensitive: true });
  });
}

async function shutdown(
  options: LauncherCoreOptions,
  signal: AbortSignal | undefined,
  timeoutMs: number,
  s: LauncherOperationSeams,
) {
  const state = await resolveLauncherState(stateInput(options));
  return await withStateLock(state, async () => {
    let gracefulFailed = false;
    let holder: Awaited<ReturnType<typeof readApiToken>> | undefined;
    try {
      const ready = await readReadyWorkerDescriptor(state);
      holder = await readApiToken(state);
      await holder.withToken(async (token) => {
        await s
          .createApiClient(clientOptions(ready.apiPort, token, timeoutMs, s))
          .request("shutdown", Object.freeze({}), signal);
      });
    } catch {
      gracefulFailed = true;
    }
    if (holder) {
      try {
        holder.dispose();
      } catch {
        gracefulFailed = true;
      }
    }
    const stopped = base("shutdown", opMeta(await s.stopWorkerForState(state, undefined)));
    if (gracefulFailed) throw new Error("launcher operation failed");
    return stopped;
  });
}

async function withReadyClient<T>(
  options: LauncherCoreOptions,
  request: CliRequest,
  ctx: LauncherOperationContext,
  s: LauncherOperationSeams,
  op: (client: ApiClient, signal?: AbortSignal) => Promise<T>,
): Promise<T> {
  const state = await resolveLauncherState(stateInput(options));
  return await withStateLock(state, async () => {
    const ready = await readReadyWorkerDescriptor(state);
    if (ready.profile !== request.profile || ready.sourceRevision !== ctx.sourceRevision)
      throw new Error("launcher operation failed");
    const holder = await readApiToken(state);
    try {
      return await holder.withToken(
        async (token) =>
          await op(
            s.createApiClient(
              clientOptions(
                ready.apiPort,
                token,
                (ctx as LauncherOperationContext & { timeoutMs: number }).timeoutMs,
                s,
              ),
            ),
            ctx.signal,
          ),
      );
    } finally {
      holder.dispose();
    }
  });
}

async function tailTerminal(client: ApiClient, correlation: string, signal?: AbortSignal) {
  const terminal = await tailTerminalEvent(client, correlation, signal);
  return deepFreeze({ terminal: terminal.kind, lastEventId: terminal.lastEventId, eventCount: terminal.eventCount });
}

async function tailTerminalProof(client: ApiClient, correlation: string, signal?: AbortSignal, live?: LiveEvents) {
  const terminal = live
    ? await tailTerminalEventFromLive(client, live, correlation, signal)
    : await tailTerminalEvent(client, correlation, signal);
  if (terminal.kind !== "run_settled" || terminal.gitMapping !== true || terminal.checkpoint !== true)
    throw new Error("launcher operation failed");
  const payload = exactPlain(terminal.payload);
  const proof = exactPlain(payload.s3_09_proof);
  if (
    proof.version !== "cogs.launcher.s3-09-proof/v1alpha1" ||
    proof.scenario !== "s3-09" ||
    proof.profile !== "linux-kvm" ||
    proof.credential_route_200 !== true ||
    proof.denied_route_absent !== true ||
    proof.total_exact_expected !== true ||
    proof.fixture_ready !== true ||
    proof.fixture_generation_zero !== true
  )
    throw new Error("launcher operation failed");
  return deepFreeze({
    terminal: terminal.kind,
    lastEventId: terminal.lastEventId,
    liveEventCount: terminal.eventCount,
    egressProof: true,
  });
}

type LiveEvents = {
  readonly iterator: AsyncGenerator<ApiEvent>;
  readonly first: Promise<IteratorResult<ApiEvent>>;
  closed: boolean;
};

function startLiveEvents(client: ApiClient, signal?: AbortSignal): LiveEvents {
  const iterator = client.events(0, 100, signal);
  return { iterator, first: iterator.next(), closed: false };
}

async function tailTerminalEventFromLive(
  client: ApiClient,
  live: LiveEvents,
  correlation: string,
  signal?: AbortSignal,
) {
  let last = 0,
    count = 0,
    gitMapping = false,
    checkpoint = false;
  const visit = (event: ApiEvent) => {
    last = eventId(event);
    count += 1;
    if (count > 1000) throw new Error("launcher operation failed");
    const data = eventData(event),
      kind = enumValue(data.kind, eventKinds);
    if (data.correlation_id === correlation && kind === "git_mapping") gitMapping = true;
    if (data.correlation_id === correlation && kind === "checkpoint") checkpoint = true;
    if (terminalKinds.has(kind) && data.correlation_id === correlation)
      return deepFreeze({
        kind,
        lastEventId: last,
        eventCount: count,
        payload: exactPlain(data.payload),
        gitMapping,
        checkpoint,
      });
    return undefined;
  };
  const first = await live.first;
  if (!first.done) {
    const terminal = visit(first.value);
    if (terminal) return terminal;
  }
  for await (const event of live.iterator) {
    const terminal = visit(event);
    if (terminal) return terminal;
  }
  return tailTerminalEvent(client, correlation, signal, last, count, gitMapping, checkpoint);
}

async function tailTerminalEvent(
  client: ApiClient,
  correlation: string,
  signal?: AbortSignal,
  startLast = 0,
  startCount = 0,
  startGitMapping = false,
  startCheckpoint = false,
) {
  let last = startLast,
    count = startCount,
    gitMapping = startGitMapping,
    checkpoint = startCheckpoint;
  for (;;) {
    let saw = false;
    for await (const event of client.events(last, 100, signal)) {
      saw = true;
      last = eventId(event);
      count += 1;
      if (count > 1000) throw new Error("launcher operation failed");
      const data = eventData(event),
        kind = enumValue(data.kind, eventKinds);
      if (data.correlation_id === correlation && kind === "git_mapping") gitMapping = true;
      if (data.correlation_id === correlation && kind === "checkpoint") checkpoint = true;
      if (terminalKinds.has(kind) && data.correlation_id === correlation)
        return deepFreeze({
          kind,
          lastEventId: last,
          eventCount: count,
          payload: exactPlain(data.payload),
          gitMapping,
          checkpoint,
        });
    }
    if (!saw) throw new Error("launcher operation failed");
  }
}

async function assertReplayGap(client: ApiClient, signal?: AbortSignal): Promise<void> {
  try {
    for await (const _event of client.events(0, 1, signal)) return void failOp();
  } catch (error) {
    if (error instanceof Error && error.message === "launcher api replay gap") return;
    throw new Error("launcher operation failed");
  }
  failOp();
}

async function pagedHistory(client: ApiClient, signal?: AbortSignal) {
  let after: string | undefined;
  let pages = 0;
  let entries = 0;
  for (;;) {
    const page = exactPlain(
      await client.request("entries", deepFreeze({ ...(after ? { after } : {}), limit: 2 }), signal),
    );
    const list = Array.isArray(page.entries) ? page.entries : failOp();
    entries += list.length;
    pages += 1;
    if (pages > 100 || entries > 200) throw new Error("launcher operation failed");
    if (page.next === undefined) break;
    after = typeof page.next === "string" && cursorRe.test(page.next) ? page.next : failOp();
  }
  if (pages < 2 || entries < 4) throw new Error("launcher operation failed");
  return deepFreeze({ pages, entries });
}

function exportProof(value: unknown) {
  const r = exactPlain(value);
  const bundle = exactPlain(r.bundle);
  if (r.sensitive !== true || r.version !== "cogs.export-response/v1alpha1")
    throw new Error("launcher operation failed");
  if (
    bundle.version !== "cogs.export-descriptor/v1alpha1" ||
    bundle.mode !== "raw" ||
    bundle.attachments_included !== false ||
    bundle.sensitive !== true ||
    bundle.sanitized !== false ||
    bundle.anonymized !== false
  )
    throw new Error("launcher operation failed");
  return deepFreeze({ descriptorValidated: true, mode: "raw", sensitive: true });
}

function failOp(): never {
  throw new Error("launcher operation failed");
}

async function s309(
  request: CliRequest,
  ctx: LauncherOperationContext & { timeoutMs: number },
  options: LauncherCoreOptions,
  s: LauncherOperationSeams,
) {
  if (request.profile !== "linux-kvm") throw new Error("launcher operation failed");
  let started = false;
  try {
    base("create", meta(result(await s.createSandbox(options, ctx.signal)).manifest));
    await locked(options, (state) => s.startWorkerForState(state, ctx.signal));
    started = true;
    const proof = await withReadyClient(options, request, ctx, s, async (client, signal) => {
      const setupCorrelation = runCorrelation(
        await client.request("run", Object.freeze({ content: LAUNCHER_DETERMINISTIC_S309_SETUP_PROMPT }), signal),
      );
      const setup = await tailTerminal(client, setupCorrelation, signal);
      if (setup.terminal !== "run_settled") throw new Error("launcher operation failed");
      const live = startLiveEvents(client, signal);
      let correlation = "";
      try {
        correlation = runCorrelation(
          await client.request("run", Object.freeze({ content: LAUNCHER_DETERMINISTIC_S309_PROMPT }), signal),
        );
        const terminal = await tailTerminalProof(client, correlation, signal, live);
        live.closed = true;
        await live.iterator.return?.(undefined);
        await assertReplayGap(client, signal);
        const history = await pagedHistory(client, signal);
        const rawExport = exportProof(await client.request("export", Object.freeze({}), signal));
        return deepFreeze({ ...terminal, history, rawExport });
      } finally {
        if (!live.closed) await live.iterator.return?.(undefined).catch(() => undefined);
      }
    });
    await shutdown(options, ctx.signal, ctx.timeoutMs, s);
    started = false;
    const inv = stripInventory((await status(options, s)).inventory);
    if (inv.descriptor !== "none" || inv.workerLive !== false || inv.recovery !== "absent")
      throw new Error("launcher operation failed");
    if (bool(result(await s.destroySandbox(options, ctx.signal)).removed) !== true)
      throw new Error("launcher operation failed");
    return deepFreeze({ op: "s3-09", complete: true, ...proof, inventory: inv });
  } catch (error) {
    if (started) await stopOnly(options, s).catch(() => undefined);
    await s.destroySandbox(options, undefined).catch(() => undefined);
    throw error;
  }
}

async function smoke(
  request: CliRequest,
  ctx: LauncherOperationContext & { timeoutMs: number },
  options: LauncherCoreOptions,
  s: LauncherOperationSeams,
) {
  let started = false;
  try {
    base("create", meta(result(await s.createSandbox(options, ctx.signal)).manifest));
    await locked(options, (state) => s.startWorkerForState(state, ctx.signal));
    started = true;
    const first = await apiRun(
      Object.freeze({ ...request, op: "run", promptFile: "dev/launcher/smoke-prompt.txt" }),
      options,
      ctx,
      s,
    );
    if (first.terminal !== "run_settled") throw new Error("launcher operation failed");
    await apiRequest("history", Object.freeze({ ...request, op: "history", limit: 25 }), options, ctx, s);
    await apiExport(Object.freeze({ ...request, op: "export", out: "launcher-smoke.json" }), options, ctx, s);
    const aborted = await withReadyClient(options, request, ctx, s, async (client, signal) => {
      const correlation = runCorrelation(
        await client.request("run", Object.freeze({ content: LAUNCHER_DETERMINISTIC_ABORT_PROMPT }), signal),
      );
      const r = exactPlain(await client.request("abort", Object.freeze({}), signal));
      if (bool(r.aborted) !== true) throw new Error("launcher operation failed");
      const terminal = await tailTerminal(client, correlation, signal);
      if (terminal.terminal !== "run_aborted") throw new Error("launcher operation failed");
      return terminal;
    });
    await shutdown(options, ctx.signal, ctx.timeoutMs, s);
    started = false;
    const inv = stripInventory((await status(options, s)).inventory);
    if (
      inv.descriptor !== "none" ||
      inv.workerLive !== false ||
      inv.recovery !== "absent" ||
      inv.cleanupRequired !== false
    )
      throw new Error("launcher operation failed");
    if (bool(result(await s.destroySandbox(options, ctx.signal)).removed) !== true)
      throw new Error("launcher operation failed");
    return deepFreeze({ op: "smoke", complete: true, aborted, inventory: inv });
  } catch (error) {
    if (started) await stopOnly(options, s).catch(() => undefined);
    await s.destroySandbox(options, undefined).catch(() => undefined);
    throw error;
  }
}

function base(op: string, value: unknown) {
  return deepFreeze({ op, ...exactPlain(value) });
}
function meta(manifest: unknown) {
  return opMeta(manifest);
}
function opMeta(value: unknown) {
  const v = exactPlain(value);
  const phase = enumValue(v.phase, phaseSet),
    profile = enumValue(v.profile, profileSet),
    authority = enumValue(v.authority, authoritySet);
  return deepFreeze({ profile, authority, phase, workerReady: phase === "worker-ready" });
}
function stripInventory(value: unknown) {
  const v = exactPlain(value);
  return deepFreeze({
    profile: enumValue(v.profile, profileSet),
    authority: enumValue(v.authority, authoritySet),
    phase: enumValue(v.phase, phaseSet),
    descriptor: enumValue(v.descriptor, new Set(["none", "starting", "ready", "malformed"])),
    workerLive: v.workerLive === "unknown" ? "unknown" : bool(v.workerLive),
    recovery: enumValue(v.recovery, new Set(["present", "absent", "unknown"])),
    cleanupRequired: bool(v.cleanupRequired),
    driverState: enumValue(v.driverState, new Set(["present", "absent", "unknown"])),
  });
}
async function stopOnly(options: LauncherCoreOptions, s: LauncherOperationSeams): Promise<void> {
  const state = await resolveLauncherState(stateInput(options));
  await withStateLock(state, async () => {
    await s.stopWorkerForState(state, undefined);
  });
}
function stateInput(options: LauncherCoreOptions) {
  return Object.freeze({ root: options.root, name: options.name, sourceRevision: options.sourceRevision });
}
function runCorrelation(value: unknown): string {
  const v = exactPlain(value);
  return id(v.correlation_id);
}
function eventId(event: ApiEvent): number {
  const id = exactPlain(event).id;
  if (!Number.isSafeInteger(id) || (id as number) < 1) throw new Error("launcher operation failed");
  return id as number;
}
function eventData(event: ApiEvent): Record<string, unknown> {
  const data = exactPlain(exactPlain(event).data);
  id(data.correlation_id);
  return data;
}
function clientOptions(port: number, token: string, timeoutMs: number | undefined, s: LauncherOperationSeams) {
  return Object.freeze({
    port,
    token,
    ...(timeoutMs === undefined ? {} : { timeoutMs }),
    ...(s.apiSeams ? { seams: s.apiSeams } : {}),
  });
}
function captureRequest(input: CliRequest): CliRequest {
  const v = exactFrozen(
    input,
    ["after", "json", "limit", "op", "out", "profile", "promptFile", "state", "timeoutMs"],
    true,
  );
  const op = enumValue(v.op, opSet) as CliRequest["op"],
    profile = enumValue(v.profile, profileSet) as LauncherProfile;
  if (typeof v.state !== "string" || !stateRe.test(v.state)) throw new Error("launcher operation failed");
  if (
    v.timeoutMs !== undefined &&
    (!Number.isSafeInteger(v.timeoutMs) || (v.timeoutMs as number) < 1 || (v.timeoutMs as number) > 900_000)
  )
    throw new Error("launcher operation failed");
  if (v.limit !== undefined && (!Number.isSafeInteger(v.limit) || (v.limit as number) < 1 || (v.limit as number) > 100))
    throw new Error("launcher operation failed");
  if (v.after !== undefined && (typeof v.after !== "string" || !cursorRe.test(v.after)))
    throw new Error("launcher operation failed");
  if (v.promptFile !== undefined && (typeof v.promptFile !== "string" || !relRe.test(v.promptFile)))
    throw new Error("launcher operation failed");
  if (v.out !== undefined && (typeof v.out !== "string" || !relRe.test(v.out)))
    throw new Error("launcher operation failed");
  if ((op === "run") !== (v.promptFile !== undefined) || (op === "export") !== (v.out !== undefined))
    throw new Error("launcher operation failed");
  if (v.json !== undefined && (op !== "status" || v.json !== true)) throw new Error("launcher operation failed");
  if (op !== "history" && (v.after !== undefined || v.limit !== undefined))
    throw new Error("launcher operation failed");
  return Object.freeze({
    op,
    profile,
    state: v.state as string,
    ...(v.timeoutMs ? { timeoutMs: v.timeoutMs as number } : {}),
    ...(v.promptFile ? { promptFile: v.promptFile as string } : {}),
    ...(v.after ? { after: v.after as string } : {}),
    ...(v.limit ? { limit: v.limit as number } : {}),
    ...(v.out ? { out: v.out as string } : {}),
  });
}
function deadline(parent: AbortSignal | undefined, timeoutMs = 120_000) {
  const ac = new AbortController();
  const onAbort = () => ac.abort();
  parent?.addEventListener("abort", onAbort, { once: true });
  if (isAborted(parent)) ac.abort();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  return Object.freeze({
    signal: ac.signal,
    timeoutMs,
    done: () => {
      clearTimeout(timer);
      parent?.removeEventListener("abort", onAbort);
    },
  });
}
function signalOk(value: unknown): AbortSignal | undefined {
  if (value === undefined) return undefined;
  if (!(value instanceof AbortSignal) || !abortGetter) throw new Error("launcher operation failed");
  return value;
}
function isAborted(signal: AbortSignal | undefined): boolean {
  return signal ? abortGetter?.call(signal) === true : false;
}
function bool(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("launcher operation failed");
  return value;
}
function result(value: unknown): Record<string, unknown> {
  return exactPlain(value);
}
function id(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value))
    throw new Error("launcher operation failed");
  return value;
}
function enumValue(value: unknown, set: Set<string>): string {
  if (typeof value !== "string" || !set.has(value)) throw new Error("launcher operation failed");
  return value;
}
function runState(value: unknown): string {
  return enumValue(value, new Set(["idle", "running", "settled", "aborting", "shutdown"]));
}
async function captureContext(input: LauncherOperationContext): Promise<LauncherOperationContext> {
  const v = exactFrozen(input, ["exportRoot", "launcherRoot", "repoRoot", "signal", "sourceRevision"], true);
  if (typeof v.sourceRevision !== "string" || !sourceRe.test(v.sourceRevision))
    throw new Error("launcher operation failed");
  const signal = signalOk(v.signal);
  if (isAborted(signal)) throw new Error("launcher operation failed");
  const out = {
    launcherRoot: await ownedDir(v.launcherRoot, 0o700),
    repoRoot: await ownedDir(v.repoRoot, 0o777),
    exportRoot: await ownedDir(v.exportRoot, 0o700),
    sourceRevision: v.sourceRevision,
    ...(signal ? { signal } : {}),
  };
  if (out.launcherRoot !== v.launcherRoot || out.repoRoot !== v.repoRoot || out.exportRoot !== v.exportRoot)
    throw new Error("launcher operation failed");
  return Object.freeze(out);
}
function captureSeams(input?: Partial<LauncherOperationSeams>): LauncherOperationSeams {
  if (input === undefined) return defaultSeams;
  const v = exactFrozen(input, [...Object.keys(defaultSeams), "apiSeams"], true);
  return Object.freeze({ ...defaultSeams, ...v });
}
function exactFrozen(input: unknown, allowed: readonly string[], partial: boolean): Record<string, unknown> {
  if (
    !input ||
    typeof input !== "object" ||
    Object.getPrototypeOf(input) !== Object.prototype ||
    !Object.isFrozen(input)
  )
    throw new Error("launcher operation failed");
  if (Object.getOwnPropertySymbols(input).length !== 0) throw new Error("launcher operation failed");
  const d = Object.getOwnPropertyDescriptors(input);
  const keys = Object.keys(d).sort();
  if (keys.some((k) => !allowed.includes(k)) || (!partial && keys.join(",") !== [...allowed].sort().join(",")))
    throw new Error("launcher operation failed");
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    const x = d[key];
    if (!x || !("value" in x) || x.enumerable !== true) throw new Error("launcher operation failed");
    out[key] = x.value;
  }
  return out;
}
function exactPlain(input: unknown): Record<string, unknown> {
  if (
    !input ||
    typeof input !== "object" ||
    Object.getPrototypeOf(input) !== Object.prototype ||
    Object.getOwnPropertySymbols(input).length !== 0
  )
    throw new Error("launcher operation failed");
  const out: Record<string, unknown> = {};
  for (const [key, d] of Object.entries(Object.getOwnPropertyDescriptors(input))) {
    if (!d || !("value" in d) || d.enumerable !== true) throw new Error("launcher operation failed");
    out[key] = d.value;
  }
  return out;
}
async function ownedDir(path: unknown, mode: number): Promise<string> {
  if (typeof path !== "string" || !path.startsWith("/")) throw new Error("launcher operation failed");
  const real = await realpath(path);
  const stat = await lstat(real);
  if (!stat.isDirectory() || (mode !== 0o777 && (stat.mode & 0o777) !== mode) || (stat.mode & 0o022) !== 0)
    throw new Error("launcher operation failed");
  if (typeof process.geteuid === "function" && stat.uid !== process.geteuid())
    throw new Error("launcher operation failed");
  return real;
}

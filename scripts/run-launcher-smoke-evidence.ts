import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, readFile, realpath, rename, statfs, unlink, writeFile } from "node:fs/promises";
import { arch, platform, release } from "node:os";
import { dirname, join, resolve } from "node:path";
import { type CommandDescriptor, commandDescriptor, runCommand } from "../dev/launcher/runner.ts";
import { resolveLauncherState } from "../dev/launcher/state.ts";

type Profile = "insecure-container" | "linux-kvm";
type Outcome = "pass" | "fail";
type Scenario = "smoke" | "s3-09";
type SmokeStage =
  | "runtime-root-preflight"
  | "state-resolution"
  | "launcher-command"
  | "metadata-validation"
  | "sensitive-export-cleanup"
  | "state-absence"
  | "runtime-root-postflight"
  | "report-write";

const stateRe = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const revisionRe = /^[a-f0-9]{40}$/u;
const root = resolve(import.meta.dirname, "..");
const generatedRoot = join(root, "docs", "security-evidence", "generated");
const runtimeRoots = ["/run/cogs/egress", "/run/cogs/ssh"] as const;
const tmpfsMagic = 0x01021994;
const noFollow = constants.O_NOFOLLOW ?? 0;

export function launcherCommandDescriptor(
  profile: Profile,
  state: string,
  timeoutMs: number,
  scenario: Scenario = "smoke",
): CommandDescriptor {
  const outerTimeoutMs = timeoutMs + 120000;
  if (!Number.isSafeInteger(outerTimeoutMs) || outerTimeoutMs > 720000)
    throw new Error("invalid launcher smoke arguments");
  return commandDescriptor({
    executable: process.execPath,
    args: Object.freeze([
      join(root, "node_modules", "tsx", "dist", "cli.mjs"),
      join(root, "dev", "launcher", "main.ts"),
      "--profile",
      profile,
      "--state",
      state,
      scenario,
      "--timeout-ms",
      String(timeoutMs),
    ]),
    cwd: root,
    env: Object.freeze({ HOME: root, NO_COLOR: "1" }),
    timeoutMs: outerTimeoutMs,
    maxOutputBytes: 65536,
    killGraceMs: 120000,
  });
}

export function reportFor(input: {
  profile: Profile;
  scenario?: Scenario;
  sourceRevision: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  outcome: Outcome;
  diagnostics: string;
}) {
  const scenario = input.scenario ?? "smoke";
  const authority = input.profile === "linux-kvm" ? "authoritative-local" : "functional-only";
  const dependencyModes = {
    authorization: "real",
    audit: "real",
    revocation: "real",
    identity: "real",
    network_enforcement: input.profile === "linux-kvm" ? "real" : "not-applicable",
  } as const;
  return {
    version: "cogs.security-report/v1alpha1",
    report_id: `launcher-${input.profile}-${input.sourceRevision.slice(0, 16)}`,
    source_revision: input.sourceRevision,
    profile: input.profile,
    authority,
    started_at: input.startedAt,
    completed_at: input.completedAt,
    duration_ms: input.durationMs,
    environment: {
      os: `${platform()} ${release()}`,
      architecture: arch(),
      runner: process.env.GITHUB_ACTIONS === "true" ? "github-actions" : "local",
      runner_image: process.env.ImageOS ?? "unknown",
      runtime_versions: { node: process.version },
      metadata:
        input.profile === "linux-kvm"
          ? {
              external_tmpfs_roots: true,
              profile: input.profile,
              kvm_present: true,
              kvm_enabled: true,
              guest_root: true,
              distinct_boot_ids: true,
            }
          : { external_tmpfs_roots: true, profile: input.profile },
    },
    components: [{ name: "development-launcher", version: "issue-70" }],
    dependencies: {
      authorization: { mode: "real", implementation: "static-policy-and-envoy-ext-authz" },
      audit: { mode: "real", implementation: "command-audit-disabled-hook-plus-wal-otlp-metadata" },
      revocation: { mode: "real", implementation: "openbao-revocation-watcher" },
      identity: { mode: "real", implementation: "openbao-model-identity-and-profile-ssh" },
      network_enforcement: {
        mode: input.profile === "linux-kvm" ? "real" : "not-applicable",
        implementation:
          input.profile === "linux-kvm" ? "linux-kvm-local-isolation" : "insecure-container-functional-only",
      },
    },
    tests: [
      {
        id: scenario === "s3-09" ? "launcher.s3-09.integrated" : "launcher.smoke",
        group: "development-launcher",
        result: input.outcome,
        release_eligible: false,
        duration_ms: input.durationMs,
        dependency_modes: dependencyModes,
        diagnostics_redacted: input.diagnostics,
      },
    ],
    known_limitations: [
      "development-only launcher; no daemon, cloud, deployment, release, compliance, or production-readiness claim",
      input.profile === "linux-kvm"
        ? "KVM booleans are prerequisites carried from the same workflow's validated qualification steps before launcher smoke; the launcher harness does not re-measure them"
        : "functional-only insecure-container profile; isolation evidence is not applicable",
      ...(scenario === "s3-09"
        ? ["external real-provider/API-key call is blocked/not-run; local deterministic pinned Pi stream used"]
        : []),
    ],
  };
}

export function validateSmokeJson(value: unknown, profile: Profile): void {
  const item = exactRecord(value, ["aborted", "complete", "inventory", "op"]);
  const aborted = exactRecord(item.aborted, ["eventCount", "lastEventId", "terminal"]);
  const inv = exactRecord(item.inventory, [
    "authority",
    "cleanupRequired",
    "descriptor",
    "driverState",
    "phase",
    "profile",
    "recovery",
    "workerLive",
  ]);
  if (
    item.op !== "smoke" ||
    item.complete !== true ||
    aborted.terminal !== "run_aborted" ||
    !positiveBoundedInteger(aborted.lastEventId, 1000) ||
    !positiveBoundedInteger(aborted.eventCount, 1000) ||
    aborted.lastEventId < aborted.eventCount
  ) {
    throw new Error("invalid launcher smoke metadata");
  }
  if (
    inv.profile !== profile ||
    inv.authority !== (profile === "linux-kvm" ? "authoritative-local" : "functional-only") ||
    inv.descriptor !== "none" ||
    inv.workerLive !== false ||
    inv.recovery !== "absent" ||
    inv.cleanupRequired !== false
  ) {
    throw new Error("invalid launcher smoke metadata");
  }
}

export function validateS309Json(value: unknown): void {
  const item = exactRecord(value, [
    "complete",
    "egressProof",
    "history",
    "inventory",
    "lastEventId",
    "liveEventCount",
    "op",
    "rawExport",
    "terminal",
  ]);
  const history = exactRecord(item.history, ["entries", "pages"]);
  const raw = exactRecord(item.rawExport, ["descriptorValidated", "mode", "rawExportOpened", "sensitive"]);
  const inv = exactRecord(item.inventory, [
    "authority",
    "cleanupRequired",
    "descriptor",
    "driverState",
    "phase",
    "profile",
    "recovery",
    "workerLive",
  ]);
  if (
    item.op !== "s3-09" ||
    item.complete !== true ||
    item.terminal !== "run_settled" ||
    item.egressProof !== true ||
    !positiveBoundedInteger(item.lastEventId, 1000) ||
    !positiveBoundedInteger(item.liveEventCount, 1000) ||
    !positiveBoundedInteger(history.pages, 100) ||
    !positiveBoundedInteger(history.entries, 200) ||
    raw.descriptorValidated !== true ||
    raw.mode !== "raw" ||
    raw.sensitive !== true ||
    raw.rawExportOpened !== true
  )
    throw new Error("invalid launcher smoke metadata");
  if (
    inv.profile !== "linux-kvm" ||
    inv.authority !== "authoritative-local" ||
    inv.descriptor !== "none" ||
    inv.workerLive !== false ||
    inv.recovery !== "absent" ||
    inv.cleanupRequired !== false
  )
    throw new Error("invalid launcher smoke metadata");
}

export function expectedReportPath(profile: Profile, scenario: Scenario = "smoke"): string {
  return join(generatedRoot, scenario === "s3-09" ? "launcher-s3-09-linux-kvm.json" : `launcher-${profile}.json`);
}

export function validateReportPath(profile: Profile, path: string, scenario: Scenario = "smoke"): string {
  const resolved = resolve(path);
  if (resolved !== expectedReportPath(profile, scenario)) throw new Error("invalid launcher smoke arguments");
  return resolved;
}

export function isTmpfsType(type: number | bigint): boolean {
  return BigInt(type) === BigInt(tmpfsMagic);
}

async function main() {
  const args = await parseArgs(process.argv.slice(2));
  const started = new Date();
  const startMs = Date.now();
  let outcome: Outcome = "fail";
  let stage: SmokeStage = "runtime-root-preflight";
  let diagnostics = "launcher smoke failed at runtime-root-preflight";
  let pendingError: unknown;
  try {
    await checkRuntimeRoots();
    stage = "state-resolution";
    const state = await resolveLauncherState({
      root: join(root, ".cogs-dev", "launcher"),
      name: args.state,
      sourceRevision: args.sourceRevision,
    });
    stage = "launcher-command";
    const stdout = await runLauncher(args.profile, args.state, args.timeoutMs, args.scenario);
    stage = "metadata-validation";
    const metadata = lastJson(stdout);
    if (args.scenario === "s3-09") validateS309Json(metadata);
    else validateSmokeJson(metadata, args.profile);
    stage = "sensitive-export-cleanup";
    await cleanupSensitiveExport(join(root, ".cogs-dev", "exports", "launcher-smoke.json"));
    stage = "state-absence";
    await proveAbsent(state.dir);
    await proveAbsent(state.lockDir);
    await proveAbsent(state.driverStateDir);
    stage = "runtime-root-postflight";
    await checkRuntimeRoots();
    outcome = "pass";
    diagnostics = "metadata-only launcher smoke passed; exact sensitive export and state cleanup verified";
  } catch (error) {
    diagnostics = `launcher smoke failed at ${stage}`;
    pendingError = error;
  } finally {
    try {
      await cleanupSensitiveExport(join(root, ".cogs-dev", "exports", "launcher-smoke.json"));
    } catch (error) {
      pendingError ??= error;
    }
    if (pendingError) diagnostics = `launcher smoke failed at ${stage}`;
    const completed = new Date();
    stage = "report-write";
    await writeReport(
      args.report,
      reportFor({
        profile: args.profile,
        scenario: args.scenario,
        sourceRevision: args.sourceRevision,
        startedAt: started.toISOString(),
        completedAt: completed.toISOString(),
        durationMs: Math.max(0, Date.now() - startMs),
        outcome,
        diagnostics,
      }),
    );
  }
  if (pendingError) {
    process.stderr.write(`${diagnostics}\n`);
    throw new Error("launcher smoke failed");
  }
}

async function parseArgs(argv: string[]) {
  const out = new Map<string, string>();
  const allowed = new Set(["--profile", "--report", "--scenario", "--state", "--timeout-ms"]);
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith("--") || !allowed.has(key) || !value || value.startsWith("--") || out.has(key))
      throw new Error("invalid launcher smoke arguments");
    out.set(key, value);
  }
  const profile = out.get("--profile");
  const state = out.get("--state");
  const report = out.get("--report");
  const timeoutRaw = out.get("--timeout-ms") ?? "600000";
  const scenario = out.get("--scenario") ?? "smoke";
  const sourceRevision = process.env.COGS_SOURCE_REVISION ?? process.env.GITHUB_SHA ?? "";
  if (profile !== "insecure-container" && profile !== "linux-kvm") throw new Error("invalid launcher smoke arguments");
  if (!state || !stateRe.test(state) || !report || !/^[1-9]\d{0,5}$/u.test(timeoutRaw))
    throw new Error("invalid launcher smoke arguments");
  if (!revisionRe.test(sourceRevision) || sourceRevision !== (await checkedOutHead()))
    throw new Error("invalid launcher smoke arguments");
  if (scenario !== "smoke" && scenario !== "s3-09") throw new Error("invalid launcher smoke arguments");
  if (scenario === "s3-09" && profile !== "linux-kvm") throw new Error("invalid launcher smoke arguments");
  const reportPath = validateReportPath(profile, report, scenario);
  const timeoutMs = Number(timeoutRaw);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000)
    throw new Error("invalid launcher smoke arguments");
  return {
    profile: profile as Profile,
    state,
    report: reportPath,
    timeoutMs,
    sourceRevision,
    scenario: scenario as Scenario,
  };
}

async function checkedOutHead(): Promise<string> {
  const gitDir = join(root, ".git");
  const head = (await readFile(join(gitDir, "HEAD"), "utf8")).trim();
  if (revisionRe.test(head)) return head;
  if (!head.startsWith("ref: refs/") || head.includes("..") || head.includes("\\"))
    throw new Error("invalid launcher smoke arguments");
  const ref = head.slice(5);
  if (!/^[A-Za-z0-9._/-]+$/u.test(ref)) throw new Error("invalid launcher smoke arguments");
  const value = (await readFile(join(gitDir, ref), "utf8")).trim();
  if (!revisionRe.test(value)) throw new Error("invalid launcher smoke arguments");
  return value;
}

async function runLauncher(profile: Profile, state: string, timeoutMs: number, scenario: Scenario): Promise<string> {
  const result = await runCommand(launcherCommandDescriptor(profile, state, timeoutMs, scenario));
  if (
    result.status !== "ok" ||
    result.exitCode !== 0 ||
    result.cleanupUncertain ||
    result.stdoutTruncated ||
    result.stderrTruncated
  ) {
    throw new Error("launcher smoke failed");
  }
  return result.stdout;
}

function lastJson(stdout: string): unknown {
  for (const line of stdout.trimEnd().split(/\n/u).reverse()) {
    const trimmed = line.trim();
    if (trimmed.startsWith("{") && trimmed.endsWith("}")) return JSON.parse(trimmed);
  }
  throw new Error("invalid launcher smoke metadata");
}

async function checkRuntimeRoots() {
  for (const path of runtimeRoots) {
    const stat = await lstat(path);
    const fs = await statfs(path, { bigint: true });
    if (!isTmpfsType(fs.type)) throw new Error("launcher smoke failed");
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700)
      throw new Error("launcher smoke failed");
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid())
      throw new Error("launcher smoke failed");
    if ((await realpath(path)) !== path || (await readdir(path)).length !== 0) throw new Error("launcher smoke failed");
  }
}

export async function cleanupSensitiveExport(path: string, afterAcquire?: () => void | Promise<void>) {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let parentBefore: Awaited<ReturnType<typeof lstat>>;
  try {
    parentBefore = await lstat(dirname(path));
    handle = await open(path, constants.O_RDONLY | noFollow);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && !handle) return;
    throw new Error("launcher smoke failed");
  }

  let failed = false;
  let closeFailed = false;
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600) failed = true;
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) failed = true;
    if ((await realpath(path)) !== path) failed = true;
    const marker = { dev: stat.dev, ino: stat.ino, parentDev: parentBefore.dev, parentIno: parentBefore.ino };
    if (afterAcquire) await afterAcquire();
    const parentFinal = await lstat(dirname(path));
    const final = await lstat(path);
    if (parentFinal.dev !== marker.parentDev || parentFinal.ino !== marker.parentIno) failed = true;
    if (final.dev !== marker.dev || final.ino !== marker.ino || !final.isFile() || final.isSymbolicLink())
      failed = true;
    const opened = await handle.stat();
    if (opened.dev !== marker.dev || opened.ino !== marker.ino) failed = true;
    if (!failed) {
      await unlink(path);
      const parent = await open(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
      const parentAfter = await lstat(dirname(path));
      if (parentAfter.dev !== marker.parentDev || parentAfter.ino !== marker.parentIno) failed = true;
      await proveAbsent(path);
    }
  } catch {
    failed = true;
  } finally {
    try {
      await handle.close();
    } catch {
      closeFailed = true;
    }
  }
  if (closeFailed || failed) throw new Error("launcher smoke failed");
}

async function proveAbsent(path: string) {
  try {
    await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
  }
  throw new Error("launcher smoke failed");
}

async function writeReport(path: string, report: unknown) {
  const parent = dirname(path);
  if (parent !== generatedRoot) throw new Error("invalid launcher smoke arguments");
  await mkdir(parent, { mode: 0o700 }).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "EEXIST") throw error;
  });
  if ((await realpath(parent)) !== parent) throw new Error("invalid launcher smoke arguments");
  const temp = `${path}.${process.pid}.tmp`;
  const handle = await open(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow, 0o600);
  try {
    await writeFile(handle, `${JSON.stringify(report, null, 2)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await proveAbsent(path);
  await rename(temp, path);
  const parentHandle = await open(parent, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    await parentHandle.sync();
  } finally {
    await parentHandle.close();
  }
  await validateReportFile(path);
}

async function validateReportFile(path: string) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600)
    throw new Error("invalid launcher smoke arguments");
  if (typeof process.geteuid === "function" && stat.uid !== process.geteuid())
    throw new Error("invalid launcher smoke arguments");
  if ((await realpath(path)) !== path || stat.size < 1 || stat.size > 65536)
    throw new Error("invalid launcher smoke arguments");
}

function positiveBoundedInteger(value: unknown, max: number): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value > 0 && value <= max;
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Array.isArray(value)
  ) {
    throw new Error("invalid launcher smoke metadata");
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new Error("invalid launcher smoke metadata");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.keys(descriptors).sort().join(",") !== [...keys].sort().join(","))
    throw new Error("invalid launcher smoke metadata");
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid launcher smoke metadata");
    out[key] = descriptor.value;
  }
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(() => {
    process.stderr.write("launcher smoke failed\n");
    process.exitCode = 1;
  });
}

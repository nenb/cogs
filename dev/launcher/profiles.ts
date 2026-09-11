import { constants, type Stats } from "node:fs";
import { access, lstat, realpath } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type DriverResult, type LauncherProfile, normalizeDriverResult, normalizeProfile } from "./contract.ts";
import { type CommandDescriptor, type RunnerSeams, runCommand } from "./runner.ts";
import type { LauncherState } from "./state.ts";

export type ProfileAction = "create" | "verify" | "reset" | "destroy";
export type ProfileAdapter = Readonly<{
  profile: LauncherProfile;
  create(state: LauncherState, generation: string, signal?: AbortSignal): Promise<DriverResult>;
  verify(state: LauncherState, generation: string, signal?: AbortSignal): Promise<DriverResult>;
  reset(state: LauncherState, generation: string, signal?: AbortSignal): Promise<DriverResult>;
  destroy(state: LauncherState, generation: string, signal?: AbortSignal): Promise<DriverResult>;
}>;

const repoRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fixedPath = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin";

export function createProfileAdapter(profile: LauncherProfile, seams?: RunnerSeams): ProfileAdapter {
  profile = normalizeProfile(profile);
  const driver = driverPath(profile);
  const create = Object.freeze((state: LauncherState, generation: string, signal?: AbortSignal) =>
    invoke(profile, driver, state, "create", generation, signal, seams),
  );
  const verify = Object.freeze((state: LauncherState, generation: string, signal?: AbortSignal) =>
    invoke(profile, driver, state, "verify", generation, signal, seams),
  );
  const reset = Object.freeze((state: LauncherState, generation: string, signal?: AbortSignal) =>
    invoke(profile, driver, state, "reset", generation, signal, seams),
  );
  const destroy = Object.freeze((state: LauncherState, generation: string, signal?: AbortSignal) =>
    invoke(profile, driver, state, "destroy", generation, signal, seams),
  );
  return Object.freeze({ profile, create, verify, reset, destroy });
}

export function driverPath(profile: LauncherProfile): string {
  switch (profile) {
    case "insecure-container":
      return join(repoRoot, "dev/insecure-sandbox/driver.sh");
    case "linux-kvm":
      return join(repoRoot, "dev/linux-kvm/driver.sh");
    case "macos-vm":
      return join(repoRoot, "dev/macos-vm/driver.sh");
  }
}

async function invoke(
  profile: LauncherProfile,
  driver: string,
  state: LauncherState,
  action: ProfileAction,
  generation: string,
  signal: AbortSignal | undefined,
  seams: RunnerSeams | undefined,
): Promise<DriverResult> {
  await validateDriver(profile, driver);
  const runOptions: { signal?: AbortSignal; seams?: RunnerSeams } = {};
  if (signal) runOptions.signal = signal;
  if (seams) runOptions.seams = seams;
  const result = await runCommand(descriptor(profile, driver, state, action, generation), runOptions);
  if (result.status !== "ok" || result.cleanupUncertain || result.stdoutTruncated || result.stderrTruncated)
    throw new Error("launcher profile operation failed");
  const parsed = normalizeDriverResult(result.stdout, profile, action, generation);
  if (action === "destroy") await verifyProfileAbsent(state);
  return parsed;
}

export function descriptor(
  profile: LauncherProfile,
  driver: string,
  state: LauncherState,
  action: ProfileAction,
  generation: string,
): CommandDescriptor {
  if (typeof generation !== "string" || !/^[a-f0-9]{32}$/.test(generation) || profile === "macos-vm")
    throw new Error("launcher profile prerequisite failed");
  const env: Record<string, string> = {
    PATH: fixedPath,
    HOME: state.controlDir,
    LANG: "C",
    LC_ALL: "C",
    COGS_SOURCE_REVISION: state.sourceRevision,
  };
  if (state.root !== join(repoRoot, ".cogs-dev", "launcher")) throw new Error("launcher profile prerequisite failed");
  if (profile === "insecure-container") {
    env.COGS_INSECURE_STATE_DIR = state.driverStateDir;
    env.COGS_INSECURE_GENERATION = generation;
    env.COGS_INSECURE_ORIGINAL_REVISION = state.sourceRevision;
  }
  if (profile === "linux-kvm") {
    env.COGS_KVM_STATE_DIR = state.driverStateDir;
    env.COGS_KVM_CACHE_DIR = state.driverCacheDir;
    env.COGS_KVM_GENERATION = generation;
  }
  return {
    executable: driver,
    args: [action],
    cwd: repoRoot,
    env,
    timeoutMs: action === "destroy" ? 120_000 : action === "verify" ? 300_000 : 900_000,
    maxOutputBytes: 16 * 1024,
    killGraceMs: 120_000,
  };
}

async function validateDriver(profile: LauncherProfile, driver: string): Promise<void> {
  const expected = driverPath(profile);
  if (driver !== expected || !driver.startsWith(`${repoRoot}/`))
    throw new Error("launcher profile prerequisite failed");
  let stat: Stats;
  try {
    stat = await lstat(driver);
  } catch {
    throw new Error("launcher profile prerequisite failed");
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1)
    throw new Error("launcher profile prerequisite failed");
  if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
    throw new Error("launcher profile prerequisite failed");
  }
  if ((stat.mode & 0o111) === 0 || (stat.mode & 0o022) !== 0) throw new Error("launcher profile prerequisite failed");
  if ((await realpath(driver)) !== driver) throw new Error("launcher profile prerequisite failed");
  await access(driver, constants.X_OK);
}

async function verifyProfileAbsent(state: LauncherState): Promise<void> {
  await verifyDriverParent(state);
  try {
    await lstat(state.driverStateDir);
    throw new Error("launcher profile cleanup uncertain");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await verifyDriverParent(state);
}

async function verifyDriverParent(state: LauncherState): Promise<void> {
  const parent = dirname(state.driverStateDir);
  const stat = await lstat(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (await realpath(parent)) !== parent)
    throw new Error("launcher profile cleanup uncertain");
  if (parent === join(repoRoot, ".cogs-dev")) {
    if ((stat.mode & 0o777) !== 0o700 || (typeof process.geteuid === "function" && stat.uid !== process.geteuid()))
      throw new Error("launcher profile cleanup uncertain");
  }
}

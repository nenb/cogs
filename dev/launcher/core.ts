import { lstat, realpath } from "node:fs/promises";
import { dirname } from "node:path";
import { types } from "node:util";
import { deepFreeze, type LauncherManifest, type LauncherProfile, normalizeProfile } from "./contract.ts";
import { requireSessionControlsAbsent } from "./control.ts";
import { createProfileAdapter, type ProfileAdapter } from "./profiles.ts";
import {
  type Acquisition,
  assertAcquisition,
  assertAcquisitionUsable,
  assertDriverAcquisition,
  consumeDriverAcquisition,
  createState,
  issueAcquisition,
  type LauncherState,
  markAcquisitionUncertain,
  markRecovery,
  publishDriverAcquisition,
  readAcquisition,
  readManifest,
  removeOwnedState,
  resolveLauncherState,
  withStateLock,
  writePhase,
} from "./state.ts";

export type LauncherCoreOptions = Readonly<{
  root: string;
  name: string;
  sourceRevision: string;
  profile: LauncherProfile;
  adapter?: ProfileAdapter;
}>;

export type SandboxResult = Readonly<{ manifest: LauncherManifest; workerReady: false; generation: string }>;
const completedAcquisitions = new WeakMap<SandboxResult, Acquisition>();

export function acquiredSandbox(value: unknown, options: LauncherCoreOptions): Acquisition {
  const a = value && typeof value === "object" ? completedAcquisitions.get(value as SandboxResult) : undefined;
  if (
    !a ||
    a.dir !== `${options.root}/${options.name}` ||
    a.profile !== options.profile ||
    a.sourceRevision !== options.sourceRevision
  )
    throw new Error("invalid launcher acquisition receipt");
  return a;
}

export async function createSandbox(options: LauncherCoreOptions, signal?: AbortSignal): Promise<SandboxResult> {
  const captured = snapshotOptions(options);
  const state = await stateFrom(captured);
  const acquisition = issueAcquisition(state, captured.profile);
  const output = await withStateLock<SandboxResult>(state, async () => {
    const { profile } = captured;
    const adapter = captureAdapter(captured.adapter ?? createProfileAdapter(profile), profile);
    let manifest = await createState(state, profile, acquisition);
    let driverAcquired = false;
    try {
      await assertAcquisition(state, acquisition);
      await expectResult(adapter.create(state, acquisition.generation, signal), profile, "create", acquisition);
      driverAcquired = true;
      await publishDriverAcquisition(state, acquisition);
      await assertDriverAcquisition(state, acquisition);
      await expectResult(
        adapter.verify(state, acquisition.generation, signal),
        manifest.profile,
        "verify",
        acquisition,
      );
      await assertAcquisition(state, acquisition);
      manifest = await writePhase(state, manifest, "sandbox-ready");
      return deepFreeze({ manifest, workerReady: false, generation: acquisition.generation });
    } catch (error) {
      try {
        if (!driverAcquired) throw new Error("driver acquisition not acknowledged");
        await consumeDriverAcquisition(state, acquisition);
        await expectResult(adapter.destroy(state, acquisition.generation), manifest.profile, "destroy", acquisition);
        await ensureDriverAbsent(state);
        await removeOwnedState(state, acquisition);
      } catch {
        await recover(state, acquisition, manifest, "create-rollback-failed");
      }
      throw error;
    }
  }).catch(async (error) => {
    await markAcquisitionUncertain(state, acquisition).catch(() => undefined);
    throw error;
  });
  // A lock-release failure is a lost response, never an outer cleanup receipt.
  completedAcquisitions.set(output, acquisition);
  return output;
}

export async function resetSandbox(options: LauncherCoreOptions, signal?: AbortSignal): Promise<SandboxResult> {
  const captured = snapshotOptions(options);
  const state = await stateFrom(captured);
  return await withStateLock(state, async () => {
    const manifest = await requireReady(state, captured.profile, captured.sourceRevision);
    await requireSessionControlsAbsent(state);
    const adapter = captureAdapter(captured.adapter ?? createProfileAdapter(manifest.profile), manifest.profile);
    const acquisition = await readAcquisition(state);
    await assertDriverAcquisition(state, acquisition);
    try {
      await expectResult(adapter.reset(state, acquisition.generation, signal), manifest.profile, "reset", acquisition);
      await assertDriverAcquisition(state, acquisition);
      await expectResult(
        adapter.verify(state, acquisition.generation, signal),
        manifest.profile,
        "verify",
        acquisition,
      );
      await assertAcquisition(state, acquisition);
      return deepFreeze({ manifest, workerReady: false, generation: acquisition.generation });
    } catch (error) {
      try {
        await consumeDriverAcquisition(state, acquisition);
        await expectResult(adapter.destroy(state, acquisition.generation), manifest.profile, "destroy", acquisition);
        await ensureDriverAbsent(state);
      } catch {
        await recover(state, acquisition, manifest, "reset-cleanup-failed");
      }
      await recover(state, acquisition, manifest, "reset-failed");
      throw error;
    }
  });
}

export async function statusSandbox(options: LauncherCoreOptions, signal?: AbortSignal): Promise<SandboxResult> {
  const captured = snapshotOptions(options);
  const state = await stateFrom(captured);
  return await withStateLock(state, async () => {
    const manifest = await requireReady(state, captured.profile, captured.sourceRevision);
    await requireSessionControlsAbsent(state);
    const adapter = captureAdapter(captured.adapter ?? createProfileAdapter(manifest.profile), manifest.profile);
    const acquisition = await readAcquisition(state);
    await assertDriverAcquisition(state, acquisition);
    try {
      await expectResult(
        adapter.verify(state, acquisition.generation, signal),
        manifest.profile,
        "verify",
        acquisition,
      );
      await assertAcquisition(state, acquisition);
      return deepFreeze({ manifest, workerReady: false, generation: acquisition.generation });
    } catch (error) {
      await recover(state, acquisition, manifest, "status-verify-failed");
      throw error;
    }
  });
}

export async function destroySandbox(
  options: LauncherCoreOptions,
  signal?: AbortSignal,
  expectedAcquisition?: Acquisition,
): Promise<{ removed: boolean }> {
  const captured = snapshotOptions(options);
  const state = await stateFrom(captured);
  return await withStateLock(state, async () => {
    // Explicit operator destroy may load retained launcher custody. Automatic
    // rollback must supply the issuer's exact successful acquisition capability.
    const acquisition = expectedAcquisition ?? (await readAcquisition(state));
    await assertDriverAcquisition(state, acquisition);
    const manifest = await readManifest(state);
    if (
      manifest.profile !== captured.profile ||
      acquisition.profile !== captured.profile ||
      manifest.sourceRevision !== acquisition.sourceRevision
    )
      throw new Error("invalid launcher state");
    if (manifest.phase === "worker-ready") throw new Error("launcher worker cleanup required");
    await requireSessionControlsAbsent(state);
    const adapter = captureAdapter(captured.adapter ?? createProfileAdapter(manifest.profile), manifest.profile);
    const destroying = await writePhase(state, manifest, "destroying");
    try {
      await consumeDriverAcquisition(state, acquisition);
      const driverState = Object.freeze({ ...state, sourceRevision: acquisition.sourceRevision });
      await expectResult(
        adapter.destroy(driverState, acquisition.generation, signal),
        manifest.profile,
        "destroy",
        acquisition,
      );
      await ensureDriverAbsent(state);
      await removeOwnedState(state, acquisition);
      return deepFreeze({ removed: true });
    } catch (error) {
      await recover(state, acquisition, destroying, "destroy-uncertain");
      throw error;
    }
  });
}

async function recover(state: LauncherState, acquisition: Acquisition, manifest: LauncherManifest, reason: string) {
  await assertAcquisition(state, acquisition)
    .then(async () => {
      await markAcquisitionUncertain(state, acquisition).catch(() => undefined);
      await markRecovery(state, reason);
      await assertAcquisition(state, acquisition);
      await writePhase(state, manifest, "cleanup-required");
    })
    .catch(() => undefined);
}

async function expectResult(
  result: Promise<import("./contract.ts").DriverResult>,
  profile: LauncherProfile,
  operation: import("./contract.ts").DriverResult["operation"],
  acquisition: Acquisition,
): Promise<void> {
  const resolved = await result;
  if (!resolved || typeof resolved !== "object" || types.isProxy(resolved))
    throw new Error("invalid launcher profile result");
  const descriptors = Object.getOwnPropertyDescriptors(resolved);
  const keys = ["authority", "generation", "operation", "profile", "result"];
  if (
    Object.getPrototypeOf(resolved) !== Object.prototype ||
    !Object.isFrozen(resolved) ||
    Object.getOwnPropertySymbols(resolved).length !== 0 ||
    Object.keys(descriptors).sort().join(",") !== keys.join(",")
  )
    throw new Error("invalid launcher profile result");
  const values: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid launcher profile result");
    values[key] = descriptor.value;
  }
  const authority = profile === "linux-kvm" ? "authoritative-local" : "functional-only";
  const expectedResult = profile === "linux-kvm" ? (operation === "destroy" ? "destroyed" : "ready") : "pass";
  if (
    values.generation !== acquisition.generation ||
    values.profile !== profile ||
    values.operation !== operation ||
    values.authority !== authority ||
    values.result !== expectedResult
  )
    throw new Error("invalid launcher profile result");
}

function captureAdapter(adapter: ProfileAdapter, profile: LauncherProfile): ProfileAdapter {
  if (!Object.isFrozen(adapter) || Object.getPrototypeOf(adapter) !== Object.prototype) {
    throw new Error("invalid launcher profile adapter");
  }
  const descriptors = Object.getOwnPropertyDescriptors(adapter);
  const keys = ["create", "destroy", "profile", "reset", "verify"];
  if (
    Object.getOwnPropertySymbols(adapter).length !== 0 ||
    Object.keys(descriptors).sort().join(",") !== keys.join(",")
  ) {
    throw new Error("invalid launcher profile adapter");
  }
  const profileDescriptor = descriptors.profile;
  if (!profileDescriptor || !("value" in profileDescriptor) || profileDescriptor.value !== profile) {
    throw new Error("invalid launcher profile adapter");
  }
  const captured: Record<string, unknown> = { profile };
  for (const key of ["create", "destroy", "reset", "verify"] as const) {
    const descriptor = descriptors[key];
    if (
      !descriptor ||
      !("value" in descriptor) ||
      typeof descriptor.value !== "function" ||
      !Object.isFrozen(descriptor.value)
    )
      throw new Error("invalid launcher profile adapter");
    captured[key] = descriptor.value;
  }
  return Object.freeze(captured) as ProfileAdapter;
}

function snapshotOptions(options: LauncherCoreOptions): LauncherCoreOptions {
  if (!options || typeof options !== "object" || Object.getPrototypeOf(options) !== Object.prototype)
    throw new Error("invalid launcher options");
  if (Object.getOwnPropertySymbols(options).length !== 0) throw new Error("invalid launcher options");
  const descriptors = Object.getOwnPropertyDescriptors(options);
  const keys = Object.keys(descriptors).sort();
  const expected = descriptors.adapter
    ? ["adapter", "name", "profile", "root", "sourceRevision"]
    : ["name", "profile", "root", "sourceRevision"];
  if (keys.join(",") !== expected.join(",")) throw new Error("invalid launcher options");
  const values: Record<string, unknown> = {};
  for (const key of expected) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid launcher options");
    values[key] = descriptor.value;
  }
  const profile = normalizeProfile(values.profile);
  if (typeof values.root !== "string" || typeof values.name !== "string" || typeof values.sourceRevision !== "string")
    throw new Error("invalid launcher options");
  return Object.freeze({
    root: values.root,
    name: values.name,
    sourceRevision: values.sourceRevision,
    profile,
    ...(values.adapter ? { adapter: values.adapter as ProfileAdapter } : {}),
  });
}

async function ensureDriverParentCanonical(state: LauncherState): Promise<void> {
  const parent = dirname(state.driverStateDir);
  const stat = await lstat(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (await realpath(parent)) !== parent)
    throw new Error("invalid launcher state");
  if (parent.endsWith("/.cogs-dev")) {
    if ((stat.mode & 0o777) !== 0o700 || (typeof process.geteuid === "function" && stat.uid !== process.geteuid()))
      throw new Error("invalid launcher state");
  }
}

async function ensureDriverAbsent(state: LauncherState): Promise<void> {
  await ensureDriverParentCanonical(state);
  try {
    await lstat(state.driverStateDir);
    throw new Error("launcher profile cleanup uncertain");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await ensureDriverParentCanonical(state);
}

async function requireReady(
  state: LauncherState,
  profile: LauncherProfile,
  sourceRevision: string,
): Promise<LauncherManifest> {
  const manifest = await readManifest(state);
  const acquisition = await readAcquisition(state);
  if (
    acquisition.profile !== profile ||
    acquisition.sourceRevision !== sourceRevision ||
    manifest.profile !== profile ||
    manifest.phase !== "sandbox-ready" ||
    manifest.sourceRevision !== sourceRevision
  )
    throw new Error("launcher sandbox not ready");
  await assertAcquisitionUsable(state, acquisition);
  try {
    await lstat(state.recoveryPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return manifest;
    throw error;
  }
  throw new Error("launcher sandbox not ready; sticky cleanup uncertainty");
}

async function stateFrom(options: LauncherCoreOptions): Promise<LauncherState> {
  if (normalizeProfile(options.profile) === "macos-vm") throw new Error("launcher profile prerequisite failed");
  return await resolveLauncherState({ root: options.root, name: options.name, sourceRevision: options.sourceRevision });
}

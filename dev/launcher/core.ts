import { lstat, realpath } from "node:fs/promises";
import { dirname } from "node:path";
import { deepFreeze, type LauncherManifest, type LauncherProfile, normalizeProfile } from "./contract.ts";
import { requireSessionControlsAbsent } from "./control.ts";
import { createProfileAdapter, type ProfileAdapter } from "./profiles.ts";
import {
  createState,
  type LauncherState,
  markRecovery,
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

export type SandboxResult = Readonly<{ manifest: LauncherManifest; workerReady: false }>;

export async function createSandbox(options: LauncherCoreOptions, signal?: AbortSignal): Promise<SandboxResult> {
  const captured = snapshotOptions(options);
  const state = await stateFrom(captured);
  return await withStateLock(state, async () => {
    const { profile } = captured;
    const adapter = captureAdapter(captured.adapter ?? createProfileAdapter(profile), profile);
    let manifest = await createState(state, profile);
    try {
      await expectResult(adapter.create(state, signal), profile, "create");
      await expectResult(adapter.verify(state, signal), manifest.profile, "verify");
      manifest = await writePhase(state, manifest, "sandbox-ready");
      return deepFreeze({ manifest, workerReady: false });
    } catch (error) {
      try {
        await expectResult(adapter.destroy(state), manifest.profile, "destroy");
        await ensureDriverAbsent(state);
        await removeOwnedState(state);
      } catch {
        await markRecovery(state, "create-rollback-failed").catch(() => undefined);
        await writePhase(state, manifest, "cleanup-required").catch(() => undefined);
      }
      throw error;
    }
  });
}

export async function resetSandbox(options: LauncherCoreOptions, signal?: AbortSignal): Promise<SandboxResult> {
  const captured = snapshotOptions(options);
  const state = await stateFrom(captured);
  return await withStateLock(state, async () => {
    const manifest = await requireReady(state, captured.profile, captured.sourceRevision);
    await requireSessionControlsAbsent(state);
    const adapter = captureAdapter(captured.adapter ?? createProfileAdapter(manifest.profile), manifest.profile);
    try {
      await expectResult(adapter.reset(state, signal), manifest.profile, "reset");
      await expectResult(adapter.verify(state, signal), manifest.profile, "verify");
      return deepFreeze({ manifest, workerReady: false });
    } catch (error) {
      try {
        await expectResult(adapter.destroy(state), manifest.profile, "destroy");
        await ensureDriverAbsent(state);
      } catch {
        await markRecovery(state, "reset-cleanup-failed").catch(() => undefined);
      }
      await writePhase(state, manifest, "cleanup-required").catch(() => undefined);
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
    try {
      await expectResult(adapter.verify(state, signal), manifest.profile, "verify");
      return deepFreeze({ manifest, workerReady: false });
    } catch (error) {
      await writePhase(state, manifest, "cleanup-required").catch(() => undefined);
      await markRecovery(state, "status-verify-failed").catch(() => undefined);
      throw error;
    }
  });
}

export async function destroySandbox(
  options: LauncherCoreOptions,
  signal?: AbortSignal,
): Promise<{ removed: boolean }> {
  const captured = snapshotOptions(options);
  const state = await stateFrom(captured);
  return await withStateLock(state, async () => {
    let manifest: LauncherManifest;
    try {
      manifest = await readManifest(state);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        const { profile } = captured;
        await ensureDriverParentCanonical(state);
        const adapter = captureAdapter(captured.adapter ?? createProfileAdapter(profile), profile);
        await expectResult(adapter.destroy(state, signal), profile, "destroy");
        await ensureDriverAbsent(state);
        return deepFreeze({ removed: true });
      }
      throw error;
    }
    if (manifest.profile !== captured.profile) throw new Error("invalid launcher state");
    if (manifest.phase === "worker-ready") throw new Error("launcher worker cleanup required");
    await requireSessionControlsAbsent(state);
    const adapter = captureAdapter(captured.adapter ?? createProfileAdapter(manifest.profile), manifest.profile);
    const destroying = await writePhase(state, manifest, "destroying");
    try {
      await expectResult(adapter.destroy(state, signal), manifest.profile, "destroy");
      await ensureDriverAbsent(state);
      await removeOwnedState(state);
      return deepFreeze({ removed: true });
    } catch (error) {
      await markRecovery(state, "destroy-uncertain").catch(() => undefined);
      await writePhase(state, destroying, "cleanup-required").catch(() => undefined);
      throw error;
    }
  });
}

async function expectResult(
  result: Promise<import("./contract.ts").DriverResult>,
  profile: LauncherProfile,
  operation: import("./contract.ts").DriverResult["operation"],
): Promise<void> {
  const resolved = await result;
  if (!resolved || typeof resolved !== "object") throw new Error("invalid launcher profile result");
  const descriptors = Object.getOwnPropertyDescriptors(resolved);
  const keys = ["authority", "operation", "profile", "result"];
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
  if (manifest.profile !== profile || manifest.phase !== "sandbox-ready" || manifest.sourceRevision !== sourceRevision)
    throw new Error("launcher sandbox not ready");
  return manifest;
}

async function stateFrom(options: LauncherCoreOptions): Promise<LauncherState> {
  normalizeProfile(options.profile);
  return await resolveLauncherState({ root: options.root, name: options.name, sourceRevision: options.sourceRevision });
}

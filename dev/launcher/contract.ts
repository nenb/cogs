import { createHash } from "node:crypto";

export const launcherProfiles = ["insecure-container", "linux-kvm", "macos-vm"] as const;
export type LauncherProfile = (typeof launcherProfiles)[number];

export const launcherOperations = ["create", "reset", "status", "destroy"] as const;
export type LauncherOperation = (typeof launcherOperations)[number];

export type LauncherAuthority = "functional-only" | "authoritative-local";
export type LauncherPhase = "creating" | "sandbox-ready" | "worker-ready" | "cleanup-required" | "destroying";

export const launcherManifestVersion = "cogs.dev-launcher-manifest/v1alpha1" as const;
export const launcherRecoveryVersion = "cogs.dev-launcher-recovery/v1alpha1" as const;

export type OwnedResources = Readonly<{
  sandboxState: string;
  controlDir: string;
  lockName: string;
}>;

export type LauncherManifest = Readonly<{
  version: typeof launcherManifestVersion;
  sourceRevision: string;
  stateId: string;
  stateName: string;
  profile: LauncherProfile;
  phase: LauncherPhase;
  authority: LauncherAuthority;
  owned: OwnedResources;
  ports: readonly number[];
}>;

export type DriverResult = Readonly<{
  profile: LauncherProfile;
  operation: "create" | "verify" | "reset" | "destroy";
  result: "pass" | "destroyed" | "ready";
  authority: LauncherAuthority;
}>;

const sourceRevisionRe = /^[a-f0-9]{40}$/;
const stateIdRe = /^[a-f0-9]{16}$/;
const stateNameRe = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const resourceRe =
  /^(?:\.[a-f0-9]{16}\.lock|(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:\/[A-Za-z0-9][A-Za-z0-9._-]{0,63}){0,3})$/;
const profileSet = new Set<string>(launcherProfiles);
const operationSet = new Set<string>(launcherOperations);
const phaseSet = new Set<string>(["creating", "sandbox-ready", "worker-ready", "cleanup-required", "destroying"]);
const authoritySet = new Set<string>(["functional-only", "authoritative-local"]);

export function normalizeProfile(value: unknown): LauncherProfile {
  if (typeof value !== "string" || !profileSet.has(value)) throw new Error("invalid launcher profile");
  return value as LauncherProfile;
}

export function normalizeOperation(value: unknown): LauncherOperation {
  if (typeof value !== "string" || !operationSet.has(value)) throw new Error("invalid launcher operation");
  return value as LauncherOperation;
}

export function profileAuthority(profile: LauncherProfile): LauncherAuthority {
  return profile === "linux-kvm" ? "authoritative-local" : "functional-only";
}

export function stateIdFor(input: { root: string; name: string }): string {
  return createHash("sha256").update(`${input.root}\0${input.name}`).digest("hex").slice(0, 16);
}

export function createLauncherManifest(input: {
  sourceRevision: string;
  stateId: string;
  stateName: string;
  profile: LauncherProfile;
  phase: LauncherPhase;
  owned: OwnedResources;
  ports?: readonly number[];
}): LauncherManifest {
  return validateManifest({
    version: launcherManifestVersion,
    sourceRevision: input.sourceRevision,
    stateId: input.stateId,
    stateName: input.stateName,
    profile: input.profile,
    phase: input.phase,
    authority: profileAuthority(input.profile),
    owned: input.owned,
    ports: input.ports ?? [],
  });
}

export function validateManifest(value: unknown): LauncherManifest {
  const record = snapshotRecord(value, [
    "version",
    "sourceRevision",
    "stateId",
    "stateName",
    "profile",
    "phase",
    "authority",
    "owned",
    "ports",
  ]);
  if (record.version !== launcherManifestVersion) throw new Error("invalid launcher manifest");
  if (typeof record.sourceRevision !== "string" || !sourceRevisionRe.test(record.sourceRevision))
    throw new Error("invalid launcher manifest");
  if (typeof record.stateId !== "string" || !stateIdRe.test(record.stateId))
    throw new Error("invalid launcher manifest");
  if (typeof record.stateName !== "string" || !stateNameRe.test(record.stateName))
    throw new Error("invalid launcher manifest");
  const profile = normalizeProfile(record.profile);
  if (typeof record.phase !== "string" || !phaseSet.has(record.phase)) throw new Error("invalid launcher manifest");
  if (typeof record.authority !== "string" || !authoritySet.has(record.authority))
    throw new Error("invalid launcher manifest");
  if (record.authority !== profileAuthority(profile)) throw new Error("invalid launcher manifest");
  const owned = snapshotRecord(record.owned, ["sandboxState", "controlDir", "lockName"]);
  for (const key of ["sandboxState", "controlDir", "lockName"] as const) {
    if (typeof owned[key] !== "string" || !resourceRe.test(owned[key])) throw new Error("invalid launcher manifest");
  }
  const ports = snapshotArray(record.ports, 0, 16, (port): number => {
    if (typeof port !== "number" || !Number.isSafeInteger(port) || port < 1 || port > 65535)
      throw new Error("invalid launcher manifest");
    return port;
  });
  return deepFreeze({
    version: launcherManifestVersion,
    sourceRevision: record.sourceRevision,
    stateId: record.stateId,
    stateName: record.stateName,
    profile,
    phase: record.phase as LauncherPhase,
    authority: record.authority as LauncherAuthority,
    owned: deepFreeze({
      sandboxState: owned.sandboxState as string,
      controlDir: owned.controlDir as string,
      lockName: owned.lockName as string,
    }),
    ports,
  });
}

export function canonicalJson(value: unknown): string {
  return `${canonical(value, new WeakSet<object>())}\n`;
}

export function parseCanonicalManifest(text: string): LauncherManifest {
  if (text.length > 8192 || hasDuplicateJsonKeys(text)) throw new Error("invalid launcher manifest");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("invalid launcher manifest");
  }
  const manifest = validateManifest(parsed);
  if (canonicalJson(manifest) !== text) throw new Error("invalid launcher manifest");
  return manifest;
}

export function normalizeDriverResult(
  text: string,
  expectedProfile: LauncherProfile,
  expectedOperation: "create" | "verify" | "reset" | "destroy",
): DriverResult {
  const trimmed = lastJsonLine(text, 8192);
  if (hasDuplicateJsonKeys(trimmed)) throw new Error("invalid launcher driver result");
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error("invalid launcher driver result");
  }
  const record = snapshotOpenRecord(parsed, 12);
  const profile = normalizeProfile(record.profile);
  if (profile !== expectedProfile) throw new Error("invalid launcher driver result");
  const authority = profileAuthority(profile);
  if ("authority" in record && record.authority !== authority) throw new Error("invalid launcher driver result");
  if (record.version === "cogs.dev-driver/v1alpha1") {
    if (profile === "linux-kvm") throw new Error("invalid launcher driver result");
    if (Object.keys(record).sort().join(",") !== "authority,command,profile,result,version")
      throw new Error("invalid launcher driver result");
    if (record.result !== "pass") throw new Error("invalid launcher driver result");
    const op = record.command === "verify" ? "verify" : record.command;
    if (op !== "create" && op !== "verify" && op !== "reset" && op !== "destroy")
      throw new Error("invalid launcher driver result");
    if (op !== expectedOperation) throw new Error("invalid launcher driver result");
    return deepFreeze({ profile, operation: op, result: "pass", authority });
  }
  if (record.status === "ready" && expectedOperation !== "destroy") {
    if (profile !== "linux-kvm") throw new Error("invalid launcher driver result");
    if (
      Object.keys(record).sort().join(",") !==
      "distinct_boot_ids,guest_image_sha512,guest_ip,guest_kernel,guest_root,host_ip,kvm_enabled,profile,proxy_port,status"
    )
      throw new Error("invalid launcher driver result");
    if (
      record.guest_root !== true ||
      record.kvm_enabled !== true ||
      record.distinct_boot_ids !== true ||
      typeof record.guest_kernel !== "string" ||
      !/^[0-9A-Za-z._-]{1,64}$/u.test(record.guest_kernel) ||
      typeof record.guest_image_sha512 !== "string" ||
      !/^[a-f0-9]{128}$/u.test(record.guest_image_sha512) ||
      record.host_ip !== "192.0.2.1" ||
      record.guest_ip !== "192.0.2.2" ||
      record.proxy_port !== 18080
    )
      throw new Error("invalid launcher driver result");
    return deepFreeze({ profile, operation: expectedOperation, result: "ready", authority });
  }
  if (record.status === "destroyed" && expectedOperation === "destroy") {
    if (profile !== "linux-kvm") throw new Error("invalid launcher driver result");
    if (Object.keys(record).sort().join(",") !== "profile,status") throw new Error("invalid launcher driver result");
    return deepFreeze({ profile, operation: "destroy", result: "destroyed", authority });
  }
  throw new Error("invalid launcher driver result");
}

function snapshotRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const record = snapshotOpenRecord(value, keys.length);
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("invalid launcher object");
  }
  return record;
}

function snapshotOpenRecord(value: unknown, maxKeys: number): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid launcher object");
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error("invalid launcher object");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new Error("invalid launcher object");
  const keys = Object.keys(descriptors);
  if (Reflect.ownKeys(descriptors).length !== keys.length) throw new Error("invalid launcher object");
  if (keys.length > maxKeys) throw new Error("invalid launcher object");
  const out: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      !descriptor ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true ||
      key === "__proto__" ||
      key === "constructor" ||
      key === "prototype"
    )
      throw new Error("invalid launcher object");
    out[key] = descriptor.value;
  }
  return out;
}

function snapshotArray<T>(value: unknown, min: number, max: number, item: (value: unknown) => T): readonly T[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype)
    throw new Error("invalid launcher array");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const length = Object.getOwnPropertyDescriptor(value, "length");
  if (!length || !("value" in length) || typeof length.value !== "number" || !Number.isSafeInteger(length.value))
    throw new Error("invalid launcher array");
  const size = length.value;
  if (size < min || size > max) throw new Error("invalid launcher array");
  const allowed = new Set(["length", ...Array.from({ length: size }, (_, i) => String(i))]);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string" || !allowed.has(key)))
    throw new Error("invalid launcher array");
  const out: T[] = [];
  for (let index = 0; index < size; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true)
      throw new Error("invalid launcher array");
    out.push(item(descriptor.value));
  }
  return deepFreeze(out);
}

function canonical(value: unknown, seen: WeakSet<object>): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("invalid launcher json");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("invalid launcher json");
    seen.add(value);
    const items = snapshotArray(value, 0, 64, (item) => item);
    return `[${items.map((item) => canonical(item, seen)).join(",")}]`;
  }
  if (!value || typeof value !== "object") throw new Error("invalid launcher json");
  if (seen.has(value)) throw new Error("invalid launcher json");
  seen.add(value);
  const record = snapshotOpenRecord(value, 64);
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(record[key], seen)}`)
    .join(",")}}`;
}

function lastJsonLine(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text) > maxBytes) throw new Error("invalid launcher driver result");
  const lines = text
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  const line = lines.at(-1);
  if (!line?.startsWith("{") || !line.endsWith("}")) throw new Error("invalid launcher driver result");
  return line;
}

export function hasDuplicateJsonKeys(text: string): boolean {
  const stack: Array<Set<string> | undefined> = [];
  let index = 0;
  let expectingKey = false;
  while (index < text.length) {
    const char = text[index];
    if (char === undefined) break;
    if (/\s/u.test(char)) {
      index += 1;
      continue;
    }
    if (char === '"') {
      const [value, next] = readJsonString(text, index);
      index = next;
      let look = index;
      while (/\s/u.test(text[look] ?? "")) look += 1;
      if (expectingKey && text[look] === ":") {
        const current = stack.at(-1);
        if (current?.has(value)) return true;
        current?.add(value);
        expectingKey = false;
      }
      continue;
    }
    if (char === "{") {
      stack.push(new Set());
      expectingKey = true;
    } else if (char === "}") {
      stack.pop();
      expectingKey = false;
    } else if (char === "[") {
      stack.push(undefined);
      expectingKey = false;
    } else if (char === "]") {
      stack.pop();
      expectingKey = false;
    } else if (char === ",") {
      expectingKey = stack.at(-1) instanceof Set;
    } else if (char === ":") {
      expectingKey = false;
    }
    index += 1;
  }
  return false;
}

function readJsonString(text: string, start: number): [string, number] {
  let index = start + 1;
  let raw = '"';
  while (index < text.length) {
    const char = text[index];
    if (char === undefined) throw new Error("invalid launcher json");
    raw += char;
    index += 1;
    if (char === "\\") {
      raw += text[index] ?? "";
      index += 1;
    } else if (char === '"') {
      return [JSON.parse(raw), index];
    }
  }
  throw new Error("invalid launcher json");
}

export function deepFreeze<T>(value: T, seen = new WeakSet<object>()): Readonly<T> {
  if (typeof value === "function") return Object.freeze(value) as Readonly<T>;
  if (!value || typeof value !== "object") return value as Readonly<T>;
  if (seen.has(value)) return value as Readonly<T>;
  seen.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    const descriptor = descriptors[key as keyof typeof descriptors];
    if (!descriptor || !("value" in descriptor)) throw new Error("invalid launcher object");
    const child = descriptor.value;
    if (child && (typeof child === "object" || typeof child === "function")) deepFreeze(child, seen);
  }
  return Object.freeze(value) as Readonly<T>;
}

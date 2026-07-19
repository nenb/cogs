export const workerProtocolVersion = "cogs.dev-launcher-worker-protocol/v1alpha1" as const;

export type ParentChallenge = Readonly<{
  version: typeof workerProtocolVersion;
  type: "parent-challenge";
  startupNonce: string;
}>;

export type ChildIdentityHello = Readonly<{
  version: typeof workerProtocolVersion;
  type: "child-identity";
  startupDigest: `sha256:${string}`;
  pid: number;
  pidIdentity: `sha256:${string}`;
}>;

export type SupervisorAdmit = Readonly<{
  version: typeof workerProtocolVersion;
  type: "supervisor-admit";
  startupDigest: `sha256:${string}`;
}>;

export type ChildReady = Readonly<{
  version: typeof workerProtocolVersion;
  type: "child-ready";
  startupDigest: `sha256:${string}`;
  pid: number;
  pidIdentity: `sha256:${string}`;
  apiPort: number;
}>;

export type SupervisorReadyAck = Readonly<{
  version: typeof workerProtocolVersion;
  type: "supervisor-ready-ack";
  startupDigest: `sha256:${string}`;
}>;

const digestPattern = /^sha256:[a-f0-9]{64}$/u;
const noncePattern = /^[A-Za-z0-9_-]{43}$/u;
const types = new Set([
  "parent-challenge",
  "child-identity",
  "supervisor-admit",
  "child-ready",
  "supervisor-ready-ack",
]);

export function createParentChallenge(input: { withNonce<T>(operation: (nonce: string) => T): T }): ParentChallenge {
  try {
    return input.withNonce((nonce) => {
      return freezeExact({
        version: workerProtocolVersion,
        type: "parent-challenge",
        startupNonce: canonicalNonce(nonce),
      });
    });
  } catch {
    throw fail();
  }
}

export function parseChildIdentityHello(value: unknown): ChildIdentityHello {
  try {
    const record = exact(value, ["pid", "pidIdentity", "startupDigest", "type", "version"]);
    if (record.version !== workerProtocolVersion || record.type !== "child-identity") fail();
    return freezeExact({
      version: workerProtocolVersion,
      type: "child-identity",
      startupDigest: digest(record.startupDigest),
      pid: pid(record.pid),
      pidIdentity: digest(record.pidIdentity),
    });
  } catch {
    throw fail();
  }
}

export function createSupervisorAdmit(startupDigest: string): SupervisorAdmit {
  try {
    return freezeExact({
      version: workerProtocolVersion,
      type: "supervisor-admit",
      startupDigest: digest(startupDigest),
    });
  } catch {
    throw fail();
  }
}

export function parseChildReady(value: unknown): ChildReady {
  try {
    const record = exact(value, ["apiPort", "pid", "pidIdentity", "startupDigest", "type", "version"]);
    if (record.version !== workerProtocolVersion || record.type !== "child-ready") fail();
    return freezeExact({
      version: workerProtocolVersion,
      type: "child-ready",
      startupDigest: digest(record.startupDigest),
      pid: pid(record.pid),
      pidIdentity: digest(record.pidIdentity),
      apiPort: port(record.apiPort),
    });
  } catch {
    throw fail();
  }
}

export function createSupervisorReadyAck(startupDigest: string): SupervisorReadyAck {
  try {
    return freezeExact({
      version: workerProtocolVersion,
      type: "supervisor-ready-ack",
      startupDigest: digest(startupDigest),
    });
  } catch {
    throw fail();
  }
}

export function parseWorkerProtocolMessage(
  value: unknown,
): ParentChallenge | ChildIdentityHello | SupervisorAdmit | ChildReady | SupervisorReadyAck {
  try {
    const record = exactOpen(value);
    if (record.version !== workerProtocolVersion || typeof record.type !== "string" || !types.has(record.type)) fail();
    if (record.type === "parent-challenge") {
      const challenge = exact(value, ["startupNonce", "type", "version"]);
      return freezeExact({
        version: workerProtocolVersion,
        type: "parent-challenge",
        startupNonce: canonicalNonce(challenge.startupNonce),
      });
    }
    if (record.type === "child-identity") return parseChildIdentityHello(value);
    if (record.type === "supervisor-admit")
      return createSupervisorAdmit(exact(value, ["startupDigest", "type", "version"]).startupDigest as string);
    if (record.type === "child-ready") return parseChildReady(value);
    return createSupervisorReadyAck(exact(value, ["startupDigest", "type", "version"]).startupDigest as string);
  } catch {
    throw fail();
  }
}

function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const record = exactOpen(value);
  if (Object.keys(record).sort().join(",") !== [...keys].sort().join(",")) fail();
  return record;
}

function exactOpen(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    fail();
  if (Object.getOwnPropertySymbols(value).length !== 0) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const output: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") fail();
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    output[key] = descriptor.value;
  }
  return output;
}

function freezeExact<T extends Record<string, unknown>>(value: T): Readonly<T> {
  return Object.freeze({ ...value });
}

function canonicalNonce(value: unknown): string {
  if (typeof value !== "string" || !noncePattern.test(value)) fail();
  const decoded = Buffer.from(value, "base64url");
  try {
    if (decoded.length !== 32 || decoded.every((byte) => byte === 0) || decoded.toString("base64url") !== value) fail();
    return value;
  } finally {
    decoded.fill(0);
  }
}

function digest(value: unknown): `sha256:${string}` {
  if (typeof value !== "string" || !digestPattern.test(value)) fail();
  return value as `sha256:${string}`;
}

function pid(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 2 ** 31 - 1) fail();
  return value as number;
}

function port(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 65535) fail();
  return value as number;
}

function fail(): never {
  throw new Error("launcher worker protocol failed");
}

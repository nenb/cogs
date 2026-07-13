import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

const maxBodyBytes = 32 * 1024;
const opaqueId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface FaultState {
  authorizationOutage: boolean;
  auditUnwritable: boolean;
  auditFull: boolean;
  completionFailure: boolean;
  telemetryOutage: boolean;
  delayMs: number;
}

export interface IntentRecord {
  sequence: number;
  intent_id: string;
  case_id: string;
  session_id: string;
  route_id: string;
  credential_required: boolean;
  completion: null | {
    outcome: "success" | "denied" | "failed";
    status_class: number;
    latency_ms: number;
  };
}

export interface FaultInjectorSnapshot {
  intents: readonly IntentRecord[];
  revocation: {
    epoch: number;
    accepting: boolean;
    action: "none" | "deny-new" | "drain";
  };
  capability_checks: {
    total: number;
    header_present: number;
    digest_matched: number;
    accepted: number;
  };
  faults: Readonly<FaultState>;
}

export interface FaultInjector {
  origin: string;
  setFaults(faults: Partial<FaultState>): void;
  denyNew(): void;
  rotateCapability(newCapability: string): void;
  snapshot(): FaultInjectorSnapshot;
  stop(): Promise<void>;
}

interface StartOptions {
  initialCapability: string;
  maxRecords?: number;
}

interface AuthorizationRequest {
  case_id: string;
  session_id: string;
  route_id: string;
  credential_required: boolean;
}

interface CompletionRequest {
  intent_id: string;
  outcome: "success" | "denied" | "failed";
  status_class: number;
  latency_ms: number;
}

function writeJSON(
  response: ServerResponse,
  status: number,
  value: object,
  headers: Readonly<Record<string, string>> = {},
): void {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    ...headers,
  });
  response.end(body);
}

async function readJSON(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > maxBodyBytes) throw new Error("request too large");
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function exactObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    Object.keys(value).every((key) => keys.includes(key))
  );
}

function parseAuthorization(value: unknown): AuthorizationRequest | undefined {
  const keys = ["case_id", "session_id", "route_id", "credential_required"];
  if (!exactObject(value, keys)) return undefined;
  if (
    typeof value.case_id !== "string" ||
    typeof value.session_id !== "string" ||
    typeof value.route_id !== "string" ||
    typeof value.credential_required !== "boolean" ||
    !opaqueId.test(value.case_id) ||
    !opaqueId.test(value.session_id) ||
    !opaqueId.test(value.route_id)
  ) {
    return undefined;
  }
  return value as unknown as AuthorizationRequest;
}

function parseEnvoyAuthorization(request: IncomingMessage): AuthorizationRequest | undefined {
  const single = (name: string): string | undefined => {
    const value = request.headers[name];
    return Array.isArray(value) ? undefined : value;
  };
  const credentialRequired = single("x-cogs-credential-required");
  return parseAuthorization({
    case_id: single("x-cogs-case-id"),
    session_id: single("x-cogs-session-id"),
    route_id: single("x-cogs-route-id"),
    credential_required: credentialRequired === "true" ? true : credentialRequired === "false" ? false : undefined,
  });
}

function parseCompletion(value: unknown): CompletionRequest | undefined {
  const keys = ["intent_id", "outcome", "status_class", "latency_ms"];
  if (!exactObject(value, keys)) return undefined;
  if (
    typeof value.intent_id !== "string" ||
    !opaqueId.test(value.intent_id) ||
    (value.outcome !== "success" && value.outcome !== "denied" && value.outcome !== "failed") ||
    !Number.isInteger(value.status_class) ||
    (value.status_class as number) < 0 ||
    (value.status_class as number) > 5 ||
    !Number.isInteger(value.latency_ms) ||
    (value.latency_ms as number) < 0 ||
    (value.latency_ms as number) > 300_000
  ) {
    return undefined;
  }
  return value as unknown as CompletionRequest;
}

function digest(value: string, key: Buffer): Buffer {
  return createHmac("sha256", key).update(value).digest();
}

export async function startFaultInjector(options: StartOptions): Promise<FaultInjector> {
  const maxRecords = options.maxRecords ?? 10_000;
  if (
    options.initialCapability.length < 16 ||
    !Number.isInteger(maxRecords) ||
    maxRecords < 1 ||
    maxRecords > 100_000
  ) {
    throw new Error("invalid fault injector options");
  }
  const comparisonKey = randomBytes(32);
  let capabilityDigest = digest(options.initialCapability, comparisonKey);
  let sequence = 0;
  let epoch = 1;
  let accepting = true;
  let action: "none" | "deny-new" | "drain" = "none";
  let stopPromise: Promise<void> | undefined;
  const lifecycle = new AbortController();
  const intents: IntentRecord[] = [];
  const sockets = new Set<Socket>();
  const capabilityChecks = { total: 0, header_present: 0, digest_matched: 0, accepted: 0 };
  const faults: FaultState = {
    authorizationOutage: false,
    auditUnwritable: false,
    auditFull: false,
    completionFailure: false,
    telemetryOutage: false,
    delayMs: 0,
  };

  const capabilityAllowed = (request: IncomingMessage): boolean => {
    capabilityChecks.total += 1;
    const supplied = request.headers["proxy-authorization"];
    const value = Array.isArray(supplied) ? undefined : supplied;
    if (value !== undefined) capabilityChecks.header_present += 1;
    const matches = value !== undefined && timingSafeEqual(digest(value, comparisonKey), capabilityDigest);
    if (matches) capabilityChecks.digest_matched += 1;
    if (matches && accepting) capabilityChecks.accepted += 1;
    return matches && accepting;
  };

  const appendIntent = (authorization: AuthorizationRequest): IntentRecord | undefined => {
    if (faults.authorizationOutage || faults.auditUnwritable || faults.auditFull || intents.length >= maxRecords) {
      return undefined;
    }
    const intent: IntentRecord = {
      sequence: sequence++,
      intent_id: randomUUID(),
      case_id: authorization.case_id,
      session_id: authorization.session_id,
      route_id: authorization.route_id,
      credential_required: authorization.credential_required,
      completion: null,
    };
    intents.push(intent);
    return intent;
  };

  const server = createServer((request, response) => {
    void (async () => {
      if (faults.delayMs > 0) await delay(faults.delayMs, undefined, { signal: lifecycle.signal });
      const url = new URL(request.url ?? "/", "http://fault-injector.invalid");
      if (url.search !== "") {
        writeJSON(response, 400, { error: "queries-not-accepted" });
        return;
      }

      if (request.method === "POST" && url.pathname === "/v1/authorize") {
        const authorization = parseAuthorization(await readJSON(request));
        if (authorization === undefined) {
          writeJSON(response, 400, { error: "invalid-request" });
          return;
        }
        const intent = appendIntent(authorization);
        if (intent === undefined) {
          writeJSON(response, 503, {
            error: faults.authorizationOutage ? "authorization-unavailable" : "audit-unavailable",
          });
          return;
        }
        writeJSON(response, 200, {
          allowed: true,
          intent_id: intent.intent_id,
          intent_sequence: intent.sequence,
          telemetry_available: !faults.telemetryOutage,
        });
        return;
      }

      if (url.pathname === "/v1/envoy/capability") {
        const allowed = capabilityAllowed(request);
        writeJSON(response, allowed ? 200 : 403, { allowed, epoch, action });
        return;
      }

      if (url.pathname === "/v1/envoy/authorize") {
        const authorization = parseEnvoyAuthorization(request);
        const requireCapability = request.headers["x-cogs-require-capability"];
        if (
          authorization === undefined ||
          (requireCapability !== "true" && requireCapability !== "false") ||
          (requireCapability === "true" && !capabilityAllowed(request)) ||
          !accepting
        ) {
          writeJSON(response, 403, { error: "denied" });
          return;
        }
        const intent = appendIntent(authorization);
        if (intent === undefined) {
          writeJSON(response, 503, {
            error: faults.authorizationOutage ? "authorization-unavailable" : "audit-unavailable",
          });
          return;
        }
        writeJSON(
          response,
          200,
          { allowed: true, telemetry_available: !faults.telemetryOutage },
          { "x-cogs-intent-id": intent.intent_id },
        );
        return;
      }

      if (request.method === "POST" && url.pathname === "/v1/complete") {
        if (faults.completionFailure || faults.auditUnwritable || faults.auditFull) {
          writeJSON(response, 503, { error: "completion-unavailable" });
          return;
        }
        const completion = parseCompletion(await readJSON(request));
        const intent =
          completion === undefined ? undefined : intents.find((record) => record.intent_id === completion.intent_id);
        if (completion === undefined || intent === undefined || intent.completion !== null) {
          writeJSON(response, 400, { error: "invalid-completion" });
          return;
        }
        intent.completion = {
          outcome: completion.outcome,
          status_class: completion.status_class,
          latency_ms: completion.latency_ms,
        };
        writeJSON(response, 200, { recorded: true, intent_sequence: intent.sequence });
        return;
      }

      if (request.method === "POST" && url.pathname === "/v1/capability/validate") {
        const allowed = capabilityAllowed(request);
        writeJSON(response, allowed ? 200 : 403, {
          allowed,
          epoch,
          action,
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/v1/revocation") {
        writeJSON(response, 200, { epoch, accepting, action });
        return;
      }

      writeJSON(response, 404, { error: "not-found" });
    })().catch(() => {
      if (lifecycle.signal.aborted) {
        response.destroy();
      } else if (!response.headersSent) {
        writeJSON(response, 400, { error: "invalid-request" });
      } else {
        response.destroy();
      }
    });
  });
  server.on("connect", (request, socket) => {
    void (async () => {
      if (faults.delayMs > 0) await delay(faults.delayMs, undefined, { signal: lifecycle.signal });
      // Node exposes CONNECT authority-form targets through the dedicated event even when
      // Envoy's ext_authz path override is configured. This loopback-only hook never opens
      // a tunnel; every CONNECT is treated solely as a capability check.
      const allowed = capabilityAllowed(request);
      const body = `${JSON.stringify({ allowed, epoch, action })}\n`;
      socket.end(
        `HTTP/1.1 ${allowed ? "200 OK" : "403 Forbidden"}\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n${body}`,
      );
    })().catch(() => socket.destroy());
  });
  server.maxConnections = 256;
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address() as AddressInfo;

  return {
    origin: `http://127.0.0.1:${address.port}`,
    setFaults(update) {
      for (const [name, value] of Object.entries(update)) {
        if (!(name in faults)) throw new Error("unknown fault");
        if (name === "delayMs") {
          if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 30_000) {
            throw new Error("invalid fault delay");
          }
        } else if (typeof value !== "boolean") {
          throw new Error("invalid fault value");
        }
      }
      Object.assign(faults, update);
    },
    denyNew() {
      accepting = false;
      action = "deny-new";
      epoch += 1;
    },
    rotateCapability(newCapability) {
      if (newCapability.length < 16) throw new Error("invalid capability");
      accepting = false;
      action = "drain";
      epoch += 1;
      capabilityDigest.fill(0);
      capabilityDigest = digest(newCapability, comparisonKey);
      accepting = true;
    },
    snapshot() {
      return structuredClone({
        intents,
        revocation: { epoch, accepting, action },
        capability_checks: capabilityChecks,
        faults,
      });
    },
    stop: async () => {
      stopPromise ??= (async () => {
        lifecycle.abort();
        for (const socket of sockets) socket.destroy();
        await new Promise<void>((resolve) => server.close(() => resolve()));
        comparisonKey.fill(0);
        capabilityDigest.fill(0);
      })();
      await stopPromise;
    },
  };
}

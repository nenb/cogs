import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import * as grpc from "@grpc/grpc-js";
import type { CogsPolicyAuthorizer } from "../policy/require-policy.ts";
import { requireCogsPolicyAllow } from "../policy/require-policy.ts";
import {
  type CogsTelemetry,
  captureTelemetry,
  emitMetric,
  emitSpan,
  telemetryDuration,
  telemetryStart,
} from "../telemetry/instrumentation.ts";
import type { EgressAuditWal } from "./audit-wal.ts";
import { buildExtAuthzResponse, type CogsExtAuthzCheck, parseExtAuthzCheck } from "./ext-authz-adapter.ts";
import { loadExtAuthzDescriptor } from "./ext-authz-descriptor.ts";
import type { CogsEgressRoute, CogsEgressRoutePlan } from "./route-policy.ts";

const maxActiveChecks = 32;
const maxTokenLength = 256;
const maxDeadlineMs = 2000;
const metadataKey = "x-cogs-authz-token";
const serverOptions = Object.freeze({
  "grpc.max_receive_message_length": 64 * 1024,
  "grpc.max_send_message_length": 16 * 1024,
  "grpc.max_metadata_size": 8 * 1024,
});
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface CogsExtAuthzServerOptions {
  readonly userId: string;
  readonly sessionId: string;
  readonly internalAuthzToken: string;
  readonly proxyCapability: string;
  readonly routePlan: CogsEgressRoutePlan;
  readonly wal: EgressAuditWal;
  readonly policyAuthorizer?: CogsPolicyAuthorizer;
  readonly workerTelemetry?: CogsTelemetry;
  readonly nowMs?: () => number;
}

export interface CogsExtAuthzServer {
  readonly target: string;
  readonly ready: boolean;
  close(): Promise<void>;
}

export class CogsExtAuthzServerError extends Error {
  public readonly code = "COGS_EXT_AUTHZ_SERVER_FAILED";
  public constructor() {
    super("ext_authz server unavailable");
    this.name = "CogsExtAuthzServerError";
  }
}

interface RouteEntry {
  readonly integrationId: string;
  readonly routeId: string;
  readonly host: string;
  readonly port: number;
  readonly method: "GET" | "POST";
  readonly credentialRequired: boolean;
  readonly re: RegExp;
}

export async function startCogsExtAuthzServer(options: CogsExtAuthzServerOptions): Promise<CogsExtAuthzServer> {
  let verifier: SecretVerifier | undefined;
  let server: grpc.Server | undefined;
  try {
    const captured = Object.freeze({ ...options });
    const userId = validOpaque(captured.userId);
    const sessionId = validOpaque(captured.sessionId);
    const internalToken = validSecret(captured.internalAuthzToken);
    const proxyCapability = validSecret(captured.proxyCapability);
    try {
      if (
        captured.policyAuthorizer !== undefined &&
        (typeof captured.policyAuthorizer !== "function" || !Object.isFrozen(captured.policyAuthorizer))
      )
        throw new Error("bad policy authorizer");
    } catch {
      throw new Error("bad policy authorizer");
    }
    if (internalToken === proxyCapability) throw new Error("shared token");
    const routes = buildRouteIndex(captured.routePlan);
    if (!captured.wal.ready) throw new Error("wal unavailable");
    verifier = SecretVerifier.create(internalToken, proxyCapability);
    const descriptor = await loadExtAuthzDescriptor();
    server = new grpc.Server(serverOptions);
    const impl = new ExtAuthzServerImpl(
      userId,
      sessionId,
      routes,
      captured.wal,
      verifier,
      server,
      captured.policyAuthorizer,
      captureTelemetry(captured.workerTelemetry),
      typeof captured.nowMs === "function" ? captured.nowMs : Date.now,
    );
    server.addService(descriptor.authorizationService as grpc.ServiceDefinition<grpc.UntypedServiceImplementation>, {
      Check: impl.check,
    });
    const port = await bind(server);
    impl.markReady(port);
    return impl.surface;
  } catch {
    verifier?.clear();
    try {
      server?.forceShutdown();
    } catch {
      // Preserve generic startup failure.
    }
    throw new CogsExtAuthzServerError();
  }
}

class ExtAuthzServerImpl {
  #ready = false;
  #closing = false;
  #active = 0;
  #closePromise: Promise<void> | undefined;
  #target = "";
  readonly #wal: EgressAuditWal;
  readonly check = (call: grpc.ServerUnaryCall<unknown, unknown>, callback: grpc.sendUnaryData<unknown>) => {
    void this.#check(call, once(callback));
  };
  readonly surface: CogsExtAuthzServer;
  public constructor(
    private readonly userId: string,
    private readonly sessionId: string,
    private readonly routes: ReadonlyMap<string, RouteEntry>,
    wal: EgressAuditWal,
    private readonly verifier: SecretVerifier,
    private readonly server: grpc.Server,
    private readonly policyAuthorizer: CogsPolicyAuthorizer | undefined,
    private readonly workerTelemetry: CogsTelemetry,
    private readonly nowMs: () => number,
  ) {
    this.#wal = wal;
    const self = this;
    this.surface = Object.freeze({
      get target() {
        return self.#target;
      },
      get ready() {
        return self.#ready && self.#wal.ready && !self.#closing;
      },
      close: () => self.close(),
    });
  }
  markReady(port: number): void {
    this.#target = `127.0.0.1:${port}`;
    this.#ready = true;
  }
  async #check(
    call: grpc.ServerUnaryCall<unknown, unknown>,
    callback: (error: grpc.ServiceError | null, value?: unknown) => void,
  ) {
    const start = telemetryStart({ now: this.nowMs });
    if (this.#closing || !this.#ready || !this.#wal.ready) {
      callback(status(grpc.status.UNAVAILABLE));
      return;
    }
    if (this.#active >= maxActiveChecks) {
      callback(status(grpc.status.RESOURCE_EXHAUSTED));
      return;
    }
    this.#active += 1;
    let appendStarted = false;
    try {
      this.#verifyInfrastructure(call);
      const check = safeParseCheck(call.request);
      if (check === undefined) {
        callback(null, buildExtAuthzResponse({ outcome: "deny", status: 403 }));
        return;
      }
      if (call.cancelled) throw status(grpc.status.CANCELLED);
      if (check.mode === "capability") {
        callback(null, this.#capability(check));
        return;
      }
      const recordInput = this.#authorize(check);
      if (recordInput === undefined) {
        emitSpan(this.workerTelemetry, "egress.authorize", {
          outcome: "denied",
          duration_ms: telemetryDuration({ now: this.nowMs }, start),
        });
        emitMetric(this.workerTelemetry, "egress.denials", 1);
        callback(null, buildExtAuthzResponse({ outcome: "deny", status: 403 }));
        return;
      }
      if (call.cancelled) throw status(grpc.status.CANCELLED);
      appendStarted = true;
      const record = await this.#wal.append(recordInput);
      emitSpan(this.workerTelemetry, "wal.append", { operation: "append", outcome: "ok" });
      emitMetric(this.workerTelemetry, "wal.depth", record.sequence + 1);
      emitSpan(this.workerTelemetry, "egress.authorize", {
        outcome: "ok",
        method: record.method,
        credential_required: record.credential_required,
        duration_ms: telemetryDuration({ now: this.nowMs }, start),
      });
      callback(null, buildExtAuthzResponse({ outcome: "allow", intentId: record.intent_id }));
    } catch (error) {
      if (appendStarted) this.#ready = false;
      if (appendStarted) emitMetric(this.workerTelemetry, "wal.failures", 1);
      emitSpan(this.workerTelemetry, appendStarted ? "wal.append" : "egress.authorize", {
        outcome: "error",
        duration_ms: telemetryDuration({ now: this.nowMs }, start),
      });
      callback(isGrpcFailure(error) ? error : status(grpc.status.UNAVAILABLE));
    } finally {
      this.#active -= 1;
    }
  }
  #verifyInfrastructure(call: grpc.ServerUnaryCall<unknown, unknown>): void {
    if (!this.verifier.internalOk(exactMetadata(call.metadata, metadataKey))) throw status(grpc.status.UNAUTHENTICATED);
    const deadline = call.getDeadline();
    const ms =
      deadline instanceof Date
        ? deadline.getTime() - Date.now()
        : typeof deadline === "number"
          ? deadline - Date.now()
          : NaN;
    if (!Number.isFinite(ms) || ms <= 0 || ms > maxDeadlineMs) throw status(grpc.status.DEADLINE_EXCEEDED);
  }
  #capability(check: CogsExtAuthzCheck): unknown {
    if (
      check.sessionId === this.sessionId &&
      check.routeId === undefined &&
      check.requireCapability === true &&
      check.credentialRequired === false &&
      check.proxyAuthorization !== undefined &&
      this.verifier.capabilityOk(check.proxyAuthorization)
    ) {
      return buildExtAuthzResponse({ outcome: "allow_capability" });
    }
    return buildExtAuthzResponse({ outcome: "deny", status: 407 });
  }
  #authorize(check: CogsExtAuthzCheck) {
    const routeId = check.routeId;
    const entry = routeId === undefined ? undefined : this.routes.get(routeId);
    if (
      check.sessionId !== this.sessionId ||
      check.requireCapability !== false ||
      entry === undefined ||
      check.proxyAuthorization !== undefined ||
      check.credentialRequired !== entry.credentialRequired ||
      check.method !== entry.method ||
      check.scheme !== "https" ||
      check.host === undefined ||
      !authorityOk(check.host, entry) ||
      check.pathAndQuery === undefined ||
      !entry.re.test(check.pathAndQuery)
    ) {
      return undefined;
    }
    try {
      requireCogsPolicyAllow(
        {
          version: "cogs.policy/v1alpha1",
          action: "egress.authorize",
          user: this.userId,
          session: this.sessionId,
          resource: entry.routeId,
          attributes: {
            integration_id: entry.integrationId,
            route_id: entry.routeId,
            method: entry.method,
            credential_required: entry.credentialRequired,
          },
        },
        this.policyAuthorizer,
      );
    } catch {
      return undefined;
    }
    return {
      session_id: this.sessionId,
      integration_id: entry.integrationId,
      route_id: entry.routeId,
      method: entry.method,
      credential_required: entry.credentialRequired,
    };
  }
  close(): Promise<void> {
    this.#closePromise ??= this.#close();
    return this.#closePromise;
  }
  async #close(): Promise<void> {
    this.#closing = true;
    this.#ready = false;
    let failed = false;

    try {
      await new Promise<void>((resolve) => {
        const done = () => {
          clearTimeout(timer);
          resolve();
        };
        const force = () => {
          try {
            this.server.forceShutdown();
          } catch {
            failed = true;
          } finally {
            done();
          }
        };
        const timer = setTimeout(force, 200).unref();
        try {
          this.server.tryShutdown(done);
        } catch {
          failed = true;
          force();
        }
      });
      const deadline = Date.now() + 200;
      while (this.#active > 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
    } finally {
      this.verifier.clear();
    }
    if (failed) throw new CogsExtAuthzServerError();
  }
}

function buildRouteIndex(plan: CogsEgressRoutePlan): ReadonlyMap<string, RouteEntry> {
  if (
    !Object.isFrozen(plan) ||
    !Object.isFrozen(plan.integrations) ||
    !Array.isArray(plan.integrations) ||
    plan.integrations.length > 16
  )
    throw new Error("bad plan");
  const routes = new Map<string, RouteEntry>();
  let count = 0;
  for (const integration of plan.integrations) {
    const integrationId = validOpaque(integration.id);
    if (!Object.isFrozen(integration) || !Object.isFrozen(integration.routes) || !Array.isArray(integration.routes))
      throw new Error("bad integration");
    for (const route of integration.routes) {
      if (++count > 256) throw new Error("too many routes");
      const entry = routeEntry(route, integrationId);
      if (routes.has(entry.routeId)) throw new Error("duplicate route");
      routes.set(entry.routeId, entry);
    }
  }
  if (routes.size !== plan.routeCount) throw new Error("bad plan");
  return routes;
}

function routeEntry(route: CogsEgressRoute, parentIntegrationId: string): RouteEntry {
  if (!Object.isFrozen(route) || !Object.isFrozen(route.pathMatch)) throw new Error("mutable route");
  const integrationId = validOpaque(route.integrationId);
  if (integrationId !== parentIntegrationId) throw new Error("wrong integration");
  const routeId = validOpaque(route.routeId);
  const method = route.method === "GET" || route.method === "POST" ? route.method : undefined;
  if (method === undefined) throw new Error("bad method");
  if (typeof route.host !== "string" || route.host.length === 0 || route.host.length > 253 || hasControl(route.host)) {
    throw new Error("bad host");
  }
  if (!Number.isSafeInteger(route.port) || route.port < 1 || route.port > 65_535) throw new Error("bad port");
  if (typeof route.credentialRequired !== "boolean" || route.injectAuth !== route.credentialRequired) {
    throw new Error("bad credential flag");
  }
  if (
    route.pathMatch.kind !== "safe_regex" ||
    route.pathMatch.value.length > 4096 ||
    !route.pathMatch.value.startsWith("^") ||
    !route.pathMatch.value.endsWith("$")
  ) {
    throw new Error("bad regex");
  }
  return Object.freeze({
    integrationId,
    routeId,
    host: route.host,
    port: route.port,
    method,
    credentialRequired: route.credentialRequired,
    re: new RegExp(route.pathMatch.value, "u"),
  });
}

function bind(server: grpc.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.bindAsync("127.0.0.1:0", grpc.ServerCredentials.createInsecure(), (error, port) => {
      if (error !== null) reject(error);
      else if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) reject(new Error("bad port"));
      else resolve(port);
    });
  });
}

class SecretVerifier {
  #cleared = false;
  readonly #key: Buffer;
  readonly #token: Buffer;
  readonly #capability: Buffer;
  private constructor(key: Buffer, token: Buffer, capability: Buffer) {
    this.#key = key;
    this.#token = token;
    this.#capability = capability;
  }
  static create(token: string, capability: string): SecretVerifier {
    const key = randomBytes(32);
    let tokenDigest: Buffer | undefined;
    let capabilityDigest: Buffer | undefined;
    try {
      tokenDigest = digest(key, token);
      capabilityDigest = digest(key, capability);
      return new SecretVerifier(key, tokenDigest, capabilityDigest);
    } catch (error) {
      key.fill(0);
      tokenDigest?.fill(0);
      capabilityDigest?.fill(0);
      throw error;
    }
  }
  internalOk(value: string): boolean {
    return this.#ok(value, this.#token);
  }
  capabilityOk(value: string): boolean {
    return this.#ok(value, this.#capability);
  }
  clear(): void {
    if (this.#cleared) return;
    this.#cleared = true;
    this.#key.fill(0);
    this.#token.fill(0);
    this.#capability.fill(0);
  }
  #ok(value: string, expected: Buffer): boolean {
    try {
      const candidate = digest(this.#key, validSecret(value));
      try {
        return timingSafeEqual(candidate, expected);
      } finally {
        candidate.fill(0);
      }
    } catch {
      return false;
    }
  }
}

function digest(key: Buffer, value: string): Buffer {
  return createHmac("sha256", key).update(value).digest();
}

function safeParseCheck(request: unknown): CogsExtAuthzCheck | undefined {
  try {
    return parseExtAuthzCheck(request);
  } catch {
    return undefined;
  }
}

function exactMetadata(metadata: grpc.Metadata, key: string): string {
  const values = metadata.get(key);
  if (values.length !== 1 || typeof values[0] !== "string") throw status(grpc.status.UNAUTHENTICATED);
  return values[0];
}
function validSecret(value: string): string {
  if (typeof value !== "string" || value.length < 16 || value.length > maxTokenLength || hasControl(value)) {
    throw new Error("bad secret");
  }
  return value;
}
function validOpaque(value: string): string {
  if (typeof value !== "string" || !opaque.test(value)) throw new Error("bad opaque");
  return value;
}
function authorityOk(value: string, route: RouteEntry): boolean {
  return route.port === 443
    ? value === route.host || value === `${route.host}:443`
    : value === `${route.host}:${route.port}`;
}
const grpcFailureBrand = Symbol("cogs.grpc.failure");
function status(code: grpc.status): grpc.ServiceError {
  const error = new Error("ext_authz check failed") as grpc.ServiceError & { [grpcFailureBrand]: true };
  error.code = code;
  error.details = "ext_authz check failed";
  error[grpcFailureBrand] = true;
  return error;
}
function isGrpcFailure(error: unknown): error is grpc.ServiceError {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { [grpcFailureBrand]?: unknown })[grpcFailureBrand] === true &&
    typeof (error as { code?: unknown }).code === "number"
  );
}
function once<T>(callback: grpc.sendUnaryData<T>): (error: grpc.ServiceError | null, value?: T) => void {
  let settled = false;
  return (error, value) => {
    if (!settled) {
      settled = true;
      try {
        callback(error, value);
      } catch {
        // gRPC owns callback delivery; hostile direct callbacks must not settle twice.
      }
    }
  };
}
function hasControl(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 32 || code === 127) return true;
  }
  return false;
}

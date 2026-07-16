import type { ModelAuthRequest, ModelCredentialResolver } from "../auth/model-auth.ts";
import type {
  CogsEnvoyCredentialRequest,
  CogsEnvoyCredentialSource,
  CogsEnvoyCredentialValue,
} from "./envoy-runtime-config.ts";

const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const segment = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export type ModelBackedEgressCredentialSourceOptions = Readonly<{
  userId: string;
  resolver: ModelCredentialResolver;
  signal?: AbortSignal;
}>;

export interface CogsEgressPkiRequest {
  readonly sessionId: string;
  readonly hosts: readonly string[];
  readonly maxSessionExpiresAtMs: number;
  readonly signal?: AbortSignal;
}

export type CogsEgressPkiMaterial = Readonly<{
  certificateChainPem: string;
  privateKeyPem: string;
  caCertificatePem: string;
  expiresAtMs: number;
}>;

export interface CogsEgressPkiSource {
  withPkiMaterial<T>(
    request: CogsEgressPkiRequest,
    consume: (material: CogsEgressPkiMaterial) => Promise<T>,
  ): Promise<T>;
}

export class CogsEgressMaterialError extends Error {
  public readonly code = "COGS_EGRESS_MATERIAL_FAILED";
  public constructor() {
    super("egress material unavailable");
    this.name = "CogsEgressMaterialError";
  }
}

export class ModelBackedEgressCredentialSource implements CogsEnvoyCredentialSource {
  readonly #userId: string;
  readonly #resolver: ModelCredentialResolver;
  readonly #signal: AbortSignal | undefined;

  public constructor(options: ModelBackedEgressCredentialSourceOptions) {
    try {
      this.#userId = validOpaque(options.userId);
      this.#resolver = options.resolver;
      this.#signal = options.signal;
    } catch {
      throw new CogsEgressMaterialError();
    }
  }

  public async withCredential(
    request: CogsEnvoyCredentialRequest,
    consume: (credential: CogsEnvoyCredentialValue) => Promise<void>,
  ): Promise<void> {
    try {
      if (this.#signal?.aborted) throw new Error("aborted");
      const captured = Object.freeze({
        integrationId: request.integrationId,
        secretHandle: request.secretHandle,
        authType: request.authType,
      });
      const modelRequest: ModelAuthRequest = Object.freeze({
        userId: this.#userId,
        provider: validOpaque(captured.integrationId),
        model: modelFor(captured.authType),
        credentialHandle: validHandle(captured.secretHandle, this.#userId),
        ...(this.#signal === undefined ? {} : { signal: this.#signal }),
      });
      await this.#resolver.withApiKey(modelRequest, async (material) =>
        consume(credentialFor(captured.authType, material)),
      );
    } catch {
      throw new CogsEgressMaterialError();
    }
  }
}

function modelFor(authType: CogsEnvoyCredentialRequest["authType"]): string {
  if (authType === "bearer_header") return "egress-bearer";
  if (authType === "api_key_header") return "egress-api-key";
  if (authType === "basic_header") return "egress-basic";
  throw new Error("bad auth");
}

function credentialFor(authType: CogsEnvoyCredentialRequest["authType"], material: string): CogsEnvoyCredentialValue {
  if (authType === "bearer_header") return Object.freeze({ type: "bearer", token: material });
  if (authType === "api_key_header") return Object.freeze({ type: "api_key", value: material });
  if (authType === "basic_header") return Object.freeze({ type: "basic", base64: material });
  throw new Error("bad auth");
}

function validOpaque(value: string): string {
  if (typeof value !== "string" || !opaque.test(value)) throw new Error("bad id");
  return value;
}

function validHandle(value: string, userId: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 512) throw new Error("bad handle");
  const parts = value.split("/");
  if (parts.some((part) => !segment.test(part))) throw new Error("bad handle");
  if (parts[0] === "users" && parts.length >= 3 && parts[1] === userId) return value;
  if (parts[0] === "organizations" && parts.length >= 2) return value;
  throw new Error("bad handle");
}

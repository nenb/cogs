import { createPrivateKey, createPublicKey, timingSafeEqual, X509Certificate } from "node:crypto";
import type { OpenBaoIdentityPort } from "../auth/model-auth.ts";
import type { CogsEgressPkiMaterial, CogsEgressPkiRequest, CogsEgressPkiSource } from "./egress-material.ts";

const dns = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const name = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const opaque = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const jsonType = /^application\/json(?:\s*;|$)/i;
const pemCert = /^-----BEGIN CERTIFICATE-----\n[\s\S]+\n-----END CERTIFICATE-----\n?$/;
const pemKey =
  /^-----BEGIN (?:PRIVATE|RSA PRIVATE|EC PRIVATE) KEY-----\n[\s\S]+\n-----END (?:PRIVATE|RSA PRIVATE|EC PRIVATE) KEY-----\n?$/;
const maxSessionMs = 8 * 60 * 60 * 1000;
const maxRequestMs = 24 * 60 * 60 * 1000;

type Data = Readonly<{
  certificate: string;
  private_key: string;
  issuing_ca?: string;
  ca_chain?: string[];
  expiration?: number;
  private_key_type?: string;
}>;

type KeyPem = Readonly<{ pem: string; type: string }>;

export type OpenBaoEgressPkiSourceOptions = Readonly<{
  origin: string;
  mount: string;
  role: string;
  identity: OpenBaoIdentityPort;
  allowLoopbackHttpDevelopment?: boolean;
  timeoutMs?: number;
  maxResponseBytes?: number;
  minValidityMarginMs?: number;
  fetchImpl?: typeof fetch;
}>;

export class CogsEgressPkiError extends Error {
  public readonly code = "COGS_EGRESS_PKI_FAILED";
  public constructor() {
    super("egress PKI material unavailable");
    this.name = "CogsEgressPkiError";
  }
}

export class OpenBaoEgressPkiSource implements CogsEgressPkiSource {
  readonly #origin: string;
  readonly #mount: string;
  readonly #role: string;
  readonly #identity: OpenBaoIdentityPort;
  readonly #timeoutMs: number;
  readonly #maxBytes: number;
  readonly #marginMs: number;
  readonly #fetch: typeof fetch;

  public constructor(options: OpenBaoEgressPkiSourceOptions) {
    try {
      this.#origin = origin(options.origin, options.allowLoopbackHttpDevelopment === true);
      this.#mount = named(options.mount);
      this.#role = named(options.role);
      this.#identity = options.identity;
      this.#timeoutMs = integer(options.timeoutMs ?? 5_000, 1, 60_000);
      this.#maxBytes = integer(options.maxResponseBytes ?? 64 * 1024, 4096, 1024 * 1024);
      this.#marginMs = integer(options.minValidityMarginMs ?? 30_000, 0, 5 * 60 * 1000);
      this.#fetch = options.fetchImpl ?? fetch;
    } catch {
      throw new CogsEgressPkiError();
    }
  }

  public async withPkiMaterial<T>(
    request: CogsEgressPkiRequest,
    consume: (material: CogsEgressPkiMaterial) => Promise<T>,
  ): Promise<T> {
    try {
      const captured = Object.freeze({
        sessionId: request.sessionId,
        hosts: [...request.hosts],
        maxSessionExpiresAtMs: request.maxSessionExpiresAtMs,
        signal: request.signal,
      });
      if (captured.signal?.aborted) throw new Error("aborted");
      if (typeof captured.sessionId !== "string" || !opaque.test(captured.sessionId)) throw new Error("bad session");
      const hosts = hostSet(captured.hosts);
      const now = Date.now();
      const ttlMs = ttl(captured.maxSessionExpiresAtMs, now, this.#marginMs);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
      const onAbort = () => controller.abort();
      captured.signal?.addEventListener("abort", onAbort, { once: true });
      try {
        const data = await tokenOnce(this.#identity, controller.signal, async (token) => {
          const body = JSON.stringify({
            common_name: hosts[0],
            ...(hosts.length === 1 ? {} : { alt_names: hosts.slice(1).join(",") }),
            ttl: `${Math.ceil(ttlMs / 1000)}s`,
          });
          const response = await this.#fetch(
            `${this.#origin}/v1/${encodeURIComponent(this.#mount)}/issue/${encodeURIComponent(this.#role)}`,
            {
              method: "POST",
              headers: {
                "x-vault-token": secret(token),
                accept: "application/json",
                "content-type": "application/json",
              },
              body,
              redirect: "error",
              signal: controller.signal,
            },
          );
          return parse(await bounded(response, this.#maxBytes, controller.signal), response);
        });
        const material = validateMaterial(data, hosts, captured.maxSessionExpiresAtMs, this.#marginMs);
        if (controller.signal.aborted) throw new Error("aborted");
        return await consume(material);
      } finally {
        clearTimeout(timeout);
        captured.signal?.removeEventListener("abort", onAbort);
      }
    } catch {
      throw new CogsEgressPkiError();
    }
  }
}

function validateMaterial(
  data: Data,
  hosts: readonly string[],
  expiresAt: number,
  marginMs: number,
): CogsEgressPkiMaterial {
  const leafPem = certPem(data.certificate);
  const privateKey = keyPem(data.private_key);
  if (data.private_key_type !== undefined && data.private_key_type !== privateKey.type) throw new Error("bad key type");
  const leaf = new X509Certificate(leafPem);
  matchKey(leaf, privateKey.pem);
  matchSan(leaf, hosts);
  const expiresAtMs = Date.parse(leaf.validTo);
  const validFromMs = Date.parse(leaf.validFrom);
  if (
    !Number.isFinite(validFromMs) ||
    !Number.isFinite(expiresAtMs) ||
    Date.now() + 60_000 < validFromMs ||
    expiresAtMs < expiresAt + marginMs
  )
    throw new Error("bad lifetime");
  if (
    data.expiration !== undefined &&
    (!Number.isSafeInteger(data.expiration) || Math.abs(data.expiration * 1000 - expiresAtMs) > 1000)
  )
    throw new Error("bad expiration");
  const caPems = caChain(data);
  const caCerts = caPems.map((pem) => new X509Certificate(pem));
  for (const cert of [leaf, ...caCerts]) validLifetime(cert, expiresAt + marginMs);
  const firstCa = caCerts[0];
  const rootCa = caCerts.at(-1);
  if (
    firstCa === undefined ||
    rootCa === undefined ||
    caCerts.some((cert) => !cert.ca) ||
    !leaf.verify(firstCa.publicKey)
  )
    throw new Error("bad chain");
  for (let index = 0; index < caCerts.length - 1; index += 1) {
    const issuer = caCerts[index + 1];
    const subject = caCerts[index];
    if (issuer === undefined || subject === undefined || !subject.verify(issuer.publicKey))
      throw new Error("bad chain");
  }
  if (!rootCa.verify(rootCa.publicKey)) throw new Error("bad root");
  const caCertificatePem = caPems.at(-1);
  if (caCertificatePem === undefined) throw new Error("missing ca");
  return Object.freeze({
    certificateChainPem: [leafPem, ...caPems.slice(0, -1)].join(""),
    privateKeyPem: privateKey.pem,
    caCertificatePem,
    expiresAtMs,
  });
}

function caChain(data: Data): string[] {
  const source =
    data.ca_chain === undefined || data.ca_chain.length === 0
      ? data.issuing_ca === undefined
        ? []
        : [data.issuing_ca]
      : data.ca_chain;
  const chain = source.map(certPem);
  if (chain.length < 1 || chain.length > 8 || new Set(chain).size !== chain.length) throw new Error("bad chain");
  if (data.issuing_ca !== undefined && certPem(data.issuing_ca) !== chain[0]) throw new Error("bad issuing ca");
  return chain;
}

function validLifetime(cert: X509Certificate, minimumExpiresAt: number): void {
  const validFrom = Date.parse(cert.validFrom);
  const validTo = Date.parse(cert.validTo);
  if (
    !Number.isFinite(validFrom) ||
    !Number.isFinite(validTo) ||
    Date.now() + 60_000 < validFrom ||
    validTo < minimumExpiresAt
  )
    throw new Error("bad lifetime");
}

function matchKey(cert: X509Certificate, keyPemValue: string): void {
  const certDer = Buffer.from(cert.publicKey.export({ type: "spki", format: "der" }));
  let keyDer: Buffer | undefined;
  try {
    keyDer = Buffer.from(createPublicKey(createPrivateKey(keyPemValue)).export({ type: "spki", format: "der" }));
    if (certDer.length !== keyDer.length || !timingSafeEqual(certDer, keyDer)) throw new Error("key mismatch");
  } finally {
    certDer.fill(0);
    keyDer?.fill(0);
  }
}

function matchSan(cert: X509Certificate, hosts: readonly string[]): void {
  const raw = cert.subjectAltName;
  if (raw === undefined || raw.includes('"') || /(?:IP Address|URI|email):/i.test(raw)) throw new Error("bad san");
  const found = raw.split(/,\s*/).map((item) => {
    if (!item.startsWith("DNS:")) throw new Error("bad san");
    return item.slice(4);
  });
  if (
    found.length !== hosts.length ||
    found.some((host) => !hosts.includes(host)) ||
    hosts.some((host) => !found.includes(host))
  )
    throw new Error("bad san");
}

function parse(text: string, response: Response): Data {
  const length = response.headers.get("content-length");
  const type = response.headers.get("content-type") ?? "";
  if (response.status !== 200 || !jsonType.test(type) || (length !== null && !/^[0-9]+$/.test(length)))
    throw new Error("bad response");
  const root = JSON.parse(text) as unknown;
  if (!plain(root)) throw new Error("bad json");
  only(root, [
    "request_id",
    "lease_id",
    "renewable",
    "lease_duration",
    "data",
    "wrap_info",
    "warnings",
    "auth",
    "mount_type",
  ]);
  if (root.request_id !== undefined && typeof root.request_id !== "string") throw new Error("bad request id");
  if (root.lease_id !== undefined && typeof root.lease_id !== "string") throw new Error("bad lease id");
  if (root.renewable !== undefined && typeof root.renewable !== "boolean") throw new Error("bad renewable");
  if (root.mount_type !== undefined && root.mount_type !== "pki") throw new Error("bad mount type");
  if (root.auth !== undefined && root.auth !== null) throw new Error("bad auth");
  if (root.wrap_info !== undefined && root.wrap_info !== null) throw new Error("bad wrap");
  if (
    root.warnings !== undefined &&
    root.warnings !== null &&
    (!Array.isArray(root.warnings) || !root.warnings.every((item) => typeof item === "string"))
  )
    throw new Error("bad warnings");
  const leaseDuration = root.lease_duration;
  if (
    leaseDuration !== undefined &&
    (typeof leaseDuration !== "number" || !Number.isSafeInteger(leaseDuration) || leaseDuration < 0)
  )
    throw new Error("bad lease");
  if (!plain(root.data)) throw new Error("bad data");
  only(root.data, [
    "certificate",
    "private_key",
    "issuing_ca",
    "ca_chain",
    "serial_number",
    "expiration",
    "private_key_type",
  ]);
  const data = root.data as Record<string, unknown>;
  if (typeof data.certificate !== "string" || typeof data.private_key !== "string") throw new Error("missing material");
  if (data.issuing_ca !== undefined && typeof data.issuing_ca !== "string") throw new Error("bad ca");
  if (
    data.ca_chain !== undefined &&
    (!Array.isArray(data.ca_chain) || !data.ca_chain.every((item) => typeof item === "string"))
  )
    throw new Error("bad chain");
  if (data.serial_number !== undefined && typeof data.serial_number !== "string") throw new Error("bad serial");
  if (data.expiration !== undefined && (!Number.isSafeInteger(data.expiration) || typeof data.expiration !== "number"))
    throw new Error("bad expiration");
  if (data.private_key_type !== undefined && typeof data.private_key_type !== "string") throw new Error("bad key type");
  return data as Data;
}

async function bounded(response: Response, maximum: number, signal: AbortSignal): Promise<string> {
  const type = response.headers.get("content-type") ?? "";
  const length = response.headers.get("content-length");
  if (
    response.status !== 200 ||
    !jsonType.test(type) ||
    (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > maximum))
  ) {
    response.body?.cancel().catch(() => undefined);
    throw new Error("bad response");
  }
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Error("missing body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      if (signal.aborted) throw new Error("aborted");
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maximum) throw new Error("too large");
      chunks.push(next.value);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  } catch (error) {
    reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
}

async function tokenOnce<T>(
  identity: OpenBaoIdentityPort,
  signal: AbortSignal,
  operation: (token: string) => Promise<T>,
): Promise<T> {
  let active = true;
  let called = false;
  let promise: Promise<void> | undefined;
  let result: { value: T } | undefined;
  try {
    await identity.withToken(signal, (token) => {
      if (!active || called) return Promise.reject(new Error("bad callback"));
      called = true;
      promise = operation(token).then((value) => {
        result = { value };
      });
      return promise;
    });
    if (!called || promise === undefined) throw new Error("missing callback");
    await promise;
    if (result === undefined) throw new Error("missing result");
    return result.value;
  } finally {
    active = false;
  }
}

function hostSet(hosts: string[]): string[] {
  if (!Array.isArray(hosts) || hosts.length < 1 || hosts.length > 32) throw new Error("bad hosts");
  const sorted = hosts
    .map((host) => (typeof host === "string" && dns.test(host) && !/^[0-9.]+$/.test(host) ? host : ""))
    .sort();
  if (sorted.some((host) => host === "") || new Set(sorted).size !== sorted.length) throw new Error("bad hosts");
  return sorted;
}

function ttl(expiresAt: number, now: number, margin: number): number {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt - now > maxSessionMs)
    throw new Error("bad expiry");
  const value = expiresAt - now + margin;
  if (value < 1 || value > maxRequestMs) throw new Error("bad ttl");
  return value;
}

function certPem(value: string): string {
  if (
    typeof value !== "string" ||
    value.length < 128 ||
    value.length > 32768 ||
    !pemCert.test(value) ||
    badChars(value) ||
    blockCount(value) !== 1
  )
    throw new Error("bad cert");
  return value.endsWith("\n") ? value : `${value}\n`;
}
function keyPem(value: string): KeyPem {
  if (
    typeof value !== "string" ||
    value.length < 128 ||
    value.length > 32768 ||
    !pemKey.test(value) ||
    badChars(value) ||
    blockCount(value) !== 1
  )
    throw new Error("bad key");
  const pem = value.endsWith("\n") ? value : `${value}\n`;
  const key = createPrivateKey(pem);
  const type = key.asymmetricKeyType;
  if (type !== "rsa" && type !== "ec" && type !== "ed25519") throw new Error("bad key type");
  return { pem, type };
}
function blockCount(value: string): number {
  return (value.match(/-----BEGIN /g) ?? []).length + (value.match(/-----END /g) ?? []).length - 1;
}
function badChars(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if ((code < 0x20 && code !== 0x0a) || code === 0x7f || code > 0x7e) return true;
  }
  return false;
}
function origin(value: string, dev: boolean): string {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error("bad origin");
  if (
    url.protocol === "https:" ||
    (url.protocol === "http:" && dev && ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname))
  )
    return url.origin;
  throw new Error("bad origin");
}
function named(value: string): string {
  if (typeof value !== "string" || !name.test(value)) throw new Error("bad name");
  return value;
}
function integer(value: number, min: number, max: number): number {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error("bad integer");
  return value;
}
function secret(value: string): string {
  if (typeof value !== "string" || value.length < 8 || value.length > 8192 || !/^[\x21-\x7e]+$/.test(value))
    throw new Error("bad secret");
  return value;
}
function plain(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}
function only(value: Record<string, unknown>, keys: string[]): void {
  if (!Object.keys(value).every((key) => keys.includes(key))) throw new Error("unknown key");
}

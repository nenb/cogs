import { execFile } from "node:child_process";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createSocket, type Socket as UdpSocket } from "node:dgram";
import type { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import type { IncomingMessage } from "node:http";
import { createSecureServer, type Http2SecureServer, type Http2ServerRequest } from "node:http2";
import { createServer, type Socket, type Server as TcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const clientWheel = Buffer.from(
  "UEsDBBQAAAAIAAAAIVCn0vFHGAAAABYAAAAYAAAAY29nc19maXh0dXJlL19faW5pdF9fLnB5i48vSy0qzszPi49XsFVQMtQz0DNQ4gIAUEsDBBQAAAAIAAAAIVD9A6ASNAAAADkAAAAlAAAAY29nc19maXh0dXJlLTEuMC4wLmRpc3QtaW5mby9NRVRBREFUQfNNLUlMSSxJ1A1LLSrOzM+zUjDSM+TyS8xNtVJIzk8v1k3LrCgpLUrlgssb6hnoGXBxAQBQSwMEFAAAAAgAAAAhUAFy6+ZTAAAAUwAAACIAAABjb2dzX2ZpeHR1cmUtMS4wLjAuZGlzdC1pbmZvL1dIRUVMC89ITc3RDUstKs7Mz7NSMNQz4HJPzUstSizJL7JSSM5PL9ZNy6woKS1K5QrKzy/R9SzWDQBycjKTrBRKikpTuUIS060UCiqNdfPy81J1E/MquQBQSwMEFAAAAAgAAAAhUAAAAAACAAAAAAAAACMAAABjb2dzX2ZpeHR1cmUtMS4wLjAuZGlzdC1pbmZvL1JFQ09SRAMAUEsBAhQDFAAAAAgAAAAhUKfS8UcYAAAAFgAAABgAAAAAAAAAAAAAAKQBAAAAAGNvZ3NfZml4dHVyZS9fX2luaXRfXy5weVBLAQIUAxQAAAAIAAAAIVD9A6ASNAAAADkAAAAlAAAAAAAAAAAAAACkAU4AAABjb2dzX2ZpeHR1cmUtMS4wLjAuZGlzdC1pbmZvL01FVEFEQVRBUEsBAhQDFAAAAAgAAAAhUAFy6+ZTAAAAUwAAACIAAAAAAAAAAAAAAKQBxQAAAGNvZ3NfZml4dHVyZS0xLjAuMC5kaXN0LWluZm8vV0hFRUxQSwECFAMUAAAACAAAACFQAAAAAAIAAAAAAAAAIwAAAAAAAAAAAAAApAFYAQAAY29nc19maXh0dXJlLTEuMC4wLmRpc3QtaW5mby9SRUNPUkRQSwUGAAAAAAQABAA6AQAAmwEAAAAA",
  "base64",
);
const clientNpmTarball = Buffer.from(
  "H4sIAB5PVWoC/+3OQQrCMBBG4RxFspZ0UmMEV14llFiqmJamFUG8u1F3rkUE37d5MP9mhtAcQxur4VVzyH1SHyaFd+7Z4r0i61rZlZd648U97tZ6L2oh6gvmPIWxvKL+01WncIp6q3dN3+Zq312meYx6qc9xzF2fymKNGNE3BQAAAAAAAAAAAAAAAAD4IXeM2RvDACgAAA==",
  "base64",
);
const packetLine = (value: string) => `${(Buffer.byteLength(value) + 4).toString(16).padStart(4, "0")}${value}`;
const gitAdvertisement = Buffer.from(
  `${packetLine("# service=git-upload-pack\n")}0000${packetLine(`${"1".repeat(40)} HEAD\0symref=HEAD:refs/heads/main\n`)}0000`,
);

export type FixtureRoute =
  | "health"
  | "header-protected"
  | "api-key-protected"
  | "basic-protected"
  | "redirect"
  | "large"
  | "stream"
  | "delayed"
  | "client-ok"
  | "client-wheel"
  | "client-npm"
  | "client-git"
  | "unknown";

export interface HttpObservation {
  kind: "http";
  protocol: "http/1.1" | "h2";
  route: FixtureRoute;
  method: string;
  authority_present: boolean;
  authority_matches: boolean | null;
  credential_present: boolean;
  credential_matches: boolean | null;
}

export interface DenialSensorObservation {
  kind: "tcp-reached" | "udp-reached";
}

export type FixtureObservation = HttpObservation | DenialSensorObservation;

export interface UpstreamFixtureOptions {
  expectedCredentials: {
    bearer: string;
    apiKey: string;
    basic: string;
  };
  redirectLocation: string;
  largeResponseBytes?: number;
  streamChunks?: number;
  streamIntervalMs?: number;
  delayedResponseMs?: number;
  maxObservations?: number;
  maxConcurrentRequests?: number;
  expectedAuthority?: string;
}

export interface UpstreamFixtures {
  tlsOrigin: string;
  tcpSensorPort: number;
  udpSensorPort: number;
  caCertificatePem: string;
  observations(): readonly FixtureObservation[];
  stop(): Promise<void>;
}

interface FixtureResponse {
  readonly destroyed: boolean;
  readonly headersSent: boolean;
  writeHead(statusCode: number, headers: Record<string, string | number>): unknown;
  write(chunk: Buffer): boolean;
  end(data?: string | Buffer): unknown;
}

interface CertificateMaterial {
  ca: Buffer;
  cert: Buffer;
  key: Buffer;
}

async function generateCertificates(): Promise<CertificateMaterial> {
  const directory = await mkdtemp(join(tmpdir(), "cogs-upstream-fixture-"));
  const caKey = join(directory, "ca.key");
  const caCert = join(directory, "ca.crt");
  const leafKey = join(directory, "leaf.key");
  const leafCsr = join(directory, "leaf.csr");
  const leafCert = join(directory, "leaf.crt");
  const extensions = join(directory, "leaf.ext");
  try {
    await writeFile(
      extensions,
      [
        "basicConstraints=critical,CA:FALSE",
        "keyUsage=critical,digitalSignature,keyEncipherment",
        "extendedKeyUsage=serverAuth",
        "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    const common = { cwd: directory, maxBuffer: 64 * 1024, windowsHide: true, timeout: 10_000 } as const;
    await execFileAsync(
      "openssl",
      ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", caKey],
      common,
    );
    await execFileAsync(
      "openssl",
      ["req", "-x509", "-new", "-key", caKey, "-sha256", "-days", "2", "-subj", "/CN=Cogs Test CA", "-out", caCert],
      common,
    );
    await execFileAsync(
      "openssl",
      ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", leafKey],
      common,
    );
    await execFileAsync("openssl", ["req", "-new", "-key", leafKey, "-subj", "/CN=localhost", "-out", leafCsr], common);
    await execFileAsync(
      "openssl",
      [
        "x509",
        "-req",
        "-in",
        leafCsr,
        "-CA",
        caCert,
        "-CAkey",
        caKey,
        "-CAcreateserial",
        "-days",
        "2",
        "-sha256",
        "-extfile",
        extensions,
        "-out",
        leafCert,
      ],
      common,
    );
    const material = {
      ca: await readFile(caCert),
      cert: await readFile(leafCert),
      key: await readFile(leafKey),
    };
    await rm(directory, { recursive: true, force: true });
    return material;
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

function digestValue(value: string, key: Buffer): Buffer {
  return createHmac("sha256", key).update(value).digest();
}

function compareCredential(actual: string | undefined, expectedDigest: Buffer, key: Buffer): boolean {
  if (actual === undefined) return false;
  return timingSafeEqual(digestValue(actual, key), expectedDigest);
}

function classifyRoute(pathname: string): FixtureRoute {
  switch (pathname) {
    case "/health":
      return "health";
    case "/protected/header":
      return "header-protected";
    case "/protected/api-key":
      return "api-key-protected";
    case "/protected/basic":
      return "basic-protected";
    case "/redirect":
      return "redirect";
    case "/large":
      return "large";
    case "/stream":
      return "stream";
    case "/delayed":
      return "delayed";
    case "/clients/ok":
      return "client-ok";
    case "/clients/cogs_fixture-1.0.0-py3-none-any.whl":
      return "client-wheel";
    case "/clients/cogs-fixture-1.0.0.tgz":
      return "client-npm";
    case "/clients/repo.git/info/refs":
      return "client-git";
    default:
      return "unknown";
  }
}

function listen(server: TcpServer | Http2SecureServer, host = "127.0.0.1"): Promise<number> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    server.once("error", onError);
    server.listen(0, host, () => {
      server.off("error", onError);
      const address = server.address();
      if (address === null || typeof address === "string") return reject(new Error("fixture did not bind a TCP port"));
      resolve(address.port);
    });
  });
}

function listenUdp(socket: UdpSocket): Promise<number> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    socket.once("error", onError);
    socket.bind(0, "127.0.0.1", () => {
      socket.off("error", onError);
      const address = socket.address();
      resolve(address.port);
    });
  });
}

function closeTcp(server: TcpServer | Http2SecureServer): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

function closeUdp(socket: UdpSocket): Promise<void> {
  return new Promise((resolve) => socket.close(() => resolve()));
}

async function closeWithin(operation: Promise<void>, milliseconds = 2_000): Promise<void> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error("fixture teardown timed out")), milliseconds);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

export async function startUpstreamFixtures(options: UpstreamFixtureOptions): Promise<UpstreamFixtures> {
  const maxObservations = options.maxObservations ?? 1_000;
  const largeResponseBytes = options.largeResponseBytes ?? 1024 * 1024;
  const streamChunks = options.streamChunks ?? 8;
  const streamIntervalMs = options.streamIntervalMs ?? 25;
  const delayedResponseMs = options.delayedResponseMs ?? 250;
  const maxConcurrentRequests = options.maxConcurrentRequests ?? 128;
  let redirect: URL;
  try {
    redirect = new URL(options.redirectLocation);
  } catch {
    throw new Error("redirect location must be an absolute URL");
  }
  if (
    redirect.protocol !== "https:" ||
    redirect.username !== "" ||
    redirect.password !== "" ||
    /[\r\n]/.test(options.redirectLocation) ||
    Object.values(options.expectedCredentials).some(
      (value) => value.length === 0 || options.redirectLocation.includes(value),
    ) ||
    !Number.isInteger(maxObservations) ||
    maxObservations < 1 ||
    maxObservations > 100_000 ||
    !Number.isInteger(largeResponseBytes) ||
    largeResponseBytes < 1 ||
    largeResponseBytes > 16 * 1024 * 1024 ||
    !Number.isInteger(streamChunks) ||
    streamChunks < 1 ||
    streamChunks > 10_000 ||
    !Number.isInteger(streamIntervalMs) ||
    streamIntervalMs < 1 ||
    streamIntervalMs > 60_000 ||
    !Number.isInteger(delayedResponseMs) ||
    delayedResponseMs < 1 ||
    delayedResponseMs > 300_000 ||
    !Number.isInteger(maxConcurrentRequests) ||
    maxConcurrentRequests < 1 ||
    maxConcurrentRequests > 1_000
  ) {
    throw new Error("invalid upstream fixture options");
  }

  const certificates = await generateCertificates();
  const comparisonKey = randomBytes(32);
  const expectedDigests = {
    bearer: digestValue(options.expectedCredentials.bearer, comparisonKey),
    apiKey: digestValue(options.expectedCredentials.apiKey, comparisonKey),
    basic: digestValue(options.expectedCredentials.basic, comparisonKey),
  };
  const expectedAuthorityDigest =
    options.expectedAuthority === undefined ? undefined : digestValue(options.expectedAuthority, comparisonKey);
  const recorded: HttpObservation[] = [];
  const sockets = new Set<Socket>();
  const lifecycle = new AbortController();
  let tcpReached = false;
  let udpReached = false;
  let activeRequests = 0;
  let stopPromise: Promise<void> | undefined;

  const record = (observation: HttpObservation): boolean => {
    if (recorded.length >= maxObservations) return false;
    recorded.push(Object.freeze(observation));
    return true;
  };

  const tls = createSecureServer({ key: certificates.key, cert: certificates.cert, allowHTTP1: true });
  certificates.key.fill(0);
  tls.maxConnections = maxConcurrentRequests;
  tls.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });

  const waitForWritable = (response: FixtureResponse): Promise<void> => {
    const emitter = response as unknown as EventEmitter;
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        emitter.off("drain", onDrain);
        emitter.off("close", onClose);
        emitter.off("error", onError);
      };
      const onDrain = () => {
        cleanup();
        resolve();
      };
      const onClose = () => {
        cleanup();
        reject(new Error("fixture response closed during backpressure"));
      };
      const onError = () => {
        cleanup();
        reject(new Error("fixture response failed during backpressure"));
      };
      emitter.on("drain", onDrain);
      emitter.on("close", onClose);
      emitter.on("error", onError);
    });
  };

  const writeChunk = async (response: FixtureResponse, chunk: Buffer): Promise<void> => {
    if (response.write(chunk)) return;
    await waitForWritable(response);
  };

  const handleRequest = async (
    request: IncomingMessage | Http2ServerRequest,
    response: FixtureResponse,
  ): Promise<void> => {
    const parsed = new URL(request.url ?? "/", "https://fixture.invalid");
    const route = classifyRoute(parsed.pathname);
    const protocol = request.httpVersionMajor >= 2 ? "h2" : "http/1.1";
    const authorityValue = request.headers[":authority"] ?? request.headers.host ?? "";
    const authority = Array.isArray(authorityValue) ? (authorityValue[0] ?? "") : authorityValue;
    const authorityMatches =
      expectedAuthorityDigest === undefined
        ? null
        : compareCredential(authority, expectedAuthorityDigest, comparisonKey);
    let credentialName: "authorization" | "x-api-key" | null = null;
    let expectedDigest: Buffer | undefined;
    if (
      route === "header-protected" ||
      route === "client-ok" ||
      route === "client-wheel" ||
      route === "client-npm" ||
      route === "client-git"
    ) {
      credentialName = "authorization";
      expectedDigest = expectedDigests.bearer;
    } else if (route === "api-key-protected") {
      credentialName = "x-api-key";
      expectedDigest = expectedDigests.apiKey;
    } else if (route === "basic-protected") {
      credentialName = "authorization";
      expectedDigest = expectedDigests.basic;
    }
    const rawCredential = credentialName === null ? undefined : request.headers[credentialName];
    const credential = Array.isArray(rawCredential) ? rawCredential[0] : rawCredential;
    const credentialMatches =
      expectedDigest === undefined ? null : compareCredential(credential, expectedDigest, comparisonKey);
    if (
      !record({
        kind: "http",
        protocol,
        route,
        method: new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]).has(request.method ?? "")
          ? (request.method ?? "UNKNOWN")
          : "OTHER",
        authority_present: authority.length > 0,
        authority_matches: authorityMatches,
        credential_present: credential !== undefined,
        credential_matches: credentialMatches,
      })
    ) {
      response.writeHead(503, { "content-type": "text/plain" });
      response.end("fixture observation capacity exceeded");
      return;
    }

    if (credentialName !== null && !credentialMatches) {
      response.writeHead(401, { "content-type": "text/plain" });
      response.end("credential rejected");
      return;
    }
    switch (route) {
      case "health":
      case "header-protected":
      case "api-key-protected":
      case "basic-protected":
      case "client-ok":
        response.writeHead(200, { "content-type": "text/plain" });
        response.end("ok");
        return;
      case "client-wheel":
        response.writeHead(200, {
          "content-type": "application/octet-stream",
          "content-length": clientWheel.length,
        });
        response.end(clientWheel);
        return;
      case "client-npm":
        response.writeHead(200, {
          "content-type": "application/octet-stream",
          "content-length": clientNpmTarball.length,
        });
        response.end(clientNpmTarball);
        return;
      case "client-git":
        response.writeHead(200, {
          "content-type": "application/x-git-upload-pack-advertisement",
          "content-length": gitAdvertisement.length,
          "cache-control": "no-store",
        });
        response.end(gitAdvertisement);
        return;
      case "redirect":
        response.writeHead(302, { location: redirect.href, "content-type": "text/plain" });
        response.end("redirect");
        return;
      case "large": {
        response.writeHead(200, { "content-type": "application/octet-stream", "content-length": largeResponseBytes });
        const chunk = Buffer.alloc(Math.min(64 * 1024, largeResponseBytes), 0x61);
        let remaining = largeResponseBytes;
        while (remaining > 0 && !response.destroyed) {
          await writeChunk(response, remaining >= chunk.length ? chunk : chunk.subarray(0, remaining));
          remaining -= Math.min(remaining, chunk.length);
        }
        response.end();
        return;
      }
      case "stream":
        response.writeHead(200, { "content-type": "application/octet-stream" });
        for (let index = 0; index < streamChunks && !response.destroyed; index += 1) {
          await writeChunk(response, Buffer.from(`chunk-${index}\n`));
          if (index + 1 < streamChunks) await delay(streamIntervalMs, undefined, { signal: lifecycle.signal });
        }
        response.end();
        return;
      case "delayed":
        await delay(delayedResponseMs, undefined, { signal: lifecycle.signal });
        if (!response.destroyed) {
          response.writeHead(200, { "content-type": "text/plain" });
          response.end("delayed");
        }
        return;
      case "unknown":
        response.writeHead(404, { "content-type": "text/plain" });
        response.end("not found");
    }
  };

  tls.on("request", (request, response) => {
    const fixtureResponse = response as FixtureResponse;
    if (activeRequests >= maxConcurrentRequests) {
      fixtureResponse.writeHead(503, { "content-type": "text/plain" });
      fixtureResponse.end("fixture concurrency limit exceeded");
      return;
    }
    activeRequests += 1;
    void handleRequest(request, fixtureResponse)
      .catch(() => {
        if (!lifecycle.signal.aborted) {
          if (!fixtureResponse.headersSent) fixtureResponse.writeHead(500, { "content-type": "text/plain" });
          fixtureResponse.end("fixture error");
        }
      })
      .finally(() => {
        activeRequests -= 1;
      });
  });

  const tcp = createServer((socket) => {
    tcpReached = true;
    socket.destroy();
  });
  tcp.maxConnections = maxConcurrentRequests;
  const udp = createSocket("udp4");
  udp.on("message", () => {
    udpReached = true;
  });

  try {
    const [tlsPort, tcpSensorPort, udpSensorPort] = await Promise.all([listen(tls), listen(tcp), listenUdp(udp)]);
    return {
      tlsOrigin: `https://127.0.0.1:${tlsPort}`,
      tcpSensorPort,
      udpSensorPort,
      caCertificatePem: certificates.ca.toString("utf8"),
      observations: () =>
        Object.freeze([
          ...recorded.map((observation) => structuredClone(observation)),
          ...(tcpReached ? ([{ kind: "tcp-reached" }] as const) : []),
          ...(udpReached ? ([{ kind: "udp-reached" }] as const) : []),
        ]),
      stop: async () => {
        stopPromise ??= (async () => {
          lifecycle.abort();
          for (const socket of sockets) socket.destroy();
          try {
            await closeWithin(Promise.all([closeTcp(tls), closeTcp(tcp), closeUdp(udp)]).then(() => undefined));
          } finally {
            comparisonKey.fill(0);
            for (const digest of Object.values(expectedDigests)) digest.fill(0);
            expectedAuthorityDigest?.fill(0);
          }
        })();
        await stopPromise;
      },
    };
  } catch (error) {
    for (const socket of sockets) socket.destroy();
    try {
      tls.close();
    } catch {}
    try {
      tcp.close();
    } catch {}
    try {
      udp.close();
    } catch {}
    lifecycle.abort();
    comparisonKey.fill(0);
    for (const digest of Object.values(expectedDigests)) digest.fill(0);
    expectedAuthorityDigest?.fill(0);
    throw error;
  }
}

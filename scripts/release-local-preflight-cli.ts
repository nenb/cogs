import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  createReadStream,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import {
  canonicalReleaseLocalBytes,
  createReleaseLocalLedger,
  inspectTrivyDatabaseMetadata,
  RELEASE_LOCAL_PREFLIGHT_LIMITS,
  RELEASE_LOCAL_TRIVY,
  type ReleaseLocalDatabaseObservation,
  type ReleaseLocalInputIdentity,
  type ReleaseLocalJson,
  type ReleaseLocalRole,
} from "./release-local-preflight.ts";

const MAX_COMMAND_OUTPUT = 8 * 1024 * 1024;
const MAX_COMMAND_ERROR = 1024 * 1024;
const MAX_LAYOUT_FILES = 4096;
const MAX_LAYOUT_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_LAYOUT_BLOB = 2 * 1024 * 1024 * 1024;
const MAX_JSON_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = MAX_LAYOUT_BYTES + 64 * 1024 * 1024;
const MAX_LEDGER_BYTES = 512 * 1024 * 1024;
const MAX_RESULT_BYTES = 8 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 30 * 60 * 1000;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const IMAGE_REFERENCE = /^[a-z0-9][a-z0-9._:/-]{0,511}@sha256:[0-9a-f]{64}$/u;
const OCI_INDEX = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json";
const CONFIG_TYPES = new Set([
  "application/vnd.oci.image.config.v1+json",
  "application/vnd.docker.container.image.v1+json",
]);
const LAYER_TYPES = new Set([
  "application/vnd.oci.image.layer.v1.tar",
  "application/vnd.oci.image.layer.v1.tar+gzip",
  "application/vnd.oci.image.layer.v1.tar+zstd",
  "application/vnd.docker.image.rootfs.diff.tar",
  "application/vnd.docker.image.rootfs.diff.tar.gzip",
]);

type Input = Readonly<
  | { role: ReleaseLocalRole; kind: "docker-image"; reference: string; identity: ReleaseLocalInputIdentity }
  | {
      role: ReleaseLocalRole;
      kind: "oci-layout";
      root: string;
      identity: ReleaseLocalInputIdentity;
      archive: string | null;
    }
>;

type Descriptor = Readonly<{ mediaType: string; digest: string; size: number }>;

class PreflightFailure extends Error {
  constructor(
    readonly reasonCode:
      | "ARGUMENT_CONTRACT_VIOLATION"
      | "OUTPUT_CONTRACT_VIOLATION"
      | "INPUT_CONTRACT_VIOLATION"
      | "TOOL_IDENTITY_UNAVAILABLE"
      | "DATABASE_ACQUISITION_FAILED"
      | "DATABASE_EXPIRED"
      | "SCAN_EXECUTION_FAILED"
      | "REPORT_CONTRACT_VIOLATION"
      | "CLEANUP_FAILED",
    message: string,
  ) {
    super(message);
  }
}

function usage(): never {
  throw new PreflightFailure(
    "ARGUMENT_CONTRACT_VIOLATION",
    "usage: release-local-preflight-cli.ts scan --worker <docker-image:repo@sha256:...|oci-layout:/absolute/path> --sandbox <...> --output /new/private/directory",
  );
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}: object required`);
  return value as Record<string, unknown>;
}

function exactImageReference(value: string): string {
  if (!IMAGE_REFERENCE.test(value) || value.split("@").length !== 2) {
    throw new PreflightFailure("INPUT_CONTRACT_VIOLATION", "docker image input must be an exact digest reference");
  }
  const repository = value.slice(0, value.indexOf("@"));
  if (basename(repository).includes(":")) {
    throw new PreflightFailure("INPUT_CONTRACT_VIOLATION", "tag-qualified image input is forbidden");
  }
  return value;
}

function stableBytes(path: string, maximum: number): Buffer {
  const state = lstatSync(path);
  if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1 || state.size < 1 || state.size > maximum) {
    throw new Error("bounded regular single-linked file required");
  }
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) {
      throw new Error("file identity drift");
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function json(path: string, maximum = MAX_JSON_BYTES): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(stableBytes(path, maximum)));
  } catch {
    throw new Error("invalid bounded UTF-8 JSON");
  }
  return asObject(parsed, "JSON");
}

function parseDescriptor(value: unknown, label: string): Descriptor {
  const object = asObject(value, label);
  if (
    typeof object.mediaType !== "string" ||
    typeof object.digest !== "string" ||
    !DIGEST.test(object.digest) ||
    !Number.isSafeInteger(object.size) ||
    (object.size as number) < 1 ||
    (object.size as number) > MAX_LAYOUT_BLOB
  ) {
    throw new Error(`${label}: invalid descriptor`);
  }
  return { mediaType: object.mediaType, digest: object.digest, size: object.size as number };
}

function blobPath(root: string, digest: string): string {
  return resolve(root, "blobs", "sha256", digest.slice(7));
}

function hashStableFile(path: string, expectedSize: number): string {
  const pathState = lstatSync(path);
  if (
    !pathState.isFile() ||
    pathState.isSymbolicLink() ||
    pathState.nlink !== 1 ||
    pathState.size !== expectedSize ||
    pathState.size > MAX_LAYOUT_BLOB
  ) {
    throw new Error("OCI blob filesystem contract violation");
  }
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    for (;;) {
      const length = readSync(descriptor, buffer, 0, buffer.length, null);
      if (length === 0) break;
      hash.update(buffer.subarray(0, length));
      total += length;
      if (total > expectedSize) throw new Error("OCI blob grew while hashing");
    }
    const after = fstatSync(descriptor);
    if (total !== expectedSize || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) {
      throw new Error("OCI blob identity drift");
    }
    return hash.digest("hex");
  } finally {
    closeSync(descriptor);
  }
}

function verifiedJsonBlob(root: string, descriptor: Descriptor): Record<string, unknown> {
  if (descriptor.size > MAX_JSON_BYTES) throw new Error("OCI JSON blob bound exceeded");
  const path = blobPath(root, descriptor.digest);
  if (hashStableFile(path, descriptor.size) !== descriptor.digest.slice(7)) throw new Error("OCI blob digest mismatch");
  return json(path);
}

function inventoryLayout(root: string): Readonly<{ files: Set<string>; bytes: number }> {
  const rootState = lstatSync(root);
  if (!rootState.isDirectory() || rootState.isSymbolicLink()) throw new Error("OCI root must be a real directory");
  const files = new Set<string>();
  let bytes = 0;
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      if (name === "." || name === ".." || name.includes("/") || name.includes("\\")) {
        throw new Error("unsafe OCI entry name");
      }
      const path = resolve(directory, name);
      const state = lstatSync(path);
      if (state.isSymbolicLink()) throw new Error("OCI symlink forbidden");
      if (state.isDirectory()) {
        visit(path);
      } else {
        if (!state.isFile() || state.nlink !== 1 || state.size < 1 || state.size > MAX_LAYOUT_BLOB) {
          throw new Error("invalid OCI file");
        }
        const selected = relative(root, path).split(sep).join("/");
        if (selected.startsWith("../") || isAbsolute(selected)) throw new Error("OCI path escape");
        files.add(selected);
        bytes += state.size;
        if (files.size > MAX_LAYOUT_FILES || bytes > MAX_LAYOUT_BYTES) throw new Error("OCI layout bound exceeded");
      }
    }
  };
  visit(root);
  return { files, bytes };
}

function verifyOciLayout(path: string, role: ReleaseLocalRole): Input {
  try {
    if (!isAbsolute(path) || realpathSync(path) !== path) throw new Error("canonical absolute OCI path required");
    const inventory = inventoryLayout(path);
    const layout = json(resolve(path, "oci-layout"), 1024);
    if (layout.imageLayoutVersion !== "1.0.0") throw new Error("unsupported OCI layout version");
    const indexBytes = stableBytes(resolve(path, "index.json"), MAX_JSON_BYTES);
    const index = JSON.parse(indexBytes.toString("utf8")) as unknown;
    const indexObject = asObject(index, "OCI index");
    if (
      indexObject.schemaVersion !== 2 ||
      (indexObject.mediaType !== undefined && indexObject.mediaType !== OCI_INDEX) ||
      !Array.isArray(indexObject.manifests) ||
      indexObject.manifests.length !== 1
    ) {
      throw new Error("exactly one direct OCI image descriptor required");
    }
    const subjectValue = asObject(indexObject.manifests[0], "OCI subject");
    const subject = parseDescriptor(subjectValue, "OCI subject");
    const platform = asObject(subjectValue.platform, "OCI subject platform");
    if (
      ![OCI_MANIFEST, DOCKER_MANIFEST].includes(subject.mediaType) ||
      platform.os !== "linux" ||
      platform.architecture !== "amd64" ||
      platform.variant !== undefined
    ) {
      throw new Error("direct linux/amd64 OCI image required");
    }
    const manifest = verifiedJsonBlob(path, subject);
    if (manifest.schemaVersion !== 2 || !Array.isArray(manifest.layers)) throw new Error("invalid OCI manifest");
    const config = parseDescriptor(manifest.config, "OCI config");
    if (!CONFIG_TYPES.has(config.mediaType)) throw new Error("unsupported OCI config type");
    const configValue = verifiedJsonBlob(path, config);
    if (configValue.os !== "linux" || configValue.architecture !== "amd64" || configValue.variant !== undefined) {
      throw new Error("OCI config platform mismatch");
    }
    if (manifest.layers.length < 1 || manifest.layers.length > 256) throw new Error("invalid OCI layer count");
    const layers = manifest.layers.map((value, index_) => parseDescriptor(value, `OCI layer ${index_}`));
    for (const layer of layers) {
      if (!LAYER_TYPES.has(layer.mediaType)) throw new Error("unsupported OCI layer type");
      if (hashStableFile(blobPath(path, layer.digest), layer.size) !== layer.digest.slice(7)) {
        throw new Error("OCI layer digest mismatch");
      }
    }
    const reachable = [subject.digest, config.digest, ...layers.map((layer) => layer.digest)];
    if (new Set(reachable).size !== reachable.length) throw new Error("duplicate OCI descriptor digest");
    const expected = new Set([
      "oci-layout",
      "index.json",
      ...reachable.map((digest) => `blobs/sha256/${digest.slice(7)}`),
    ]);
    if (inventory.files.size !== expected.size || [...inventory.files].some((file) => !expected.has(file))) {
      throw new Error("unexpected or unreachable OCI layout content");
    }
    return {
      role,
      kind: "oci-layout",
      root: path,
      archive: null,
      identity: {
        kind: "oci-layout",
        exact_reference: null,
        index_sha256: createHash("sha256").update(indexBytes).digest("hex"),
        subject_manifest_digest: subject.digest,
      },
    };
  } catch (error) {
    throw new PreflightFailure(
      "INPUT_CONTRACT_VIOLATION",
      `${role} OCI layout rejected: ${error instanceof Error ? error.message : "invalid layout"}`,
    );
  }
}

function inputSpec(value: string, role: ReleaseLocalRole): Input {
  if (value.startsWith("docker-image:")) {
    const reference = exactImageReference(value.slice("docker-image:".length));
    return { role, kind: "docker-image", reference, identity: { kind: "docker-image", exact_reference: reference } };
  }
  if (value.startsWith("oci-layout:")) return verifyOciLayout(value.slice("oci-layout:".length), role);
  throw new PreflightFailure("INPUT_CONTRACT_VIOLATION", `${role} input kind is unsupported`);
}

function prepareOutput(path: string): string {
  try {
    if (!isAbsolute(path) || resolve(path) !== path || basename(path).length < 1)
      throw new Error("absolute path required");
    const parent = dirname(path);
    if (realpathSync(parent) !== parent) throw new Error("canonical real parent required");
    mkdirSync(path, { mode: 0o700 });
    const state = lstatSync(path);
    if (!state.isDirectory() || state.isSymbolicLink() || state.uid !== process.getuid?.()) {
      throw new Error("new caller-owned directory required");
    }
    chmodSync(path, 0o700);
    return path;
  } catch (error) {
    throw new PreflightFailure(
      "OUTPUT_CONTRACT_VIOLATION",
      `output directory rejected: ${error instanceof Error ? error.message : "invalid output"}`,
    );
  }
}

function privateOutput(path: string, bytes: Uint8Array, maximum = MAX_LEDGER_BYTES): void {
  if (bytes.byteLength < 1 || bytes.byteLength > maximum) {
    throw new PreflightFailure("OUTPUT_CONTRACT_VIOLATION", "private output size bound exceeded");
  }
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
  chmodSync(path, 0o600);
  const state = lstatSync(path);
  if (
    !state.isFile() ||
    state.isSymbolicLink() ||
    state.nlink !== 1 ||
    state.uid !== process.getuid?.() ||
    (state.mode & 0o777) !== 0o600
  ) {
    throw new PreflightFailure("OUTPUT_CONTRACT_VIOLATION", "private output ownership or mode mismatch");
  }
}

type CommandResult = Readonly<{ stdout: Buffer; stderr: Buffer }>;

function execute(
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  stdinPath?: string,
  maximumOutput = MAX_COMMAND_OUTPUT,
): Promise<CommandResult> {
  return new Promise((fulfill, reject) => {
    const child = spawn(command, [...args], {
      env,
      stdio: [stdinPath === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      shell: false,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let failure: Error | null = null;
    const timer = setTimeout(() => {
      failure = new Error("command timeout");
      child.kill("SIGKILL");
    }, COMMAND_TIMEOUT_MS);
    const childStdout = child.stdout;
    const childStderr = child.stderr;
    const childStdin = child.stdin;
    if (childStdout === null || childStderr === null || (stdinPath !== undefined && childStdin === null)) {
      child.kill("SIGKILL");
      reject(new Error("command pipe contract unavailable"));
      return;
    }
    childStdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maximumOutput) {
        failure = new Error("command output bound exceeded");
        child.kill("SIGKILL");
      } else stdout.push(chunk);
    });
    childStderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_COMMAND_ERROR) {
        failure = new Error("command error-output bound exceeded");
        child.kill("SIGKILL");
      } else stderr.push(chunk);
    });
    child.on("error", (error) => {
      failure = error;
    });
    if (stdinPath !== undefined) {
      const state = lstatSync(stdinPath);
      if (
        !state.isFile() ||
        state.isSymbolicLink() ||
        state.nlink !== 1 ||
        state.size < 1 ||
        state.size > MAX_ARCHIVE_BYTES
      ) {
        failure = new Error("bounded regular command input required");
        child.kill("SIGKILL");
      } else {
        const inputDescriptor = openSync(stdinPath, constants.O_RDONLY | constants.O_NOFOLLOW);
        const stream = createReadStream(stdinPath, { fd: inputDescriptor, autoClose: true });
        stream.on("error", (error) => {
          failure = error;
          child.kill("SIGKILL");
        });
        stream.pipe(childStdin as NodeJS.WritableStream);
      }
    }
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (failure !== null) reject(failure);
      else if (code !== 0 || signal !== null) {
        const diagnostic = Buffer.concat(stderr).toString("utf8").trim().slice(-2000);
        reject(new Error(`command failed (${code ?? signal}): ${diagnostic}`));
      } else fulfill({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    });
  });
}

async function commandHost(): Promise<string> {
  const result = await execute("docker", ["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], process.env);
  const host = result.stdout.toString("utf8").trim();
  if (!host.startsWith("unix://") || host.length > 1024) {
    throw new PreflightFailure("TOOL_IDENTITY_UNAVAILABLE", "a local Unix Docker endpoint is required");
  }
  return host;
}

function dockerEnvironment(host: string, config: string): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: config,
    DOCKER_CONFIG: config,
    DOCKER_HOST: host,
    LC_ALL: "C",
    TZ: "UTC",
  };
}

async function verifyToolAndInputs(inputs: readonly Input[], env: NodeJS.ProcessEnv): Promise<void> {
  try {
    const info = JSON.parse(
      (await execute("docker", ["info", "--format", "{{json .}}"], env)).stdout.toString("utf8"),
    ) as { OSType?: unknown; Architecture?: unknown };
    if (info.OSType !== "linux" || info.Architecture !== "x86_64") throw new Error("linux/x86_64 Docker required");
    const tool = JSON.parse(
      (await execute("docker", ["image", "inspect", RELEASE_LOCAL_TRIVY.image], env)).stdout.toString("utf8"),
    ) as Array<{ RepoDigests?: unknown }>;
    const digest = RELEASE_LOCAL_TRIVY.image.slice(RELEASE_LOCAL_TRIVY.image.indexOf("@"));
    if (
      tool.length !== 1 ||
      !Array.isArray(tool[0]?.RepoDigests) ||
      !(tool[0].RepoDigests as unknown[]).some((value) => typeof value === "string" && value.endsWith(digest))
    ) {
      throw new Error("exact release Trivy image is not already local");
    }
    for (const input of inputs) {
      if (input.kind !== "docker-image") continue;
      const inspected = JSON.parse(
        (await execute("docker", ["image", "inspect", input.reference], env)).stdout.toString("utf8"),
      ) as Array<{ Os?: unknown; Architecture?: unknown; RepoDigests?: unknown }>;
      if (
        inspected.length !== 1 ||
        inspected[0]?.Os !== "linux" ||
        inspected[0]?.Architecture !== "amd64" ||
        !Array.isArray(inspected[0]?.RepoDigests) ||
        !(inspected[0].RepoDigests as unknown[]).includes(input.reference)
      ) {
        throw new Error(`${input.role} exact local linux/amd64 digest is unavailable`);
      }
    }
  } catch (error) {
    throw new PreflightFailure(
      "TOOL_IDENTITY_UNAVAILABLE",
      error instanceof Error ? error.message : "local tool identity unavailable",
    );
  }
}

function dockerRunPrefix(network: "bridge" | "none"): string[] {
  return ["run", "--rm", "--pull", "never", "--network", network];
}

async function databaseMetadata(cacheVolume: string, path: string, env: NodeJS.ProcessEnv, evaluatedAt: Date) {
  const result = await execute(
    "docker",
    [
      ...dockerRunPrefix("none"),
      "--mount",
      `type=volume,src=${cacheVolume},dst=/cache,readonly`,
      "--entrypoint",
      "/bin/cat",
      RELEASE_LOCAL_TRIVY.image,
      path,
    ],
    env,
    undefined,
    64 * 1024,
  );
  return inspectTrivyDatabaseMetadata(Uint8Array.from(result.stdout), evaluatedAt);
}

async function inspectDatabases(
  cacheVolume: string,
  env: NodeJS.ProcessEnv,
  evaluatedAt: Date,
): Promise<ReleaseLocalDatabaseObservation> {
  return {
    vulnerability: await databaseMetadata(cacheVolume, "/cache/db/metadata.json", env, evaluatedAt),
    java: await databaseMetadata(cacheVolume, "/cache/java-db/metadata.json", env, evaluatedAt),
  };
}

async function acquireDatabases(cacheVolume: string, env: NodeJS.ProcessEnv): Promise<void> {
  try {
    await execute(
      "docker",
      [
        ...dockerRunPrefix("bridge"),
        "--mount",
        `type=volume,src=${cacheVolume},dst=/cache`,
        RELEASE_LOCAL_TRIVY.image,
        "image",
        "--cache-dir",
        "/cache",
        "--db-repository",
        RELEASE_LOCAL_TRIVY.database,
        "--download-db-only",
        "--no-progress",
        "--skip-version-check",
      ],
      env,
    );
    await execute(
      "docker",
      [
        ...dockerRunPrefix("bridge"),
        "--mount",
        `type=volume,src=${cacheVolume},dst=/cache`,
        RELEASE_LOCAL_TRIVY.image,
        "image",
        "--cache-dir",
        "/cache",
        "--java-db-repository",
        RELEASE_LOCAL_TRIVY.java_database,
        "--download-java-db-only",
        "--no-progress",
        "--skip-version-check",
      ],
      env,
    );
  } catch (error) {
    throw new PreflightFailure(
      "DATABASE_ACQUISITION_FAILED",
      error instanceof Error ? error.message : "exact database acquisition failed",
    );
  }
}

async function archiveLayout(input: Extract<Input, { kind: "oci-layout" }>, work: string, env: NodeJS.ProcessEnv) {
  const archive = resolve(work, `${input.role}.oci.tar`);
  try {
    await execute("tar", ["-C", input.root, "-cf", archive, "oci-layout", "index.json", "blobs"], env);
    const state = lstatSync(archive);
    if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1 || state.size > MAX_ARCHIVE_BYTES) {
      throw new Error("bounded OCI archive required");
    }
    verifyOciLayout(input.root, input.role);
    return { ...input, archive };
  } catch (error) {
    throw new PreflightFailure(
      "INPUT_CONTRACT_VIOLATION",
      `${input.role} OCI archival failed: ${error instanceof Error ? error.message : "archive failure"}`,
    );
  }
}

async function copyArchiveToVolume(
  input: Extract<Input, { kind: "oci-layout" }> & { archive: string },
  volume: string,
  env: NodeJS.ProcessEnv,
): Promise<void> {
  await execute(
    "docker",
    [
      ...dockerRunPrefix("none"),
      "--mount",
      `type=volume,src=${volume},dst=/input`,
      "--entrypoint",
      "/bin/sh",
      RELEASE_LOCAL_TRIVY.image,
      "-c",
      "umask 077; cat > /input/image.tar",
    ],
    env,
    input.archive,
  );
}

async function scan(
  input: Input,
  outputRoot: string,
  cacheVolume: string,
  inputVolume: string,
  env: NodeJS.ProcessEnv,
): Promise<Readonly<{ raw: Buffer; expectedArtifactName: string }>> {
  const common = [
    "image",
    "--cache-dir",
    "/cache",
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-version-check",
    "--offline-scan",
    "--platform",
    "linux/amd64",
    "--scanners",
    "vuln",
    "--severity",
    "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    "--ignore-unfixed=false",
    "--exit-code",
    "0",
    "--format",
    "json",
    "--list-all-pkgs",
  ];
  const dockerArgs = [
    ...dockerRunPrefix("none"),
    "--workdir",
    "/cogs-empty",
    "--tmpfs",
    "/cogs-empty:rw,noexec,nosuid,size=16777216",
    "--mount",
    `type=volume,src=${cacheVolume},dst=/cache`,
  ];
  let expectedArtifactName: string;
  if (input.kind === "docker-image") {
    dockerArgs.push(
      "--mount",
      "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly",
      RELEASE_LOCAL_TRIVY.image,
      ...common,
      "--image-src",
      "docker",
      input.reference,
    );
    expectedArtifactName = input.reference;
  } else {
    dockerArgs.push(
      "--mount",
      `type=volume,src=${inputVolume},dst=/input,readonly`,
      RELEASE_LOCAL_TRIVY.image,
      ...common,
      "--input",
      "/input/image.tar",
    );
    expectedArtifactName = "/input/image.tar";
  }
  try {
    const result = await execute("docker", dockerArgs, env, undefined, RELEASE_LOCAL_PREFLIGHT_LIMITS.max_report_bytes);
    const raw = result.stdout;
    privateOutput(
      resolve(outputRoot, `${input.role}.trivy.raw.private.json`),
      raw,
      RELEASE_LOCAL_PREFLIGHT_LIMITS.max_report_bytes,
    );
    return { raw, expectedArtifactName };
  } catch (error) {
    throw new PreflightFailure(
      "SCAN_EXECUTION_FAILED",
      `${input.role} scan failed: ${error instanceof Error ? error.message : "scan failure"}`,
    );
  }
}

function failureRecord(reasonCode: string): ReleaseLocalJson {
  return {
    version: "cogs.release-local-preflight-result/v1",
    authority: "bounded-local-trivy-observation",
    completed: false,
    local_policy_gate_passed: false,
    publication_performed: false,
    registry_write_performed: false,
    signing_performed: false,
    workflow_dispatched: false,
    publication_truth_established: false,
    vulnerability_truth_established: false,
    readiness_promoted: false,
    production_ready: false,
    release_eligible: false,
    reason_code: reasonCode,
  };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (
    args.length !== 7 ||
    args[0] !== "scan" ||
    args[1] !== "--worker" ||
    args[3] !== "--sandbox" ||
    args[5] !== "--output" ||
    args[2] === undefined ||
    args[4] === undefined ||
    args[6] === undefined
  ) {
    usage();
  }
  const outputRoot = prepareOutput(args[6]);
  let work: string | null = null;
  let dockerConfig: string | null = null;
  let cacheVolume: string | null = null;
  let inputVolume: string | null = null;
  let env: NodeJS.ProcessEnv | null = null;
  let resultWritten = false;
  try {
    let inputs: Input[] = [inputSpec(args[2], "worker"), inputSpec(args[4], "sandbox")];
    work = mkdtempSync(resolve(tmpdir(), "cogs-release-local-preflight-"));
    chmodSync(work, 0o700);
    dockerConfig = resolve(work, "docker-config");
    mkdirSync(dockerConfig, { mode: 0o700 });
    writeFileSync(resolve(dockerConfig, "config.json"), "{}\n", { mode: 0o600, flag: "wx" });
    const host = await commandHost();
    env = dockerEnvironment(host, dockerConfig);
    await verifyToolAndInputs(inputs, env);
    const cacheVolumeName = `cogs-release-preflight-cache-${randomBytes(12).toString("hex")}`;
    await execute("docker", ["volume", "create", cacheVolumeName], env);
    cacheVolume = cacheVolumeName;
    const inputVolumeName = `cogs-release-preflight-input-${randomBytes(12).toString("hex")}`;
    await execute("docker", ["volume", "create", inputVolumeName], env);
    inputVolume = inputVolumeName;
    await acquireDatabases(cacheVolume, env);
    const initialDatabases = await inspectDatabases(cacheVolume, env, new Date());
    if (!initialDatabases.vulnerability.current || !initialDatabases.java.current) {
      throw new PreflightFailure("DATABASE_EXPIRED", "an exact release database NextUpdate has passed");
    }
    inputs = await Promise.all(
      inputs.map(async (input) =>
        input.kind === "oci-layout" ? archiveLayout(input, work as string, env as NodeJS.ProcessEnv) : input,
      ),
    );
    const scans: Array<Readonly<{ raw: Buffer; expectedArtifactName: string }>> = [];
    for (const input of inputs) {
      if (input.kind === "oci-layout") {
        if (input.archive === null) throw new PreflightFailure("INPUT_CONTRACT_VIOLATION", "OCI archive missing");
        await copyArchiveToVolume(
          input as Extract<Input, { kind: "oci-layout" }> & { archive: string },
          inputVolume,
          env,
        );
      }
      scans.push(await scan(input, outputRoot, cacheVolume, inputVolume, env));
    }
    const databases = await inspectDatabases(cacheVolume, env, new Date());
    const ledgers = inputs.map((input, index) => {
      const scanned = scans[index];
      if (scanned === undefined) throw new Error("scan cardinality drift");
      try {
        return createReleaseLocalLedger(Uint8Array.from(scanned.raw), {
          role: input.role,
          input: input.identity,
          expectedArtifactName: scanned.expectedArtifactName,
          databases,
        });
      } catch (error) {
        throw new PreflightFailure(
          "REPORT_CONTRACT_VIOLATION",
          `${input.role} report rejected: ${error instanceof Error ? error.message : "report drift"}`,
        );
      }
    });
    for (const [index, ledger] of ledgers.entries()) {
      const input = inputs[index];
      if (input === undefined) throw new Error("ledger cardinality drift");
      privateOutput(
        resolve(outputRoot, `${input.role}.vulnerability-ledger.canonical.json`),
        canonicalReleaseLocalBytes(ledger),
      );
    }
    const databaseCurrent = databases.vulnerability.current && databases.java.current;
    const gateCount = ledgers.reduce(
      (total, ledger) => total + ((ledger.gate as Record<string, unknown>).finding_count as number),
      0,
    );
    const passed = databaseCurrent && gateCount === 0;
    const reasonCode = !databaseCurrent
      ? "DATABASE_EXPIRED"
      : passed
        ? "LOCAL_POLICY_GATE_OBSERVED_ZERO"
        : "VULNERABILITY_GATE_BLOCKED";
    const finalResult: ReleaseLocalJson = {
      version: "cogs.release-local-preflight-result/v1",
      authority: "bounded-local-trivy-observation",
      completed: true,
      roles: ledgers.map((ledger, index) => ({
        role: ledger.role as ReleaseLocalJson,
        ledger_sha256: createHash("sha256").update(canonicalReleaseLocalBytes(ledger)).digest("hex"),
        raw_report_sha256: (ledger.report as Record<string, unknown>).sha256 as string,
        gate_finding_count: ((ledger.gate as Record<string, unknown>).finding_count ?? 0) as number,
        reason_code: ledger.reason_code as ReleaseLocalJson,
        input: inputs[index]?.identity as unknown as ReleaseLocalJson,
      })),
      database_current_at_evaluation: databaseCurrent,
      local_policy_gate_passed: passed,
      gate_finding_count: gateCount,
      publication_performed: false,
      registry_write_performed: false,
      signing_performed: false,
      workflow_dispatched: false,
      publication_truth_established: false,
      vulnerability_truth_established: false,
      readiness_promoted: false,
      production_ready: false,
      release_eligible: false,
      reason_code: reasonCode,
    };
    privateOutput(
      resolve(outputRoot, "preflight-result.canonical.json"),
      canonicalReleaseLocalBytes(finalResult),
      MAX_RESULT_BYTES,
    );
    resultWritten = true;
    process.stdout.write(Buffer.from(canonicalReleaseLocalBytes(finalResult)));
    if (!passed) process.exitCode = 1;
  } catch (error) {
    const failure =
      error instanceof PreflightFailure ? error : new PreflightFailure("INPUT_CONTRACT_VIOLATION", "preflight failed");
    if (!resultWritten) {
      try {
        const path = resolve(outputRoot, "preflight-result.canonical.json");
        if (!statSync(path, { throwIfNoEntry: false }))
          privateOutput(path, canonicalReleaseLocalBytes(failureRecord(failure.reasonCode)), MAX_RESULT_BYTES);
      } catch {
        // Preserve the primary reason when even bounded failure recording is impossible.
      }
    }
    process.stderr.write(`${failure.reasonCode}: ${failure.message}\n`);
    process.exitCode = 1;
  } finally {
    let cleanupFailed = false;
    if (env !== null) {
      for (const volume of [inputVolume, cacheVolume]) {
        if (volume === null) continue;
        try {
          await execute("docker", ["volume", "rm", "--force", volume], env);
        } catch {
          cleanupFailed = true;
        }
      }
    }
    if (work !== null) {
      try {
        rmSync(work, { recursive: true, force: true });
      } catch {
        cleanupFailed = true;
      }
    }
    if (cleanupFailed) {
      process.stderr.write("CLEANUP_FAILED: temporary cache or input state may remain\n");
      process.exitCode = 1;
    }
  }
}

try {
  await main();
} catch (error) {
  const failure =
    error instanceof PreflightFailure ? error : new PreflightFailure("ARGUMENT_CONTRACT_VIOLATION", "preflight failed");
  process.stderr.write(`${failure.reasonCode}: ${failure.message}\n`);
  process.exitCode = 1;
}

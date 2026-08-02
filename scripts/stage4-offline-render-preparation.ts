import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";

export const STAGE4_PINNED_NODE = Object.freeze({
  executable: "/Users/nenb/.nvm/versions/node/v22.22.2/bin/node",
  version: "v22.22.2",
  platform: "darwin",
  arch: "arm64",
  sha256: "5c899797c4eb8f1db5563eea56538342ddb3e9276ee1b04a5a1f0f1023d2b011",
} as const);

export const STAGE4_PINNED_HELM = Object.freeze({
  executable: "/opt/homebrew/bin/helm",
  realExecutable: "/opt/homebrew/Cellar/helm/4.1.1/bin/helm",
  version: "v4.1.1+g5caf004",
  sha256: "9f7e2bfe4f0b8d9a746f509645307553fd0ff37cd764b9f91ee8dbe73a7489e4",
} as const);

export const STAGE4_RENDER_PREPARATION_LIMITS = Object.freeze({
  generatorBytes: 128 * 1024,
  helmBytes: 128 * 1024 * 1024,
  inventoryBytes: 64 * 1024,
  valuesBytes: 64 * 1024,
  chartFileBytes: 512 * 1024,
  renderBytes: 256 * 1024,
  stdoutBytes: 512 * 1024,
  stderrBytes: 64 * 1024,
  versionBytes: 4096,
  processTimeoutMs: 20_000,
});

const REVIEW_WRAPPER = `apiVersion: v1
kind: ConfigMap
metadata:
  name: cogs-notes-review-wrapper
data:
  payload: {{ include "cogs.stage4.notes.payload" . | b64enc | quote }}
`;
const RECEIPT_VERSION = "cogs.stage4-offline-render-preparation-receipt/v3";
const EXPECTED_CHART_INVENTORY_SHA256 = "c5a92117c4bf604a188393a4c3cce15fde287f35a0b7c0751fe5f1720b286321";
const EXPECTED_VALUES_SHA256 = "e63a0fadebe16637cc97b21adeeb4ecf33efa8e76a1469e6008c7f7ed4fbb58f";
const EXPECTED_RENDER_SHA256 = "614361336f5cbf87e4fd7b1a8a806fa5d08bbceb3c91b2b33a1710b4cfd73331";
const RELEASE = "stage4";
const NAMESPACE = "static-preparation";
const SHA256 = /^[0-9a-f]{64}$/u;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Inventory = {
  algorithm: "sha256-over-exact-file-bytes";
  chart: "cogs";
  entries: Array<{ path: string; sha256: string }>;
  version: "cogs.stage4-offline-chart-inventory/v1";
};
type AuthenticatedExecutor = Readonly<{
  path: string;
  fileFd: number;
  directoryFd: number;
  fileIdentity: Readonly<{
    device: bigint;
    inode: bigint;
    size: bigint;
    ctimeNs: bigint;
    mtimeNs: bigint;
    mode: bigint;
  }>;
  directoryIdentity: Readonly<{ device: bigint; inode: bigint; ctimeNs: bigint; mtimeNs: bigint; mode: bigint }>;
}>;

function fail(code: string): never {
  throw new Error(code);
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonical(value: Json): Uint8Array {
  function encode(item: Json): string {
    if (Array.isArray(item)) return `[${item.map(encode).join(",")}]`;
    if (item !== null && typeof item === "object") {
      return `{${Object.entries(item)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, child]) => `${JSON.stringify(key)}:${encode(child)}`)
        .join(",")}}`;
    }
    const encoded = JSON.stringify(item);
    if (encoded === undefined) fail("STAGE4_RENDER_PREPARATION_JSON_INVALID");
    return encoded;
  }
  return new TextEncoder().encode(`${encode(value)}\n`);
}

function byteEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) if (left[index] !== right[index]) return false;
  return true;
}

function readDescriptor(
  fd: number,
  maximum: number,
  code: string,
): { bytes: Uint8Array; device: bigint; inode: bigint } {
  const before = fstatSync(fd, { bigint: true });
  if (!before.isFile() || before.size <= 0 || before.size > BigInt(maximum) || before.nlink < 1n) fail(code);
  const bytes = new Uint8Array(readFileSync(fd));
  const after = fstatSync(fd, { bigint: true });
  if (
    BigInt(bytes.byteLength) !== before.size ||
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeNs !== after.mtimeNs ||
    before.ctimeNs !== after.ctimeNs
  )
    fail("STAGE4_RENDER_PREPARATION_FILE_RACE");
  return { bytes, device: before.dev, inode: before.ino };
}

function boundedBytes(path: string, maximum: number): Uint8Array {
  const metadata = lstatSync(path, { bigint: true });
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail("STAGE4_RENDER_PREPARATION_BOUNDED_FILE_INVALID");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const value = readDescriptor(fd, maximum, "STAGE4_RENDER_PREPARATION_BOUNDED_FILE_INVALID");
    if (metadata.dev !== value.device || metadata.ino !== value.inode) fail("STAGE4_RENDER_PREPARATION_FILE_RACE");
    return value.bytes;
  } finally {
    closeSync(fd);
  }
}

function writeExclusive(path: string, bytes: Uint8Array, mode: number): void {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try {
    writeFileSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function walk(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink()) fail("STAGE4_RENDER_PREPARATION_CHART_LINK_FORBIDDEN");
    return metadata.isDirectory() ? walk(path) : [path];
  });
}

function authenticateInventory(
  chartRoot: string,
  inventoryPath: string,
): { inventoryBytes: Uint8Array; files: Map<string, Uint8Array> } {
  const inventoryBytes = boundedBytes(inventoryPath, STAGE4_RENDER_PREPARATION_LIMITS.inventoryBytes);
  let value: Inventory;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(inventoryBytes)) as Inventory;
  } catch {
    fail("STAGE4_RENDER_PREPARATION_INVENTORY_INVALID");
  }
  if (!byteEqual(inventoryBytes, canonical(value as unknown as Json))) {
    fail("STAGE4_RENDER_PREPARATION_INVENTORY_NONCANONICAL");
  }
  if (
    value.version !== "cogs.stage4-offline-chart-inventory/v1" ||
    value.algorithm !== "sha256-over-exact-file-bytes" ||
    value.chart !== "cogs" ||
    !Array.isArray(value.entries) ||
    Reflect.ownKeys(value).length !== 4
  )
    fail("STAGE4_RENDER_PREPARATION_INVENTORY_INVALID");
  const paths = walk(chartRoot)
    .map((path) => relative(chartRoot, path))
    .sort();
  if (value.entries.length !== paths.length) fail("STAGE4_RENDER_PREPARATION_CHART_INVENTORY_DRIFT");
  const files = new Map<string, Uint8Array>();
  for (const [index, path] of paths.entries()) {
    const row = value.entries[index];
    const bytes = boundedBytes(join(chartRoot, path), STAGE4_RENDER_PREPARATION_LIMITS.chartFileBytes);
    if (
      row === undefined ||
      Reflect.ownKeys(row).length !== 2 ||
      row.path !== path ||
      !SHA256.test(row.sha256) ||
      row.sha256 !== sha256(bytes)
    )
      fail("STAGE4_RENDER_PREPARATION_CHART_INVENTORY_DRIFT");
    files.set(path, bytes);
  }
  if (sha256(inventoryBytes) !== EXPECTED_CHART_INVENTORY_SHA256) {
    fail("STAGE4_RENDER_PREPARATION_CHART_INVENTORY_DRIFT");
  }
  return { inventoryBytes, files };
}

function authenticateExecutionLayer(): { generatorSha256: string; nodeSha256: string } {
  if (
    process.execArgv.length !== 0 ||
    process.version !== STAGE4_PINNED_NODE.version ||
    process.platform !== STAGE4_PINNED_NODE.platform ||
    process.arch !== STAGE4_PINNED_NODE.arch ||
    realpathSync(process.execPath) !== STAGE4_PINNED_NODE.executable ||
    realpathSync(process.argv[1] ?? "") !== realpathSync(import.meta.filename)
  )
    fail("STAGE4_RENDER_PREPARATION_EXECUTION_LAYER_INVALID");
  const nodeBytes = boundedBytes(STAGE4_PINNED_NODE.executable, STAGE4_RENDER_PREPARATION_LIMITS.helmBytes);
  if (sha256(nodeBytes) !== STAGE4_PINNED_NODE.sha256) fail("STAGE4_RENDER_PREPARATION_EXECUTION_LAYER_INVALID");
  const generator = boundedBytes(import.meta.filename, STAGE4_RENDER_PREPARATION_LIMITS.generatorBytes);
  return { generatorSha256: sha256(generator), nodeSha256: sha256(nodeBytes) };
}

function materializeAuthenticatedHelm(temporary: string): AuthenticatedExecutor {
  if (realpathSync(STAGE4_PINNED_HELM.executable) !== STAGE4_PINNED_HELM.realExecutable) {
    fail("STAGE4_RENDER_PREPARATION_HELM_PATH_DRIFT");
  }
  const helmBytes = boundedBytes(STAGE4_PINNED_HELM.realExecutable, STAGE4_RENDER_PREPARATION_LIMITS.helmBytes);
  if (sha256(helmBytes) !== STAGE4_PINNED_HELM.sha256) fail("STAGE4_RENDER_PREPARATION_HELM_IDENTITY_INVALID");
  const directory = join(temporary, "authenticated-executor");
  mkdirSync(directory, { mode: 0o700 });
  const path = join(directory, "helm");
  writeExclusive(path, helmBytes, 0o400);
  chmodSync(path, 0o500);
  const copy = boundedBytes(path, STAGE4_RENDER_PREPARATION_LIMITS.helmBytes);
  if (sha256(copy) !== STAGE4_PINNED_HELM.sha256) fail("STAGE4_RENDER_PREPARATION_HELM_COPY_INVALID");
  const fileFd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  const directoryFd = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
  const file = fstatSync(fileFd, { bigint: true });
  const parent = fstatSync(directoryFd, { bigint: true });
  return {
    path,
    fileFd,
    directoryFd,
    fileIdentity: {
      device: file.dev,
      inode: file.ino,
      size: file.size,
      ctimeNs: file.ctimeNs,
      mtimeNs: file.mtimeNs,
      mode: file.mode,
    },
    directoryIdentity: {
      device: parent.dev,
      inode: parent.ino,
      ctimeNs: parent.ctimeNs,
      mtimeNs: parent.mtimeNs,
      mode: parent.mode,
    },
  };
}

function verifyExecutor(executor: AuthenticatedExecutor): void {
  const file = fstatSync(executor.fileFd, { bigint: true });
  const parent = fstatSync(executor.directoryFd, { bigint: true });
  const path = lstatSync(executor.path, { bigint: true });
  const expectedFile = executor.fileIdentity;
  const expectedParent = executor.directoryIdentity;
  if (
    !file.isFile() ||
    !path.isFile() ||
    path.isSymbolicLink() ||
    file.dev !== expectedFile.device ||
    file.ino !== expectedFile.inode ||
    file.size !== expectedFile.size ||
    file.ctimeNs !== expectedFile.ctimeNs ||
    file.mtimeNs !== expectedFile.mtimeNs ||
    file.mode !== expectedFile.mode ||
    file.nlink !== 1n ||
    path.dev !== expectedFile.device ||
    path.ino !== expectedFile.inode ||
    parent.dev !== expectedParent.device ||
    parent.ino !== expectedParent.inode ||
    parent.ctimeNs !== expectedParent.ctimeNs ||
    parent.mtimeNs !== expectedParent.mtimeNs ||
    parent.mode !== expectedParent.mode
  )
    fail("STAGE4_RENDER_PREPARATION_HELM_COPY_INVALID");
}

function authenticateHelmVersion(executor: AuthenticatedExecutor, temporary: string): string {
  verifyExecutor(executor);
  const version = spawnSync(executor.path, ["version", "--short"], {
    encoding: "utf8",
    env: { HOME: temporary, PATH: "/usr/bin:/bin", HELM_DEBUG: "false" },
    timeout: 5_000,
    maxBuffer: STAGE4_RENDER_PREPARATION_LIMITS.versionBytes,
    shell: false,
  });
  if (version.error !== undefined || version.status !== 0 || version.signal !== null || version.stderr !== "") {
    fail("STAGE4_RENDER_PREPARATION_HELM_VERSION_FAILED");
  }
  const normalized = version.stdout.trim();
  if (normalized !== STAGE4_PINNED_HELM.version) fail("STAGE4_RENDER_PREPARATION_HELM_VERSION_DRIFT");
  verifyExecutor(executor);
  return sha256(new TextEncoder().encode(`${normalized}\n`));
}

function materializeInputs(
  temporary: string,
  files: Map<string, Uint8Array>,
  values: Uint8Array,
): { chart: string; values: string } {
  const chart = join(temporary, "cogs");
  mkdirSync(chart, { mode: 0o700 });
  for (const [path, bytes] of files) {
    const components = path.split("/");
    const name = components.pop();
    if (name === undefined || components.some((part) => part === "" || part === "." || part === "..")) {
      fail("STAGE4_RENDER_PREPARATION_CHART_INVENTORY_DRIFT");
    }
    const parent = join(chart, ...components);
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    writeExclusive(join(parent, name), bytes, 0o400);
  }
  const valuesPath = join(temporary, "authenticated-values.yaml");
  writeExclusive(valuesPath, values, 0o400);
  return { chart, values: valuesPath };
}

function runHelm(
  executor: AuthenticatedExecutor,
  arguments_: readonly string[],
  temporary: string,
  code: string,
): { stdout: string; stderr: string } {
  verifyExecutor(executor);
  const helmHome = join(temporary, "helm-home");
  const result = spawnSync(executor.path, arguments_, {
    encoding: "utf8",
    env: {
      HOME: helmHome,
      PATH: "/usr/bin:/bin",
      HELM_CACHE_HOME: join(helmHome, "cache"),
      HELM_CONFIG_HOME: join(helmHome, "config"),
      HELM_DATA_HOME: join(helmHome, "data"),
      HELM_DEBUG: "false",
      KUBECONFIG: join(temporary, "absent-kubeconfig"),
    },
    timeout: STAGE4_RENDER_PREPARATION_LIMITS.processTimeoutMs,
    maxBuffer: STAGE4_RENDER_PREPARATION_LIMITS.stdoutBytes + STAGE4_RENDER_PREPARATION_LIMITS.stderrBytes,
    shell: false,
  });
  if (result.error !== undefined || result.status !== 0 || result.signal !== null) fail(code);
  if (
    Buffer.byteLength(result.stdout) > STAGE4_RENDER_PREPARATION_LIMITS.stdoutBytes ||
    Buffer.byteLength(result.stderr) > STAGE4_RENDER_PREPARATION_LIMITS.stderrBytes
  ) {
    fail("STAGE4_RENDER_PREPARATION_OUTPUT_BOUNDED_IO");
  }
  verifyExecutor(executor);
  return { stdout: result.stdout, stderr: result.stderr };
}

function normalizedHelmOutputSha256(output: string, temporary: string): string {
  return sha256(new TextEncoder().encode(output.split(temporary).join("<PRIVATE_TEMP>")));
}

function authenticateLocalHelmContracts(
  executor: AuthenticatedExecutor,
  chart: string,
  values: string,
  temporary: string,
): { lintOutputSha256: string; zeroManifestOutputSha256: string } {
  const lint = runHelm(
    executor,
    ["lint", chart, "--strict", "-f", values],
    temporary,
    "STAGE4_RENDER_PREPARATION_HELM_LINT_FAILED",
  );
  if (lint.stderr !== "" || !lint.stdout.includes("1 chart(s) linted, 0 chart(s) failed")) {
    fail("STAGE4_RENDER_PREPARATION_HELM_LINT_FAILED");
  }
  const zero = runHelm(
    executor,
    ["template", RELEASE, chart, "--namespace", NAMESPACE, "--dry-run=client", "-f", values],
    temporary,
    "STAGE4_RENDER_PREPARATION_ZERO_MANIFEST_FAILED",
  );
  if (zero.stderr !== "" || zero.stdout.trim() !== "") fail("STAGE4_RENDER_PREPARATION_ZERO_MANIFEST_FAILED");
  return {
    lintOutputSha256: normalizedHelmOutputSha256(lint.stdout, temporary),
    zeroManifestOutputSha256: sha256(new TextEncoder().encode(zero.stdout)),
  };
}

function extractPayload(stdout: string): Uint8Array {
  if (Buffer.byteLength(stdout) > STAGE4_RENDER_PREPARATION_LIMITS.stdoutBytes) {
    fail("STAGE4_RENDER_PREPARATION_OUTPUT_BOUNDED_IO");
  }
  const matches = [...stdout.matchAll(/^ {2}payload: "([A-Za-z0-9+/]*={0,2})"$/gmu)];
  if (matches.length !== 1 || matches[0]?.[1] === undefined) fail("STAGE4_RENDER_PREPARATION_OUTPUT_INVALID");
  const encoded = matches[0][1];
  const payload = Buffer.from(encoded, "base64");
  if (
    payload.toString("base64") !== encoded ||
    payload.byteLength === 0 ||
    payload.byteLength > STAGE4_RENDER_PREPARATION_LIMITS.renderBytes
  ) {
    fail("STAGE4_RENDER_PREPARATION_OUTPUT_INVALID");
  }
  return new Uint8Array(payload.at(-1) === 0x0a ? payload : Buffer.concat([payload, Buffer.from("\n")]));
}

function renderOnce(executor: AuthenticatedExecutor, chart: string, values: string, temporary: string): Uint8Array {
  const result = runHelm(
    executor,
    ["template", RELEASE, chart, "--namespace", NAMESPACE, "--dry-run=client", "--hide-notes=false", "-f", values],
    temporary,
    "STAGE4_RENDER_PREPARATION_HELM_TEMPLATE_FAILED",
  );
  if (result.stderr !== "") fail("STAGE4_RENDER_PREPARATION_HELM_TEMPLATE_FAILED");
  return extractPayload(result.stdout);
}

function run(): Uint8Array {
  if (process.argv.length !== 2) fail("STAGE4_RENDER_PREPARATION_ARGUMENTS_FORBIDDEN");
  const execution = authenticateExecutionLayer();
  const root = resolve(import.meta.dirname, "..");
  const artifactRoot = resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts");
  const chart = authenticateInventory(resolve(root, "deploy/helm/cogs"), resolve(artifactRoot, "chart-inventory.json"));
  const values = boundedBytes(
    resolve(root, "test/fixtures/helm/stage4-notes-source-shapes-valid.yaml"),
    STAGE4_RENDER_PREPARATION_LIMITS.valuesBytes,
  );
  if (sha256(values) !== EXPECTED_VALUES_SHA256) fail("STAGE4_RENDER_PREPARATION_VALUES_DRIFT");
  const committed = boundedBytes(
    resolve(artifactRoot, "notes-render.yaml"),
    STAGE4_RENDER_PREPARATION_LIMITS.renderBytes,
  );
  const repeatedCommitted = boundedBytes(
    resolve(artifactRoot, "notes-render-repeat.yaml"),
    STAGE4_RENDER_PREPARATION_LIMITS.renderBytes,
  );
  if (sha256(committed) !== EXPECTED_RENDER_SHA256 || sha256(repeatedCommitted) !== EXPECTED_RENDER_SHA256) {
    fail("STAGE4_RENDER_PREPARATION_COMMITTED_RENDER_MISMATCH");
  }

  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-render-preparation-"));
  try {
    chmodSync(temporary, 0o700);
    const executor = materializeAuthenticatedHelm(temporary);
    try {
      const inputs = materializeInputs(temporary, chart.files, values);
      const helmVersionSha256 = authenticateHelmVersion(executor, temporary);
      const localContracts = authenticateLocalHelmContracts(executor, inputs.chart, inputs.values, temporary);
      writeExclusive(
        join(inputs.chart, "templates/notes-review.yaml"),
        new TextEncoder().encode(REVIEW_WRAPPER),
        0o400,
      );
      const first = renderOnce(executor, inputs.chart, inputs.values, temporary);
      const repeated = renderOnce(executor, inputs.chart, inputs.values, temporary);
      if (!byteEqual(first, repeated)) fail("STAGE4_RENDER_PREPARATION_NONDETERMINISTIC");
      if (!byteEqual(first, committed) || !byteEqual(repeated, repeatedCommitted)) {
        fail("STAGE4_RENDER_PREPARATION_COMMITTED_RENDER_MISMATCH");
      }
      const executionLayer = {
        generator_source_sha256: execution.generatorSha256,
        node_arch: STAGE4_PINNED_NODE.arch,
        node_executable_sha256: execution.nodeSha256,
        node_platform: STAGE4_PINNED_NODE.platform,
        node_version: STAGE4_PINNED_NODE.version,
        typescript_loader: "none-node-native-strip-types",
      };
      return canonical({
        authority: "trusted-local-static-render-preparation",
        chart_inventory_sha256: sha256(chart.inventoryBytes),
        cloud_execution_observed: false,
        committed_render_match: true,
        execution: "pinned-node-native-typescript-authenticated-helm-copy",
        execution_layer_sha256: sha256(canonical(executionLayer)),
        first_render_sha256: sha256(first),
        generator_source_sha256: execution.generatorSha256,
        helm_executable_sha256: STAGE4_PINNED_HELM.sha256,
        helm_execution_copy_sha256: STAGE4_PINNED_HELM.sha256,
        helm_lint_output_sha256: localContracts.lintOutputSha256,
        helm_lint_passed: true,
        helm_version_sha256: helmVersionSha256,
        kubernetes_execution_observed: false,
        node_arch: STAGE4_PINNED_NODE.arch,
        node_executable_sha256: execution.nodeSha256,
        node_platform: STAGE4_PINNED_NODE.platform,
        node_version: STAGE4_PINNED_NODE.version,
        provider_execution_observed: false,
        renders_byte_identical: true,
        repeated_render_sha256: sha256(repeated),
        trusted_preparation_complete: true,
        typescript_loader: "none-node-native-strip-types",
        values_sha256: sha256(values),
        version: RECEIPT_VERSION,
        wrapper_source_sha256: sha256(new TextEncoder().encode(REVIEW_WRAPPER)),
        zero_manifest_output_sha256: localContracts.zeroManifestOutputSha256,
        zero_submitted_manifests: true,
      });
    } finally {
      closeSync(executor.fileFd);
      closeSync(executor.directoryFd);
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(import.meta.filename)) {
  try {
    process.stdout.write(run());
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "STAGE4_RENDER_PREPARATION_FAILED"}\n`);
    process.exitCode = 1;
  }
}

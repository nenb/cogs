import { spawnSync } from "node:child_process";
import {
  cpSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { canonicalStage4OfflineReadinessBytes, stage4OfflineReadinessSha256 } from "./stage4-offline-readiness.ts";

const require = createRequire(import.meta.url);
const yaml = require("yaml") as { parseAllDocuments(source: string): Array<{ toJSON(): unknown; errors: unknown[] }> };

export const STAGE4_PINNED_HELM = Object.freeze({
  executable: "/opt/homebrew/bin/helm",
  realExecutable: "/opt/homebrew/Cellar/helm/4.1.1/bin/helm",
  version: "v4.1.1+g5caf004",
  sha256: "9f7e2bfe4f0b8d9a746f509645307553fd0ff37cd764b9f91ee8dbe73a7489e4",
} as const);

export const STAGE4_RENDER_PREPARATION_LIMITS = Object.freeze({
  helmBytes: 128 * 1024 * 1024,
  inventoryBytes: 64 * 1024,
  valuesBytes: 64 * 1024,
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
  payload: |-
{{ include "cogs.stage4.notes.payload" . | nindent 4 }}
`;
const RECEIPT_VERSION = "cogs.stage4-offline-render-preparation-receipt/v1";
const EXPECTED_CHART_INVENTORY_SHA256 = "c5a92117c4bf604a188393a4c3cce15fde287f35a0b7c0751fe5f1720b286321";
const EXPECTED_VALUES_SHA256 = "e63a0fadebe16637cc97b21adeeb4ecf33efa8e76a1469e6008c7f7ed4fbb58f";
const EXPECTED_RENDER_SHA256 = "614361336f5cbf87e4fd7b1a8a806fa5d08bbceb3c91b2b33a1710b4cfd73331";
const RELEASE = "stage4";
const NAMESPACE = "static-preparation";

type Inventory = {
  algorithm: "sha256-over-exact-file-bytes";
  chart: "cogs";
  entries: Array<{ path: string; sha256: string }>;
  version: "cogs.stage4-offline-chart-inventory/v1";
};

type RenderReceipt = {
  version: typeof RECEIPT_VERSION;
  authority: "trusted-local-static-render-preparation";
  execution: "local-helm-template-only";
  chart_inventory_sha256: string;
  values_sha256: string;
  helm_executable_sha256: string;
  helm_version_sha256: string;
  generator_source_sha256: string;
  wrapper_source_sha256: string;
  first_render_sha256: string;
  repeated_render_sha256: string;
  renders_byte_identical: true;
  committed_render_match: true;
  trusted_preparation_complete: true;
  cloud_execution_observed: false;
  kubernetes_execution_observed: false;
  provider_execution_observed: false;
};

export type Stage4RenderPreparationResult = Readonly<{
  receipt: Readonly<RenderReceipt>;
  receiptBytes: Uint8Array;
  render: Uint8Array;
  repeatedRender: Uint8Array;
}>;

export type Stage4RenderPreparationPaths = Readonly<{
  chartRoot: string;
  chartInventory: string;
  values: string;
  committedRender: string;
  committedRepeatedRender: string;
  generatorSource: string;
}>;

function fail(code: string): never {
  throw new Error(code);
}

function boundedBytes(path: string, maximum: number): Uint8Array {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size <= 0 || metadata.size > maximum) {
    fail("STAGE4_RENDER_PREPARATION_BOUNDED_FILE_INVALID");
  }
  const bytes = new Uint8Array(readFileSync(path));
  if (bytes.byteLength !== metadata.size) fail("STAGE4_RENDER_PREPARATION_FILE_RACE");
  return bytes;
}

function byteEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) if (left[index] !== right[index]) return false;
  return true;
}

function walk(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink()) fail("STAGE4_RENDER_PREPARATION_CHART_LINK_FORBIDDEN");
    return metadata.isDirectory() ? walk(path) : [path];
  });
}

function authenticateInventory(chartRoot: string, inventoryPath: string): { bytes: Uint8Array; value: Inventory } {
  const bytes = boundedBytes(inventoryPath, STAGE4_RENDER_PREPARATION_LIMITS.inventoryBytes);
  let value: Inventory;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as Inventory;
  } catch {
    fail("STAGE4_RENDER_PREPARATION_INVENTORY_INVALID");
  }
  if (!byteEqual(bytes, canonicalStage4OfflineReadinessBytes(value as never))) {
    fail("STAGE4_RENDER_PREPARATION_INVENTORY_NONCANONICAL");
  }
  if (
    value.version !== "cogs.stage4-offline-chart-inventory/v1" ||
    value.algorithm !== "sha256-over-exact-file-bytes" ||
    value.chart !== "cogs" ||
    !Array.isArray(value.entries)
  )
    fail("STAGE4_RENDER_PREPARATION_INVENTORY_INVALID");
  const paths = walk(chartRoot)
    .map((path) => relative(chartRoot, path))
    .sort();
  if (value.entries.length !== paths.length) fail("STAGE4_RENDER_PREPARATION_CHART_INVENTORY_DRIFT");
  for (const [index, path] of paths.entries()) {
    const row = value.entries[index];
    if (
      row?.path !== path ||
      row.sha256 !== stage4OfflineReadinessSha256(boundedBytes(join(chartRoot, path), 512 * 1024))
    ) {
      fail("STAGE4_RENDER_PREPARATION_CHART_INVENTORY_DRIFT");
    }
  }
  if (stage4OfflineReadinessSha256(bytes) !== EXPECTED_CHART_INVENTORY_SHA256) {
    fail("STAGE4_RENDER_PREPARATION_CHART_INVENTORY_DRIFT");
  }
  return { bytes, value };
}

function authenticateHelm(): { executable: string; versionSha256: string } {
  if (realpathSync(STAGE4_PINNED_HELM.executable) !== STAGE4_PINNED_HELM.realExecutable) {
    fail("STAGE4_RENDER_PREPARATION_HELM_PATH_DRIFT");
  }
  const metadata = statSync(STAGE4_PINNED_HELM.realExecutable);
  if (!metadata.isFile() || metadata.size <= 0 || metadata.size > STAGE4_RENDER_PREPARATION_LIMITS.helmBytes) {
    fail("STAGE4_RENDER_PREPARATION_HELM_IDENTITY_INVALID");
  }
  const digest = stage4OfflineReadinessSha256(new Uint8Array(readFileSync(STAGE4_PINNED_HELM.realExecutable)));
  if (digest !== STAGE4_PINNED_HELM.sha256) fail("STAGE4_RENDER_PREPARATION_HELM_IDENTITY_INVALID");
  const version = spawnSync(STAGE4_PINNED_HELM.realExecutable, ["version", "--short"], {
    encoding: "utf8",
    env: { HOME: tmpdir(), PATH: "/usr/bin:/bin", HELM_DEBUG: "false" },
    timeout: 5_000,
    maxBuffer: STAGE4_RENDER_PREPARATION_LIMITS.versionBytes,
    shell: false,
  });
  if (version.error !== undefined || version.status !== 0 || version.stderr !== "") {
    fail("STAGE4_RENDER_PREPARATION_HELM_VERSION_FAILED");
  }
  const normalized = version.stdout.trim();
  if (normalized !== STAGE4_PINNED_HELM.version) fail("STAGE4_RENDER_PREPARATION_HELM_VERSION_DRIFT");
  return {
    executable: STAGE4_PINNED_HELM.realExecutable,
    versionSha256: stage4OfflineReadinessSha256(new TextEncoder().encode(`${normalized}\n`)),
  };
}

function extractPayload(stdout: string): Uint8Array {
  const documents = yaml.parseAllDocuments(stdout);
  if (documents.length !== 1 || documents[0]?.errors.length !== 0) fail("STAGE4_RENDER_PREPARATION_OUTPUT_INVALID");
  const wrapper = documents[0]?.toJSON() as { metadata?: { name?: unknown }; data?: { payload?: unknown } } | undefined;
  if (wrapper?.metadata?.name !== "cogs-notes-review-wrapper" || typeof wrapper.data?.payload !== "string") {
    fail("STAGE4_RENDER_PREPARATION_OUTPUT_INVALID");
  }
  const bytes = new TextEncoder().encode(`${wrapper.data.payload.trim()}\n`);
  if (bytes.byteLength === 0 || bytes.byteLength > STAGE4_RENDER_PREPARATION_LIMITS.renderBytes) {
    fail("STAGE4_RENDER_PREPARATION_OUTPUT_BOUNDED_IO");
  }
  return bytes;
}

function renderOnce(chartRoot: string, valuesPath: string, helmExecutable: string): Uint8Array {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-render-preparation-"));
  try {
    const chart = join(temporary, "cogs");
    cpSync(chartRoot, chart, { recursive: true, dereference: false, errorOnExist: true });
    writeFileSync(join(chart, "templates/notes-review.yaml"), REVIEW_WRAPPER, { mode: 0o600, flag: "wx" });
    const helmHome = join(temporary, "helm-home");
    const result = spawnSync(
      helmExecutable,
      [
        "template",
        RELEASE,
        chart,
        "--namespace",
        NAMESPACE,
        "--dry-run=client",
        "--hide-notes=false",
        "-f",
        valuesPath,
      ],
      {
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
      },
    );
    if (result.error !== undefined || result.status !== 0 || result.signal !== null || result.stderr !== "") {
      fail("STAGE4_RENDER_PREPARATION_HELM_TEMPLATE_FAILED");
    }
    if (Buffer.byteLength(result.stdout) > STAGE4_RENDER_PREPARATION_LIMITS.stdoutBytes) {
      fail("STAGE4_RENDER_PREPARATION_OUTPUT_BOUNDED_IO");
    }
    return extractPayload(result.stdout);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

export function prepareAndVerifyStage4OfflineRender(
  paths: Stage4RenderPreparationPaths,
): Stage4RenderPreparationResult {
  const chartRoot = realpathSync(paths.chartRoot);
  const inventory = authenticateInventory(chartRoot, paths.chartInventory);
  const values = boundedBytes(paths.values, STAGE4_RENDER_PREPARATION_LIMITS.valuesBytes);
  if (stage4OfflineReadinessSha256(values) !== EXPECTED_VALUES_SHA256) {
    fail("STAGE4_RENDER_PREPARATION_VALUES_DRIFT");
  }
  const committed = boundedBytes(paths.committedRender, STAGE4_RENDER_PREPARATION_LIMITS.renderBytes);
  const committedRepeated = boundedBytes(paths.committedRepeatedRender, STAGE4_RENDER_PREPARATION_LIMITS.renderBytes);
  if (
    stage4OfflineReadinessSha256(committed) !== EXPECTED_RENDER_SHA256 ||
    stage4OfflineReadinessSha256(committedRepeated) !== EXPECTED_RENDER_SHA256
  )
    fail("STAGE4_RENDER_PREPARATION_COMMITTED_RENDER_MISMATCH");
  const generator = boundedBytes(paths.generatorSource, 128 * 1024);
  const helm = authenticateHelm();
  const render = renderOnce(chartRoot, realpathSync(paths.values), helm.executable);
  const repeatedRender = renderOnce(chartRoot, realpathSync(paths.values), helm.executable);
  if (!byteEqual(render, repeatedRender)) fail("STAGE4_RENDER_PREPARATION_NONDETERMINISTIC");
  if (!byteEqual(render, committed) || !byteEqual(repeatedRender, committedRepeated)) {
    fail("STAGE4_RENDER_PREPARATION_COMMITTED_RENDER_MISMATCH");
  }
  const receipt: RenderReceipt = {
    version: RECEIPT_VERSION,
    authority: "trusted-local-static-render-preparation",
    execution: "local-helm-template-only",
    chart_inventory_sha256: stage4OfflineReadinessSha256(inventory.bytes),
    values_sha256: stage4OfflineReadinessSha256(values),
    helm_executable_sha256: STAGE4_PINNED_HELM.sha256,
    helm_version_sha256: helm.versionSha256,
    generator_source_sha256: stage4OfflineReadinessSha256(generator),
    wrapper_source_sha256: stage4OfflineReadinessSha256(new TextEncoder().encode(REVIEW_WRAPPER)),
    first_render_sha256: stage4OfflineReadinessSha256(render),
    repeated_render_sha256: stage4OfflineReadinessSha256(repeatedRender),
    renders_byte_identical: true,
    committed_render_match: true,
    trusted_preparation_complete: true,
    cloud_execution_observed: false,
    kubernetes_execution_observed: false,
    provider_execution_observed: false,
  };
  const receiptBytes = canonicalStage4OfflineReadinessBytes(receipt as never);
  return Object.freeze({ receipt: Object.freeze(receipt), receiptBytes, render, repeatedRender });
}

export function defaultStage4RenderPreparationPaths(root: string): Stage4RenderPreparationPaths {
  return Object.freeze({
    chartRoot: resolve(root, "deploy/helm/cogs"),
    chartInventory: resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts/chart-inventory.json"),
    values: resolve(root, "test/fixtures/helm/stage4-notes-source-shapes-valid.yaml"),
    committedRender: resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts/notes-render.yaml"),
    committedRepeatedRender: resolve(
      root,
      "docs/security-evidence/stage4-offline-readiness-artifacts/notes-render-repeat.yaml",
    ),
    generatorSource: resolve(root, "scripts/stage4-offline-render-preparation.ts"),
  });
}

if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(import.meta.filename)) {
  if (process.argv.length !== 2) fail("STAGE4_RENDER_PREPARATION_ARGUMENTS_FORBIDDEN");
  process.stdout.write(
    prepareAndVerifyStage4OfflineRender(defaultStage4RenderPreparationPaths(resolve(import.meta.dirname, "..")))
      .receiptBytes,
  );
}

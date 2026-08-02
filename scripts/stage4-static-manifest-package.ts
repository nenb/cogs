import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const requestSchema = require("../schemas/stage4-static-manifest-request-v1.json") as object;
const validateRequest = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  ownProperties: true,
}).compile(requestSchema) as ValidateFunction;

export const STAGE4_STATIC_MANIFEST_HELM = Object.freeze({
  executable: "/opt/homebrew/Cellar/helm/4.1.1/bin/helm",
  sha256: "9f7e2bfe4f0b8d9a746f509645307553fd0ff37cd764b9f91ee8dbe73a7489e4",
  version: "v4.1.1+g5caf004",
});
export const STAGE4_STATIC_MANIFEST_INPUTS = Object.freeze({
  chartInventorySha256: "a3801a32d9f1a59864bd027aebf44554b087911c7d4a4486e7bcda697ff68617",
  nicContractSha256: "b9f50811706846373f1519bab10af0abf44df1c9957b713cb494cde55c724743",
});

const LIMITS = Object.freeze({
  request: 128 * 1024,
  chartFile: 512 * 1024,
  helm: 128 * 1024 * 1024,
  output: 512 * 1024,
});
const REVIEW_WRAPPER = `apiVersion: v1
kind: ConfigMap
metadata:
  name: cogs-static-manifest-review-wrapper
data:
  payload: {{ include "cogs.stage4.notes.payload" . | b64enc | quote }}
`;
const SHA = /^[0-9a-f]{64}$/u;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Request = {
  version: "cogs.stage4-static-manifest-request/v1";
  authority: "local-static-manifest-request-only";
  release_name: string;
  namespace: string;
  values: Record<string, Json>;
  nic: {
    node_group_name: "cogs-stage4-sandbox-kata";
    external_launch_template: {
      id: string;
      version: number;
      operator_review: { cpu_options: { nested_virtualization: "enabled"; core_count: 1; threads_per_core: 2 } };
    };
  };
};

type Inventory = {
  version: "cogs.stage4-offline-chart-inventory/v1";
  algorithm: "sha256-over-exact-file-bytes";
  chart: "cogs";
  entries: Array<{ path: string; sha256: string }>;
};

function fail(code: string): never {
  throw new Error(code);
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function compare(left: string, right: string): number {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return Buffer.compare(a, b);
}

function canonical(value: Json): Buffer {
  const encode = (item: Json): string => {
    if (Array.isArray(item)) return `[${item.map(encode).join(",")}]`;
    if (item !== null && typeof item === "object") {
      return `{${Object.entries(item)
        .sort(([left], [right]) => compare(left, right))
        .map(([key, nested]) => `${JSON.stringify(key)}:${encode(nested)}`)
        .join(",")}}`;
    }
    return JSON.stringify(item);
  };
  return Buffer.from(`${encode(value)}\n`, "utf8");
}

function boundedRegular(path: string, maximum: number): Buffer {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximum))
    fail("STAGE4_MANIFEST_INPUT_INVALID");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size)
      fail("STAGE4_MANIFEST_INPUT_RACE");
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      pathAfter.dev !== opened.dev ||
      pathAfter.ino !== opened.ino ||
      pathAfter.size !== opened.size
    )
      fail("STAGE4_MANIFEST_INPUT_RACE");
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function parseRequest(path: string): { request: Request; bytes: Buffer } {
  const bytes = boundedRegular(path, LIMITS.request);
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("STAGE4_MANIFEST_REQUEST_INVALID");
  }
  if (!validateRequest(value)) fail("STAGE4_MANIFEST_REQUEST_INVALID");
  const normalized = canonical(value as Json);
  if (!bytes.equals(normalized)) fail("STAGE4_MANIFEST_REQUEST_NONCANONICAL");
  return { request: value as Request, bytes };
}

function authenticateChart(root: string, inventoryPath: string, destination: string): Buffer {
  const inventoryBytes = boundedRegular(inventoryPath, LIMITS.request);
  if (sha256(inventoryBytes) !== STAGE4_STATIC_MANIFEST_INPUTS.chartInventorySha256)
    fail("STAGE4_MANIFEST_CHART_INVENTORY_DRIFT");
  let inventory: Inventory;
  try {
    inventory = JSON.parse(inventoryBytes.toString("utf8")) as Inventory;
  } catch {
    fail("STAGE4_MANIFEST_CHART_INVENTORY_INVALID");
  }
  if (
    inventory.version !== "cogs.stage4-offline-chart-inventory/v1" ||
    inventory.algorithm !== "sha256-over-exact-file-bytes" ||
    inventory.chart !== "cogs" ||
    !Array.isArray(inventory.entries) ||
    inventory.entries.length < 2 ||
    inventory.entries.length > 32
  )
    fail("STAGE4_MANIFEST_CHART_INVENTORY_INVALID");
  const paths = inventory.entries.map((entry) => entry.path);
  if ([...paths].sort(compare).some((path, index) => path !== paths[index]) || new Set(paths).size !== paths.length)
    fail("STAGE4_MANIFEST_CHART_INVENTORY_INVALID");
  mkdirSync(destination, { mode: 0o700 });
  for (const entry of inventory.entries) {
    if (
      !entry.path ||
      entry.path.startsWith("/") ||
      entry.path.split("/").some((part) => part === "" || part === "." || part === "..") ||
      !SHA.test(entry.sha256)
    )
      fail("STAGE4_MANIFEST_CHART_INVENTORY_INVALID");
    const source = join(root, entry.path);
    const bytes = boundedRegular(source, LIMITS.chartFile);
    if (sha256(bytes) !== entry.sha256) fail("STAGE4_MANIFEST_CHART_DRIFT");
    const target = join(destination, entry.path);
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    writeFileSync(target, bytes, { flag: "wx", mode: 0o400 });
  }
  return inventoryBytes;
}

function runHelm(helm: string, args: string[], temporary: string): string {
  const home = join(temporary, "helm-home");
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const result = spawnSync(helm, args, {
    cwd: temporary,
    encoding: "utf8",
    timeout: 20_000,
    maxBuffer: LIMITS.output,
    env: {
      HOME: home,
      HELM_CACHE_HOME: join(home, "cache"),
      HELM_CONFIG_HOME: join(home, "config"),
      HELM_DATA_HOME: join(home, "data"),
      KUBECONFIG: join(temporary, "absent-kubeconfig"),
      PATH: "/usr/bin:/bin",
    },
  });
  if (result.error !== undefined || result.status !== 0 || result.signal !== null || result.stderr !== "")
    fail("STAGE4_MANIFEST_HELM_FAILED");
  return result.stdout;
}

function expectedInventory(release: string): string[] {
  const prefix = release === "cogs" ? "cogs" : `${release}-cogs`;
  return [
    `ConfigMap/${prefix}-contract`,
    `ServiceAccount/${prefix}-trusted`,
    "ServiceAccount/cogs-sandbox-inert",
    `Service/${prefix}-proxy`,
    `NetworkPolicy/${prefix}-default-deny`,
    `NetworkPolicy/${prefix}-trusted-allow`,
    `NetworkPolicy/${prefix}-sandbox-allow`,
    `PodTemplate/${prefix}-trusted-template`,
    `PodTemplate/${prefix}-sandbox-template`,
  ];
}

function extractManifest(stdout: string, release: string): { bytes: Buffer; inventory: string[] } {
  const matches = [...stdout.matchAll(/^ {2}payload: "([A-Za-z0-9+/]*={0,2})"$/gmu)];
  if (matches.length !== 1 || matches[0]?.[1] === undefined) fail("STAGE4_MANIFEST_WRAPPER_INVALID");
  const encoded = matches[0][1];
  const payload = Buffer.from(encoded, "base64");
  if (payload.toString("base64") !== encoded || payload.length < 1 || payload.length > LIMITS.output)
    fail("STAGE4_MANIFEST_WRAPPER_INVALID");
  const bytes = payload.at(-1) === 0x0a ? payload : Buffer.concat([payload, Buffer.from("\n")]);
  const text = bytes.toString("utf8");
  if (
    !text.startsWith("# COGS NOTES-ONLY STATIC SOURCE SHAPES BEGIN: WARNING — UNSAFE TO APPLY; UNQUALIFIED\n") ||
    !text.endsWith("# COGS NOTES-ONLY STATIC SOURCE SHAPES END: WARNING — UNSAFE TO APPLY; UNQUALIFIED\n")
  )
    fail("STAGE4_MANIFEST_WARNING_BOUNDARY_INVALID");
  const inventory = [...text.matchAll(/^kind: ([A-Za-z]+)\nmetadata:\n {2}name: ([a-z0-9-]+)$/gmu)].map(
    (match) => `${match[1]}/${match[2]}`,
  );
  if (JSON.stringify(inventory) !== JSON.stringify(expectedInventory(release)))
    fail("STAGE4_MANIFEST_OBJECT_INVENTORY_INVALID");
  return { bytes, inventory };
}

function nicConfig(request: Request): Buffer {
  const template = request.nic.external_launch_template;
  const quote = (value: string): string => JSON.stringify(value);
  return Buffer.from(
    `# Cogs local/static NIC handoff only. No provider or deployment authority.\ncluster:\n  provider: aws\n  aws:\n    node_groups:\n      ${request.nic.node_group_name}:\n        instance: c8i-flex.large\n        min_nodes: 0\n        max_nodes: 1\n        spot: false\n        external_launch_template:\n          id: ${quote(template.id)}\n          version: ${template.version}\n          operator_review:\n            cpu_options:\n              nested_virtualization: enabled\n        labels:\n          cogs.dev/node-domain: sandbox-kata\n          cogs.dev/nested-virtualization: enabled\n          cogs.dev/sandbox-runtime: kata-qemu-kvm\n        taints:\n          - key: cogs.dev/sandbox\n            value: kata\n            effect: NO_SCHEDULE\n`,
    "utf8",
  );
}

function ensureNewOutput(path: string): string {
  const requested = resolve(path);
  const parent = realpathSync(dirname(requested));
  const output = join(parent, basename(requested));
  mkdirSync(output, { mode: 0o700 });
  if (realpathSync(output) !== output) fail("STAGE4_MANIFEST_OUTPUT_INVALID");
  return output;
}

export function materializeStage4StaticManifestPackage(requestPath: string, outputPath: string): void {
  const { request, bytes: requestBytes } = parseRequest(requestPath);
  const root = resolve(import.meta.dirname, "..");
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-static-manifest-"));
  let output: string | undefined;
  try {
    chmodSync(temporary, 0o700);
    const helmBytes = boundedRegular(STAGE4_STATIC_MANIFEST_HELM.executable, LIMITS.helm);
    if (sha256(helmBytes) !== STAGE4_STATIC_MANIFEST_HELM.sha256) fail("STAGE4_MANIFEST_HELM_IDENTITY_INVALID");
    const version = runHelm(STAGE4_STATIC_MANIFEST_HELM.executable, ["version", "--short"], temporary).trim();
    if (version !== STAGE4_STATIC_MANIFEST_HELM.version) fail("STAGE4_MANIFEST_HELM_IDENTITY_INVALID");

    const chart = join(temporary, "cogs");
    const inventoryBytes = authenticateChart(
      resolve(root, "deploy/helm/cogs"),
      resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts/chart-inventory.json"),
      chart,
    );
    const valuesPath = join(temporary, "request-values.json");
    writeFileSync(valuesPath, canonical({ stage4Preparation: request.values } as Json), { flag: "wx", mode: 0o400 });
    runHelm(STAGE4_STATIC_MANIFEST_HELM.executable, ["lint", chart, "--strict", "-f", valuesPath], temporary);
    const zero = runHelm(
      STAGE4_STATIC_MANIFEST_HELM.executable,
      ["template", request.release_name, chart, "--namespace", request.namespace, "--dry-run=client", "-f", valuesPath],
      temporary,
    );
    if (zero.trim() !== "") fail("STAGE4_MANIFEST_BASE_CHART_NOT_EMPTY");
    writeFileSync(join(chart, "templates/review-wrapper.yaml"), REVIEW_WRAPPER, { flag: "wx", mode: 0o400 });
    const rendered = runHelm(
      STAGE4_STATIC_MANIFEST_HELM.executable,
      [
        "template",
        request.release_name,
        chart,
        "--namespace",
        request.namespace,
        "--dry-run=client",
        "--hide-notes=false",
        "-f",
        valuesPath,
      ],
      temporary,
    );
    const manifest = extractManifest(rendered, request.release_name);
    const nic = nicConfig(request);
    const nicContract = boundedRegular(
      resolve(root, "deploy/nic/stage4-sandbox-node-group-contract.json"),
      LIMITS.request,
    );
    if (sha256(nicContract) !== STAGE4_STATIC_MANIFEST_INPUTS.nicContractSha256)
      fail("STAGE4_MANIFEST_NIC_CONTRACT_DRIFT");
    output = ensureNewOutput(outputPath);
    writeFileSync(join(output, "manifests.yaml"), manifest.bytes, { flag: "wx", mode: 0o400 });
    writeFileSync(join(output, "nic-config.yaml"), nic, { flag: "wx", mode: 0o400 });
    const receipt = canonical({
      apply_route_present: false,
      authority: "local-static-manifest-materialization-only",
      campaign_authorized: false,
      chart_inventory_sha256: sha256(inventoryBytes),
      cloud_execution_observed: false,
      deployment_execution_route_present: false,
      helm_executable_sha256: sha256(helmBytes),
      kubernetes_client_present: false,
      kubernetes_execution_observed: false,
      launch_template_contents_observed: false,
      manifest_render_route_present: true,
      manifest_sha256: sha256(manifest.bytes),
      nic_config_sha256: sha256(nic),
      nic_contract_sha256: sha256(nicContract),
      object_inventory: manifest.inventory,
      provider_execution_observed: false,
      provider_truth_observed: false,
      release_eligible: false,
      request_sha256: sha256(requestBytes),
      stage4_exit_satisfied: false,
      version: "cogs.stage4-static-manifest-receipt/v1",
    });
    writeFileSync(join(output, "receipt.json"), receipt, { flag: "wx", mode: 0o400 });
    if (
      sha256(boundedRegular(STAGE4_STATIC_MANIFEST_HELM.executable, LIMITS.helm)) !== STAGE4_STATIC_MANIFEST_HELM.sha256
    )
      fail("STAGE4_MANIFEST_HELM_IDENTITY_INVALID");
  } catch (error) {
    if (output !== undefined) rmSync(output, { recursive: true, force: true });
    throw error;
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(import.meta.filename)) {
  try {
    if (process.argv.length !== 6 || process.argv[2] !== "--request" || process.argv[4] !== "--output")
      fail("STAGE4_MANIFEST_ARGUMENTS_INVALID");
    materializeStage4StaticManifestPackage(process.argv[3] ?? "", process.argv[5] ?? "");
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "STAGE4_MANIFEST_FAILED"}\n`);
    process.exitCode = 1;
  }
}

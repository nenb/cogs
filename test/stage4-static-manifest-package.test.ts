/* biome-ignore-all lint/suspicious/noExplicitAny: mutable hostile JSON fixtures and parser boundary */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import {
  STAGE4_STATIC_MANIFEST_HELM,
  STAGE4_STATIC_MANIFEST_INPUTS,
} from "../scripts/stage4-static-manifest-package.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const yaml = require("yaml") as { parseAllDocuments(source: string): Array<{ errors: unknown[]; toJSON(): any }> };
const receiptSchema = require("../schemas/stage4-static-manifest-receipt-v1.json") as object;
const validateReceipt = new Ajv2020({ allErrors: true, strict: true, strictRequired: false }).compile(
  receiptSchema,
) as ValidateFunction;
const root = resolve(import.meta.dirname, "..");
const script = resolve(root, "scripts/stage4-static-manifest-package.ts");
const validRequest = resolve(root, "test/fixtures/stage4-static-manifest/valid-request-v1.json");
const sha = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
const pinnedHelmAvailable =
  existsSync(STAGE4_STATIC_MANIFEST_HELM.executable) &&
  sha(readFileSync(STAGE4_STATIC_MANIFEST_HELM.executable)) === STAGE4_STATIC_MANIFEST_HELM.sha256;

function run(request: string, output: string) {
  return spawnSync(process.execPath, [script, "--request", request, "--output", output], {
    cwd: root,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonical(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function temporaryRequest(directory: string, mutate: (value: Record<string, any>) => void): string {
  const value = JSON.parse(readFileSync(validRequest, "utf8")) as Record<string, any>;
  mutate(value);
  const path = join(directory, `request-${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(path, `${canonical(value)}\n`, { mode: 0o600 });
  return path;
}

test("materializes deterministic local manifests, NIC handoff, and a non-authorizing receipt", {
  skip: !pinnedHelmAvailable,
}, () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-manifest-test-"));
  try {
    const first = join(temporary, "first");
    const second = join(temporary, "second");
    const one = run(validRequest, first);
    const two = run(validRequest, second);
    assert.equal(one.status, 0, one.stderr);
    assert.equal(two.status, 0, two.stderr);
    assert.equal(one.stdout, "");
    assert.equal(two.stdout, "");
    for (const name of ["manifests.yaml", "nic-config.yaml", "receipt.json"]) {
      assert.deepEqual(readFileSync(join(first, name)), readFileSync(join(second, name)), name);
    }

    const manifests = readFileSync(join(first, "manifests.yaml"), "utf8");
    assert.match(manifests, /^# COGS NOTES-ONLY STATIC SOURCE SHAPES BEGIN:/u);
    assert.match(manifests, /UNSAFE TO APPLY; UNQUALIFIED/u);
    const objects = yaml
      .parseAllDocuments(manifests)
      .filter((document) => document.toJSON() !== null)
      .map((document) => {
        assert.deepEqual(document.errors, []);
        return document.toJSON() as { kind: string; metadata: { name: string; namespace: string } };
      });
    assert.equal(objects.length, 9);
    assert.deepEqual(
      objects.map((object) => object.kind),
      [
        "ConfigMap",
        "ServiceAccount",
        "ServiceAccount",
        "Service",
        "NetworkPolicy",
        "NetworkPolicy",
        "NetworkPolicy",
        "PodTemplate",
        "PodTemplate",
      ],
    );
    assert.ok(objects.every((object) => object.metadata.namespace === "static-preparation"));

    const nic = readFileSync(join(first, "nic-config.yaml"), "utf8");
    assert.match(nic, /id: "lt-0123456789abcdef0"/u);
    assert.match(nic, /version: 7/u);
    assert.match(nic, /nested_virtualization: enabled/u);
    assert.doesNotMatch(
      nic,
      /core_count|threads_per_core/u,
      "NIC receives attestation shape it supports, not invented fields",
    );
    assert.doesNotMatch(nic, /disk_size/u);

    const receiptBytes = readFileSync(join(first, "receipt.json"));
    const receipt = JSON.parse(receiptBytes.toString("utf8")) as Record<string, unknown>;
    assert.equal(validateReceipt(receipt), true, JSON.stringify(validateReceipt.errors));
    assert.equal(receipt.manifest_sha256, sha(readFileSync(join(first, "manifests.yaml"))));
    assert.equal(receipt.nic_config_sha256, sha(readFileSync(join(first, "nic-config.yaml"))));
    assert.equal(receipt.chart_inventory_sha256, STAGE4_STATIC_MANIFEST_INPUTS.chartInventorySha256);
    assert.equal(receipt.nic_contract_sha256, STAGE4_STATIC_MANIFEST_INPUTS.nicContractSha256);
    assert.equal(receipt.manifest_render_route_present, true);
    for (const field of [
      "deployment_execution_route_present",
      "apply_route_present",
      "kubernetes_client_present",
      "kubernetes_execution_observed",
      "provider_execution_observed",
      "cloud_execution_observed",
      "provider_truth_observed",
      "launch_template_contents_observed",
      "campaign_authorized",
      "stage4_exit_satisfied",
      "release_eligible",
    ])
      assert.equal(receipt[field], false, field);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("rejects aliases, quoted/fractional versions, attestation drift, extra fields, and noncanonical bytes", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-manifest-hostile-"));
  try {
    const cases: Array<(value: Record<string, any>) => void> = [
      (value) => (value.nic.external_launch_template.version = "$Latest"),
      (value) => (value.nic.external_launch_template.version = "7"),
      (value) => (value.nic.external_launch_template.version = 1.5),
      (value) => (value.nic.external_launch_template.version = 0),
      (value) => (value.nic.external_launch_template.operator_review.cpu_options.nested_virtualization = "observed"),
      (value) => (value.nic.external_launch_template.operator_review.cpu_options.core_count = 2),
      (value) => (value.extra = true),
    ];
    for (const [index, mutate] of cases.entries()) {
      const request = temporaryRequest(temporary, mutate);
      const result = run(request, join(temporary, `output-${index}`));
      assert.notEqual(result.status, 0, `case ${index}`);
      assert.equal(result.stderr, "STAGE4_MANIFEST_REQUEST_INVALID\n");
    }
    const whitespace = join(temporary, "whitespace.json");
    writeFileSync(whitespace, ` ${readFileSync(validRequest, "utf8")}`, { mode: 0o600 });
    assert.match(run(whitespace, join(temporary, "whitespace-output")).stderr, /STAGE4_MANIFEST_REQUEST_NONCANONICAL/u);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("rejects Helm-level placement drift", { skip: !pinnedHelmAvailable }, () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-manifest-helm-hostile-"));
  try {
    const request = temporaryRequest(temporary, (value) => (value.values.placement.sandbox.tolerations = []));
    const result = run(request, join(temporary, "output"));
    assert.notEqual(result.status, 0);
    assert.equal(result.stderr, "STAGE4_MANIFEST_HELM_FAILED\n");
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("rejects symlink request, existing output, extra arguments, and unreadable request", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-manifest-paths-"));
  try {
    const link = join(temporary, "request-link.json");
    symlinkSync(validRequest, link);
    assert.notEqual(run(link, join(temporary, "link-output")).status, 0);
    const output = join(temporary, "existing");
    writeFileSync(output, "occupied", { mode: 0o600 });
    assert.notEqual(run(validRequest, output).status, 0);
    const unreadable = join(temporary, "unreadable.json");
    writeFileSync(unreadable, readFileSync(validRequest), { mode: 0o000 });
    chmodSync(unreadable, 0o000);
    assert.notEqual(run(unreadable, join(temporary, "unreadable-output")).status, 0);
    const extra = spawnSync(
      process.execPath,
      [script, "--request", validRequest, "--output", join(temporary, "extra"), "--apply"],
      {
        cwd: root,
        encoding: "utf8",
      },
    );
    assert.notEqual(extra.status, 0);
    assert.equal(extra.stderr, "STAGE4_MANIFEST_ARGUMENTS_INVALID\n");
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("source exposes only fixed local Helm rendering and no deployment/provider/client route", () => {
  const source = readFileSync(script, "utf8");
  assert.match(source, /--dry-run=client/u);
  assert.match(source, /absent-kubeconfig/u);
  assert.equal(STAGE4_STATIC_MANIFEST_HELM.executable, "/opt/homebrew/Cellar/helm/4.1.1/bin/helm");
  for (const forbidden of [
    "@kubernetes/client-node",
    "aws-sdk",
    "@aws-sdk",
    "kubectl",
    "opentofu",
    "terraform",
    "helm install",
    "helm upgrade",
    "fetch(",
    "https.request",
    "http.request",
    "execSync",
    "shell: true",
  ])
    assert.equal(source.includes(forbidden), false, forbidden);
  assert.equal((source.match(/spawnSync\(/gu) ?? []).length, 1);
});

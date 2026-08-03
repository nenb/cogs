/* biome-ignore-all lint/suspicious/noExplicitAny: mutable hostile JSON fixtures */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import {
  evaluateStage4NicSandboxNodeGroupContract,
  STAGE4_NIC_V2_REASON_CODES,
} from "../scripts/stage4-nic-sandbox-node-group.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const contractSchema = require("../schemas/stage4-nic-sandbox-node-group-contract-v2.json") as object;
const verdictSchema = require("../schemas/stage4-nic-sandbox-node-group-verdict-v2.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validateContract = ajv.compile(contractSchema) as ValidateFunction;
const validateVerdict = ajv.compile(verdictSchema) as ValidateFunction;
const path = resolve(import.meta.dirname, "../deploy/nic/stage4-sandbox-node-group-contract.json");
const fixture = (): Record<string, any> => JSON.parse(readFileSync(path, "utf8")) as Record<string, any>;

function classify(value: unknown) {
  const verdict = evaluateStage4NicSandboxNodeGroupContract(value);
  assert.equal(validateVerdict(verdict), true, JSON.stringify(validateVerdict.errors));
  assert.equal(verdict.campaign_authorized, false);
  assert.equal(verdict.cloud_execution_observed, false);
  assert.equal(verdict.provider_truth_observed, false);
  assert.equal(verdict.launch_template_contents_observed, false);
  assert.equal(verdict.node_image_pin_resolved, false);
  assert.equal(verdict.stage4_exit_satisfied, false);
  assert.equal(verdict.release_eligible, false);
  return verdict;
}

test("active v2 pins the accepted personal forks and resolves only source capability", () => {
  const contract = fixture();
  assert.equal(validateContract(contract), true, JSON.stringify(validateContract.errors));
  const verdict = classify(contract);
  assert.equal(verdict.status, "source-capability-satisfied-local-static");
  assert.equal(verdict.reason_code, "STAGE4_NIC_SOURCE_CAPABILITY_PRESENT_NONOBSERVING");
  assert.equal(verdict.nic_source_pin_resolved, true);
  assert.equal(verdict.launch_template_selection_capability_resolved, true);
  assert.equal(verdict.contract_sha256, "5dfc1bb269868daf536598d3a80e9c4dfee51793ce3f391b3d5dc1ee753cbb29");

  assert.equal(contract.nic_source.commit_sha, "53b1a791ed1ff394969e0aeaa6379be955244b62");
  assert.equal(contract.nic_source.tree_git_sha, "32c14bd9a19c0519006a9b86284402f9e0187947");
  assert.equal(contract.nic_source.protected_main, false);
  assert.equal(contract.nic_source.commit_signature_verified, false);
  assert.equal(contract.nic_source.eks_module.commit_sha, "c3017c0e15b538cd4e04c0786809a861ea82c621");
  assert.equal(contract.nic_source.eks_module.tree_git_sha, "59105ac6f037977d0dddebf844affa06e0b01236");
  assert.equal(
    contract.nic_capability_assessment.cpu_options_nested_virtualization,
    "operator-attestation-only-not-observed",
  );
  assert.equal(contract.nic_capability_assessment.launch_template_contents_observed, false);
  assert.equal(contract.node_image.pin_state, "public-candidate");
  assert.equal(contract.node_image.release, "1.35.6-20260728");
  assert.equal(contract.node_image.ami_id, null);
  assert.equal(contract.node_image.kernel_release, null);
  assert.equal(contract.sandbox_node_group.runtime.qemu_version, "11.0.1");
  assert.equal(
    contract.sandbox_node_group.runtime.qemu_artifact_sha256,
    "1e4968d9cce98c7cba8f9e3488236cba56993d9747f268d03b0284f3df2b012d",
  );
});

test("v2 binds every reviewed file blob, content digest, and size in exact order", () => {
  const contract = fixture();
  assert.equal(contract.nic_source.files.length, 10);
  assert.equal(contract.nic_source.eks_module.files.length, 9);
  for (const file of [...contract.nic_source.files, ...contract.nic_source.eks_module.files]) {
    assert.match(file.git_blob_sha, /^[0-9a-f]{40}$/u);
    assert.match(file.content_sha256, /^[0-9a-f]{64}$/u);
    assert.ok(Number.isSafeInteger(file.size_bytes) && file.size_bytes > 0);
  }
  assert.deepEqual(contract.nic_source.files[0], {
    path: "pkg/providers/cluster/aws/config.go",
    git_blob_sha: "18675e9558fb46deba4fb85b0e8af309e103ec45",
    content_sha256: "d9c14cdda1b4e8da3f7f8b546c6b0e52c054d29df64ca2f36debdd143ed42246",
    size_bytes: 11700,
  });
  assert.deepEqual(contract.nic_source.eks_module.files[1], {
    path: "locals.tf",
    git_blob_sha: "78e420cdca768c5e28000152e8f186f9c239fc97",
    content_sha256: "10e18f2ee4e9629d14991e06303a681563c9570b7ba48a702b382a097763d109",
    size_bytes: 5431,
  });
});

test("source, attestation, selection, scheduling, and non-observation drift all reject", () => {
  const mutations: Array<(value: Record<string, any>) => void> = [
    (value) => (value.nic_source.commit_sha = "0".repeat(40)),
    (value) => (value.nic_source.files[0].content_sha256 = "0".repeat(64)),
    (value) => (value.nic_source.eks_module.commit_sha = "0".repeat(40)),
    (value) => (value.nic_capability_assessment.launch_template_contents_observed = true),
    (value) => (value.nic_capability_assessment.cpu_options_nested_virtualization = "observed"),
    (value) => (value.sandbox_node_group.launch_template.allow_latest_version = true),
    (value) => (value.sandbox_node_group.capacity_type = "SPOT"),
    (value) => (value.scheduling.trusted.tolerations = value.scheduling.sandbox.tolerations),
  ];
  for (const mutate of mutations) {
    const value = fixture();
    mutate(value);
    const verdict = classify(value);
    assert.equal(verdict.status, "reject-drift");
    assert.equal(verdict.reason_code, "STAGE4_NIC_SOURCE_DRIFT");
    assert.equal(verdict.nic_source_pin_resolved, false);
    assert.equal(verdict.launch_template_selection_capability_resolved, false);
  }
});

test("malformed and hostile object surfaces fail without getters or authority promotion", () => {
  assert.deepEqual(STAGE4_NIC_V2_REASON_CODES, [
    "STAGE4_NIC_SOURCE_CAPABILITY_PRESENT_NONOBSERVING",
    "STAGE4_NIC_INVALID_SHAPE",
    "STAGE4_NIC_INVALID_VERSION",
    "STAGE4_NIC_SOURCE_DRIFT",
  ]);
  assert.equal(classify(null).reason_code, "STAGE4_NIC_INVALID_SHAPE");
  const wrong = fixture();
  wrong.version = "cogs.stage4-nic-sandbox-node-group-contract/v1";
  assert.equal(classify(wrong).reason_code, "STAGE4_NIC_INVALID_VERSION");
  let reads = 0;
  const hostile = Object.defineProperty({}, "version", {
    enumerable: true,
    get() {
      reads += 1;
      return "cogs.stage4-nic-sandbox-node-group-contract/v2";
    },
  });
  assert.equal(classify(hostile).reason_code, "STAGE4_NIC_INVALID_SHAPE");
  assert.equal(reads, 0);
  const symbol = fixture();
  Object.defineProperty(symbol, Symbol("hidden"), { value: true, enumerable: true });
  assert.equal(classify(symbol).reason_code, "STAGE4_NIC_INVALID_SHAPE");
});

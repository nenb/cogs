import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import * as contractModule from "../scripts/stage4-nic-sandbox-node-group.ts";
import {
  evaluateStage4NicSandboxNodeGroupContract,
  STAGE4_DISJOINT_SCHEDULING,
  STAGE4_NIC_CAPABILITY_ASSESSMENT,
  STAGE4_NIC_REASON_CODES,
  STAGE4_PINNED_NIC_SOURCE,
  STAGE4_SANDBOX_NODE_GROUP,
  type Stage4NicVerdict,
} from "../scripts/stage4-nic-sandbox-node-group.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const contractPath = resolve(root, "deploy/nic/stage4-sandbox-node-group-contract.json");
const contractSchema = require("../schemas/stage4-nic-sandbox-node-group-contract-v1.json") as object;
const verdictSchema = require("../schemas/stage4-nic-sandbox-node-group-verdict-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validateContract = ajv.compile(contractSchema) as ValidateFunction;
const validateVerdict = ajv.compile(verdictSchema) as ValidateFunction;

type MutableContract = Record<string, unknown> & {
  nic_source: Record<string, unknown>;
  nic_capability_assessment: Record<string, unknown>;
  node_image: Record<string, unknown>;
  sandbox_node_group: Record<string, unknown> & {
    scaling: Record<string, unknown>;
    required_labels: Record<string, unknown>;
    required_taints: Array<Record<string, unknown>>;
    launch_template: Record<string, unknown> & { cpu_options: Record<string, unknown> };
    runtime: Record<string, unknown>;
  };
  scheduling: Record<string, unknown> & {
    trusted: Record<string, unknown> & { required_node_selector: Record<string, unknown>; tolerations: unknown[] };
    sandbox: Record<string, unknown> & { required_node_selector: Record<string, unknown>; tolerations: unknown[] };
  };
};

function fixture(): MutableContract {
  return JSON.parse(readFileSync(contractPath, "utf8")) as MutableContract;
}

function imagePinned(): MutableContract {
  const value = fixture();
  value.node_image = {
    pin_state: "pinned",
    ami_id: "ami-0123456789abcdef0",
    release: "synthetic-test-release",
    kernel_release: "6.17.0-synthetic",
  };
  return value;
}

function assertNonAuthority(verdict: Stage4NicVerdict): void {
  assert.equal(verdict.authority, "local-static-nic-contract-classifier");
  assert.equal(verdict.campaign_authorized, false);
  assert.equal(verdict.cloud_execution_observed, false);
  assert.equal(verdict.stage4_exit_satisfied, false);
  assert.equal(verdict.release_eligible, false);
  assert.equal(validateVerdict(verdict), true, JSON.stringify(validateVerdict.errors));
}

function assertDrift(value: unknown, reason: Stage4NicVerdict["reason_code"]): void {
  const verdict = evaluateStage4NicSandboxNodeGroupContract(value);
  assert.equal(verdict.status, "reject-drift");
  assert.equal(verdict.reason_code, reason);
  assertNonAuthority(verdict);
}

test("the checked-in contract pins exact NIC source and is blocked by its missing capability", () => {
  const value = fixture();
  assert.equal(validateContract(value), true, JSON.stringify(validateContract.errors));
  const first = evaluateStage4NicSandboxNodeGroupContract(value);
  const second = evaluateStage4NicSandboxNodeGroupContract(value);
  assert.deepEqual(first, second);
  assert.equal(first.status, "blocked-missing-capability");
  assert.equal(first.reason_code, "STAGE4_NIC_LAUNCH_TEMPLATE_CAPABILITY_MISSING");
  assert.equal(first.nic_source_pin_resolved, true);
  assert.equal(first.node_image_pin_resolved, false);
  assert.equal(first.launch_template_capability_resolved, false);
  assert.match(first.contract_sha256 ?? "", /^[0-9a-f]{64}$/u);
  assert.equal(Object.isFrozen(first), true);
  assertNonAuthority(first);

  assert.deepEqual(value.nic_source, STAGE4_PINNED_NIC_SOURCE);
  const tofuSource = STAGE4_PINNED_NIC_SOURCE.files[2];
  assert.equal(tofuSource?.git_blob_sha, "934a1f92413ba7c758f57d779c3ad1049256b30d");
  assert.equal(tofuSource?.content_sha256, "39e87c14203fa602568bcff4e64126271073484e531c21a83028eb104a9a506b");
  assert.deepEqual(value.nic_capability_assessment, STAGE4_NIC_CAPABILITY_ASSESSMENT);
  assert.equal(Object.isFrozen(STAGE4_PINNED_NIC_SOURCE.files), true);
  assert.equal(Object.isFrozen(STAGE4_PINNED_NIC_SOURCE.eks_module.files), true);
  assert.equal(Object.isFrozen(STAGE4_SANDBOX_NODE_GROUP.launch_template.cpu_options), true);
  assert.equal(Object.isFrozen(STAGE4_DISJOINT_SCHEDULING.sandbox.tolerations), true);
  assert.equal(value.node_image.ami_id, null);
  assert.equal(value.node_image.kernel_release, null);
});

test("an exact synthetic node-image pin cannot bypass the pinned NIC capability blocker", () => {
  const value = imagePinned();
  assert.equal(validateContract(value), true, JSON.stringify(validateContract.errors));
  const verdict = evaluateStage4NicSandboxNodeGroupContract(value);
  assert.equal(verdict.status, "blocked-missing-capability");
  assert.equal(verdict.reason_code, "STAGE4_NIC_LAUNCH_TEMPLATE_CAPABILITY_MISSING");
  assert.equal(verdict.nic_source_pin_resolved, true);
  assert.equal(verdict.node_image_pin_resolved, true);
  assert.equal(verdict.launch_template_capability_resolved, false);
  assertNonAuthority(verdict);
});

test("the node-group constants match the Helm placement boundary exactly", () => {
  const value = fixture();
  assert.deepEqual(value.sandbox_node_group, STAGE4_SANDBOX_NODE_GROUP);
  assert.deepEqual(value.scheduling, STAGE4_DISJOINT_SCHEDULING);
  assert.deepEqual(value.sandbox_node_group.required_labels, {
    "cogs.dev/node-domain": "sandbox-kata",
    "cogs.dev/nested-virtualization": "enabled",
    "cogs.dev/sandbox-runtime": "kata-qemu-kvm",
  });
  assert.deepEqual(value.sandbox_node_group.required_taints, [
    { key: "cogs.dev/sandbox", value: "kata", effect: "NO_SCHEDULE" },
  ]);
  assert.deepEqual(value.scheduling.trusted.tolerations, []);
  assert.deepEqual(value.scheduling.sandbox.tolerations, [
    { key: "cogs.dev/sandbox", operator: "Equal", value: "kata", effect: "NoSchedule" },
  ]);
});

test("rejects Spot, bare metal, scaling expansion, and instance drift", () => {
  const mutations: Array<[string, (value: MutableContract) => void]> = [
    ["Spot", (value) => (value.sandbox_node_group.capacity_type = "SPOT")],
    ["bare metal", (value) => (value.sandbox_node_group.bare_metal = true)],
    ["metal type", (value) => (value.sandbox_node_group.instance_type = "c8i.metal-24xl")],
    ["larger virtual type", (value) => (value.sandbox_node_group.instance_type = "c8i-flex.xlarge")],
    ["minimum", (value) => (value.sandbox_node_group.scaling.min = 1)],
    ["maximum", (value) => (value.sandbox_node_group.scaling.max = 2)],
    ["unsupported desired", (value) => (value.sandbox_node_group.scaling.desired = 1)],
    ["region", (value) => (value.sandbox_node_group.region = "us-west-2")],
  ];
  for (const [name, mutate] of mutations) {
    const value = imagePinned();
    mutate(value);
    assertDrift(value, "STAGE4_NODE_GROUP_DRIFT");
    assert.equal(validateContract(value), false, `${name} passed schema`);
  }
});

test("rejects nested-virtualization and launch-template reference drift", () => {
  const mutations: Array<[string, (value: MutableContract) => void]> = [
    [
      "nested virtualization",
      (value) => (value.sandbox_node_group.launch_template.cpu_options.nested_virtualization = "disabled"),
    ],
    ["core count", (value) => (value.sandbox_node_group.launch_template.cpu_options.core_count = 2)],
    ["latest", (value) => (value.sandbox_node_group.launch_template.version_selection = "$Latest")],
    ["default allowed", (value) => (value.sandbox_node_group.launch_template.allow_default_version = true)],
    ["latest allowed", (value) => (value.sandbox_node_group.launch_template.allow_latest_version = true)],
    ["version dropped", (value) => (value.sandbox_node_group.launch_template.preserve_id_and_version = false)],
    ["reconcile drift", (value) => (value.sandbox_node_group.launch_template.reject_reconcile_drift = false)],
    ["managed implicit template", (value) => (value.sandbox_node_group.launch_template.source = "managed-implicit")],
  ];
  for (const [name, mutate] of mutations) {
    const value = imagePinned();
    mutate(value);
    assertDrift(value, "STAGE4_NODE_GROUP_DRIFT");
    assert.equal(validateContract(value), false, `${name} passed schema`);
  }
});

test("rejects runc, TCG, runtime substitution, and unpinned Kata", () => {
  const mutations: Array<[string, (value: MutableContract) => void]> = [
    ["runc class", (value) => (value.sandbox_node_group.runtime.runtime_class_name = "runc")],
    ["runc handler", (value) => (value.sandbox_node_group.runtime.handler = "runc")],
    ["runc runtime", (value) => (value.sandbox_node_group.runtime.cri_runtime_type = "io.containerd.runc.v2")],
    ["runc fallback", (value) => (value.sandbox_node_group.runtime.allow_runc_fallback = true)],
    ["TCG accelerator", (value) => (value.sandbox_node_group.runtime.accelerator = "tcg")],
    ["TCG fallback", (value) => (value.sandbox_node_group.runtime.allow_tcg_fallback = true)],
    ["Kata version", (value) => (value.sandbox_node_group.runtime.kata_version = "latest")],
    ["Kata digest", (value) => (value.sandbox_node_group.runtime.kata_archive_sha256 = "0".repeat(64))],
    ["containerd", (value) => (value.sandbox_node_group.runtime.containerd_version = "latest")],
    ["QEMU", (value) => (value.sandbox_node_group.runtime.qemu_version = "latest")],
  ];
  for (const [name, mutate] of mutations) {
    const value = imagePinned();
    mutate(value);
    assertDrift(value, "STAGE4_NODE_GROUP_DRIFT");
    assert.equal(validateContract(value), false, `${name} passed schema`);
  }
});

test("rejects label, taint, toleration, and trusted/sandbox overlap", () => {
  const mutations: Array<[string, (value: MutableContract) => void]> = [
    ["label removal", (value) => delete value.sandbox_node_group.required_labels["cogs.dev/node-domain"]],
    ["trusted node label", (value) => (value.sandbox_node_group.required_labels["cogs.dev/node-domain"] = "trusted")],
    ["taint removal", (value) => value.sandbox_node_group.required_taints.pop()],
    [
      "taint effect",
      (value) => {
        const taint = value.sandbox_node_group.required_taints[0];
        assert.ok(taint);
        taint.effect = "PREFER_NO_SCHEDULE";
      },
    ],
  ];
  for (const [name, mutate] of mutations) {
    const value = imagePinned();
    mutate(value);
    assertDrift(value, "STAGE4_NODE_GROUP_DRIFT");
    assert.equal(validateContract(value), false, `${name} passed schema`);
  }

  const schedulingMutations: Array<[string, (value: MutableContract) => void]> = [
    [
      "trusted selector overlap",
      (value) => (value.scheduling.trusted.required_node_selector["cogs.dev/node-domain"] = "sandbox-kata"),
    ],
    [
      "trusted toleration",
      (value) => value.scheduling.trusted.tolerations.push(STAGE4_DISJOINT_SCHEDULING.sandbox.tolerations[0]),
    ],
    [
      "sandbox selector",
      (value) => (value.scheduling.sandbox.required_node_selector["cogs.dev/node-domain"] = "trusted"),
    ],
    ["sandbox toleration removal", (value) => value.scheduling.sandbox.tolerations.pop()],
    ["disjoint flag", (value) => (value.scheduling.domains_disjoint = false)],
  ];
  for (const [name, mutate] of schedulingMutations) {
    const value = imagePinned();
    mutate(value);
    assertDrift(value, "STAGE4_SCHEDULING_DRIFT");
    assert.equal(validateContract(value), false, `${name} passed schema`);
  }
});

test("pinned NIC source, module closure, and missing-capability assessment reject drift", () => {
  const sourceMutations: Array<(value: MutableContract) => void> = [
    (value) => (value.nic_source.release_tag = "latest"),
    (value) => (value.nic_source.commit_sha = "a".repeat(40)),
    (value) => (value.nic_source.tree_git_sha = "a".repeat(40)),
    (value) => {
      const source = value.nic_source.files as Array<Record<string, unknown>>;
      const row = source[0];
      assert.ok(row);
      row.content_sha256 = "0".repeat(64);
    },
    (value) => {
      const source = value.nic_source.files as Array<Record<string, unknown>>;
      const row = source[1];
      assert.ok(row);
      row.git_blob_sha = "0".repeat(40);
    },
    (value) => {
      const module = value.nic_source.eks_module as Record<string, unknown>;
      module.version = "latest";
    },
    (value) => {
      const module = value.nic_source.eks_module as Record<string, unknown>;
      module.tree_git_sha = "0".repeat(40);
    },
    (value) => {
      const module = value.nic_source.eks_module as Record<string, unknown>;
      const files = module.files as Array<Record<string, unknown>>;
      const row = files[2];
      assert.ok(row);
      row.content_sha256 = "0".repeat(64);
    },
    (value) => (value.nic_capability_assessment.custom_launch_template_id = true),
    (value) => (value.nic_capability_assessment.cpu_options_nested_virtualization = true),
    (value) => (value.nic_capability_assessment.outcome = "supported"),
  ];
  for (const mutate of sourceMutations) {
    const value = imagePinned();
    mutate(value);
    assertDrift(value, "STAGE4_NIC_SOURCE_DRIFT");
    assert.equal(validateContract(value), false);
  }
});

test("external pins reject placeholders, moving refs, malformed identities, and invented fields", () => {
  const mutations: Array<[Stage4NicVerdict["reason_code"], (value: MutableContract) => void]> = [
    ["STAGE4_NIC_SOURCE_DRIFT", (value) => (value.nic_source.commit_sha = "main")],
    ["STAGE4_NIC_SOURCE_DRIFT", (value) => (value.nic_source.commit_sha = "A".repeat(40))],
    ["STAGE4_NIC_SOURCE_DRIFT", (value) => (value.nic_source.repository = "https://user@example.invalid/nic.git")],
    ["STAGE4_NIC_SOURCE_DRIFT", (value) => (value.nic_source.reason_code = "invented")],
    ["STAGE4_NODE_IMAGE_DRIFT", (value) => (value.node_image.ami_id = "ami-latest")],
    ["STAGE4_NODE_IMAGE_DRIFT", (value) => (value.node_image.kernel_release = "")],
  ];
  for (const [reason, mutate] of mutations) {
    const value = imagePinned();
    mutate(value);
    assertDrift(value, reason);
    assert.equal(validateContract(value), false);
  }
});

test("unknown fields, reordered semantics, and hostile introspection fail deterministically", () => {
  const unknown = imagePinned();
  unknown.sandbox_node_group.runtime.fallback = "runc";
  assertDrift(unknown, "STAGE4_NODE_GROUP_DRIFT");
  assert.equal(validateContract(unknown), false);

  const original = imagePinned();
  const reordered = {
    scheduling: original.scheduling,
    sandbox_node_group: original.sandbox_node_group,
    node_image: original.node_image,
    nic_source: original.nic_source,
    nic_capability_assessment: original.nic_capability_assessment,
    authority: original.authority,
    version: original.version,
  };
  assert.deepEqual(
    evaluateStage4NicSandboxNodeGroupContract(reordered),
    evaluateStage4NicSandboxNodeGroupContract(original),
  );

  let getterCalls = 0;
  const inheritedValues = imagePinned();
  delete inheritedValues.version;
  const inherited = Object.assign(
    Object.create({
      get version() {
        getterCalls += 1;
        return "cogs.stage4-nic-sandbox-node-group-contract/v1";
      },
    }) as Record<string, unknown>,
    inheritedValues,
  );
  const traps: unknown[] = [
    new Proxy(
      {},
      {
        ownKeys: () => {
          throw new Error("ownKeys");
        },
      },
    ),
    Object.defineProperty({}, "version", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "cogs.stage4-nic-sandbox-node-group-contract/v1";
      },
    }),
    inherited,
    { ...imagePinned(), scheduling: new Date() },
  ];
  for (const hostile of traps) {
    assert.doesNotThrow(() => evaluateStage4NicSandboxNodeGroupContract(hostile));
    assertDrift(hostile, "STAGE4_NIC_INVALID_SHAPE");
  }
  assert.equal(getterCalls, 0, "classifier must not invoke own or inherited getters");
});

test("the classifier exposes only fixed local-static outputs and no execution/provider surface", () => {
  assert.deepEqual(STAGE4_NIC_REASON_CODES, [
    "STAGE4_NIC_LAUNCH_TEMPLATE_CAPABILITY_MISSING",
    "STAGE4_NIC_INVALID_SHAPE",
    "STAGE4_NIC_INVALID_VERSION",
    "STAGE4_NIC_SOURCE_DRIFT",
    "STAGE4_NODE_IMAGE_DRIFT",
    "STAGE4_NODE_GROUP_DRIFT",
    "STAGE4_SCHEDULING_DRIFT",
  ]);
  assert.deepEqual(Object.keys(contractModule).sort(), [
    "STAGE4_DISJOINT_SCHEDULING",
    "STAGE4_NIC_CAPABILITY_ASSESSMENT",
    "STAGE4_NIC_REASON_CODES",
    "STAGE4_PINNED_NIC_SOURCE",
    "STAGE4_SANDBOX_NODE_GROUP",
    "evaluateStage4NicSandboxNodeGroupContract",
  ]);

  const source = readFileSync(resolve(root, "scripts/stage4-nic-sandbox-node-group.ts"), "utf8");
  assert.doesNotMatch(
    source,
    /(?:from\s*|import\s*\()["'](?:node:(?:child_process|fs|http|https|net|tls|dns|dgram|os)|@aws|@kubernetes|aws-sdk|kubernetes|opentofu)/u,
  );
  assert.doesNotMatch(source, /\b(?:fetch|eval|spawn|exec|writeFile|appendFile)\s*\(/u);
  assert.doesNotMatch(source, /\bprocess(?:\.|\[)/u);
  assert.doesNotMatch(source, /\b(?:helm|kubectl|terraform|opentofu|aws)\s+/iu);
});

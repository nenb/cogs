import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { renderAwsStage2CompletionReport } from "../scripts/render-aws-stage2-completion-report-v2.ts";
import {
  CompletionEvidenceValidationError,
  parseAwsStage2CompletionEvidence,
  validateAwsStage2CompletionEvidence,
} from "../scripts/validate-aws-stage2-completion-evidence-v2.ts";

const digest = (label: string) => createHash("sha256").update(`completion-evidence:${label}`).digest("hex");
const phases = [
  "READINESS_REVOKED",
  "TASK_STOPPED",
  "TASK_ABSENT",
  "RUNTIME_PROCESSES_ABSENT",
  "NETWORK_ABSENT",
  "CONTAINER_ABSENT",
  "SHARE_AND_MOUNTS_ABSENT",
  "FIREWALL_ABSENT",
  "CONTAINERD_ABSENT",
  "INPUTS_ABSENT",
  "ROOTFS_ABSENT",
  "FINAL_BASELINES",
  "RETIRED",
];
const freshness = [
  "instance_commitment",
  "root_volume_commitment",
  "launch_template_generation_commitment",
  "host_boot_commitment",
  "operation_commitment",
  "client_key_commitment",
  "host_key_commitment",
  "pre_destroy_receipt_commitment",
];
const modes = ["full", "readiness", "readiness", "readiness", "readiness", "readiness", "readiness"];
const ceilCost = (duration: number, rate: number) =>
  Number((BigInt(duration) * BigInt(rate) + 3_600_000_000_000n - 1n) / 3_600_000_000_000n);
const makeSummary = (samples_ns: number[]) => {
  const sorted = [...samples_ns].sort((left, right) => left - right);
  return { samples_ns, min_ns: sorted[0], p50_ns: sorted[3], p95_ns: sorted[6], max_ns: sorted[6] };
};

// biome-ignore lint/suspicious/noExplicitAny: hostile mutations deliberately cross the closed evidence type
function fixture(): Record<string, any> {
  const rates = { compute: 90_000, public_ipv4: 5_000, gp3: 3_000, support_allowance: 20_000 };
  const launch = [70, 20, 50, 40, 60, 30, 10].map((value) => value * 1_000_000);
  const ssh = [90, 30, 70, 50, 70, 40, 20].map((value) => value * 1_000_000);
  const receipt = Array.from({ length: 7 }, (_, index) => digest(`receipt-${index + 1}`));
  const outputs = { git: digest("git-output"), build: digest("build-output"), install: digest("install-output") };
  const workloads = Object.fromEntries(
    Object.entries(outputs).map(([category, output]) => [
      category,
      Array.from({ length: 7 }, (_, index) => ({
        ordinal: index + 1,
        duration_ns: (index + 1 + (category === "git" ? 0 : category === "build" ? 10 : 20)) * 1_000_000,
        output_commitment: output,
        deleted: true,
        cycle_receipt_commitment: receipt[0],
      })),
    ]),
  );
  const cycles = Array.from({ length: 7 }, (_, index) => {
    const duration = 600_000_000_000;
    const component = {
      compute_micro_usd: ceilCost(duration, rates.compute),
      public_ipv4_micro_usd: ceilCost(duration, rates.public_ipv4),
      gp3_micro_usd: ceilCost(duration, rates.gp3),
      support_allowance_micro_usd: ceilCost(duration, rates.support_allowance),
    };
    return {
      ordinal: index + 1,
      mode: modes[index],
      cycle_commitment: digest(`cycle-${index + 1}`),
      receipt_commitment: receipt[index],
      expiry_at: "2026-08-23T12:00:00Z",
      deadline_binding_commitment: digest("deadline-binding"),
      effect_started_offset_ns: index * duration,
      effect_ended_offset_ns: (index + 1) * duration,
      duration_ns: duration,
      apply_to_running_ns: launch[index],
      kata_launch_to_ssh_ready_ns: ssh[index],
      attempts: { apply: 1, remote_lifecycle: 1, kata_ctr_launch: 1, ssh: 1, destroy: 1 },
      freshness: Object.fromEntries(freshness.map((name) => [name, digest(`${name}-${index + 1}`)])),
      ...(index === 0 ? { workloads } : {}),
      teardown: phases.map((phase) => ({ phase, passed: true })),
      destroy_commitment: digest(`destroy-${index + 1}`),
      zero_inventory_commitment: digest(`zero-${index + 1}`),
      cost: {
        billable_duration_ns: duration,
        ...component,
        total_micro_usd: Object.values(component).reduce((sum, value) => sum + value, 0),
      },
    };
  });
  const aggregateCost = cycles.reduce((sum, cycle) => sum + cycle.cost.total_micro_usd, 0);
  return {
    version: "cogs.aws-stage2-completion-evidence/v2",
    authority: "aws-stage2-completion",
    result: "pass",
    batch: {
      commitment: digest("batch"),
      source_revision: "a".repeat(40),
      expiry_at: "2026-08-23T12:00:00Z",
      cycle_count: 7,
      modes,
    },
    bindings: Object.fromEntries(
      [
        "account_principals",
        "ami",
        "rootfs",
        "rootfs_descriptor",
        "rootfs_package_manifest",
        "rootfs_provenance",
        "rootfs_publication_receipt",
        "pre_aws_package",
        "resolved_ami_identity",
        "runtime_archive",
        "static_control",
        "final_package_pin",
        "fixture",
        "full_guest_program",
        "readiness_guest_program",
        "owner",
        "controller",
        "schema",
        "validator",
        "renderer",
        "plan_policy",
        "rate_table",
      ].map((name) => [`${name}_commitment`, digest(`binding-${name}`)]),
    ),
    deadlines: {
      first_apply_started_at: "2026-08-23T10:00:00Z",
      effect_deadline_at: "2026-08-23T11:30:00Z",
      expiry_at: "2026-08-23T12:00:00Z",
      normal_effect_deadline_seconds: 5400,
      cleanup_reserve_seconds: 1200,
      binding_commitment: digest("deadline-binding"),
    },
    cycles,
    launch_summary: makeSummary(launch),
    ssh_ready_summary: makeSummary(ssh),
    workload_summary: {
      cycle_ordinal: 1,
      receipt_commitment: receipt[0],
      ...Object.fromEntries(
        Object.entries(workloads).map(([name, rows]) => [
          name,
          {
            output_commitment: outputs[name as keyof typeof outputs],
            ...makeSummary((rows as Array<{ duration_ns: number }>).map((row) => row.duration_ns)),
          },
        ]),
      ),
    },
    cleanup: {
      cycle_zero_commitments: cycles.map((cycle) => cycle.zero_inventory_commitment),
      final_zero_commitment: digest("zero-final"),
      zero_receipt_count: 8,
      destroy_attempts: 7,
      inventory_observations: 8,
      teardown_phase_count: 13,
      final_zero_receipt: {
        receipt_commitment: digest("final-zero-receipt"),
        observer_commitment: digest("final-observer"),
        session_commitment: digest("final-session"),
        run_commitment: digest("final-run"),
        observed_at: "2026-08-23T11:20:00Z",
        pagination_complete: true,
        account_region_complete: true,
        resource_total: 0,
        categories: [
          "ec2_instances",
          "ebs_volumes",
          "network_interfaces",
          "elastic_ips",
          "security_groups",
          "iam_roles",
          "iam_instance_profiles",
          "eventbridge_schedules",
          "ssm_managed_instances",
          "launch_templates",
          "key_pairs",
        ],
      },
      inventory_categories: [
        "ec2_instances",
        "ebs_volumes",
        "network_interfaces",
        "elastic_ips",
        "security_groups",
        "iam_roles",
        "iam_instance_profiles",
        "eventbridge_schedules",
        "ssm_managed_instances",
        "launch_templates",
        "key_pairs",
      ],
    },
    cost: {
      currency: "micro-USD",
      rate_table_commitment: digest("binding-rate_table"),
      price_evidence_commitment: digest("price-evidence"),
      deadline_binding_commitment: digest("deadline-binding"),
      rates_micro_usd_per_hour: rates,
      expected_upper_bound_micro_usd: 200_000,
      expected_limit_micro_usd: 250_000,
      aggregate_effect_duration_ns: cycles.reduce((sum, cycle) => sum + cycle.duration_ns, 0),
      actual_campaign_duration_ns: 4_800_000_000_000,
      aggregate_cost_micro_usd: aggregateCost,
      publishable_limit_micro_usd: 500_000,
    },
    limitations: [
      "standalone-stage-2-only",
      "not-eks-or-kubernetes",
      "not-production-release-or-general-availability",
      "not-stage-4-under-30-second-readiness",
      "not-general-capacity",
      "no-isolation-claim-beyond-measured-sandbox",
      "custody-is-local-tamper-evidence-not-external-worm",
    ],
  };
}

// biome-ignore lint/suspicious/noExplicitAny: hostile mutations deliberately cross the closed evidence type
function reject(mutator: (value: Record<string, any>) => void, label: string): void {
  const value = fixture();
  mutator(value);
  assert.throws(() => validateAwsStage2CompletionEvidence(value), CompletionEvidenceValidationError, label);
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

test("closed v2 accepts exact seven cycles and renderer accepts only its validator token", () => {
  const value = fixture();
  const validated = validateAwsStage2CompletionEvidence(value);
  value.authority = "mutated-after-validation";
  assert.equal(
    validated.evidence.authority,
    "aws-stage2-completion",
    "validator token must hold an immutable snapshot",
  );
  assert.throws(() => {
    (validated.evidence as { authority: string }).authority = "mutated-token";
  }, TypeError);
  const report = renderAwsStage2CompletionReport(validated);
  assert.match(report, /Cycle 1|\| 1 \| full/u);
  assert.match(report, /Distinct independently observed zero receipts: 8/u);
  assert.doesNotMatch(report, /AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|arn:aws:|\bi-[0-9a-f]{8}/u);
  assert.throws(() => renderAwsStage2CompletionReport({ evidence: value } as never), /validator-issued/u);
  const canonicalValue = fixture();
  const raw = `${canonical(canonicalValue)}\n`;
  assert.deepEqual(parseAwsStage2CompletionEvidence(raw).evidence, canonicalValue);
  assert.throws(() => parseAwsStage2CompletionEvidence(raw.trim()), /final LF/u);
  assert.throws(() => parseAwsStage2CompletionEvidence(`${raw.slice(0, -2)}, \n`), CompletionEvidenceValidationError);
  assert.throws(() => parseAwsStage2CompletionEvidence('{"authority":"x","authority":"y"}\n'), /duplicate JSON key/u);
});

test("nearest-rank summaries, exact modes, durations, and cycle-1-only 21-row workload fail closed", () => {
  for (const field of ["min_ns", "p50_ns", "p95_ns", "max_ns"])
    reject((value) => {
      value.launch_summary[field] += 1;
    }, `launch ${field}`);
  for (const field of ["min_ns", "p50_ns", "p95_ns", "max_ns"])
    reject((value) => {
      value.ssh_ready_summary[field] += 1;
    }, `ssh ${field}`);
  for (const category of ["git", "build", "install"]) {
    for (const field of ["min_ns", "p50_ns", "p95_ns", "max_ns"])
      reject((value) => {
        value.workload_summary[category][field] += 1;
      }, `${category} ${field}`);
  }
  reject((value) => {
    value.cycles.pop();
  }, "six cycles");
  reject((value) => {
    value.cycles.push(structuredClone(value.cycles[6]));
  }, "eight cycles");
  reject((value) => {
    value.cycles[0].mode = "readiness";
  }, "wrong full ordinal");
  reject((value) => {
    value.cycles[1].workloads = {};
  }, "readiness workloads");
  reject((value) => {
    value.cycles[1].workloads = null;
  }, "readiness null workloads");
  reject((value) => {
    value.cycles[0].workloads.git.pop();
  }, "twenty workload rows");
  reject((value) => {
    value.cycles[0].workloads.git[0].deleted = false;
  }, "deletion proof");
  reject((value) => {
    value.cycles[0].workloads.git[1].output_commitment = digest("drift");
  }, "output drift");
  reject((value) => {
    value.cycles[0].workloads.git[0].cycle_receipt_commitment = digest("swap");
  }, "receipt swap");
  reject((value) => {
    value.cycles[2].effect_started_offset_ns = value.cycles[1].effect_ended_offset_ns - 1;
  }, "overlap");
  reject((value) => {
    value.cycles[6].effect_ended_offset_ns = 5_400_000_000_000;
  }, "effect settling at deadline");
  reject((value) => {
    value.cycles[6].effect_ended_offset_ns = 5_400_000_000_001;
  }, "deadline crossing");
});

test("eight fresh zeros, all private freshness domains, deadlines, and integer costs are recomputed", () => {
  reject((value) => {
    value.cleanup.final_zero_commitment = value.cleanup.cycle_zero_commitments[6];
  }, "copied cycle seven zero");
  reject((value) => {
    value.cleanup.cycle_zero_commitments[2] = value.cleanup.cycle_zero_commitments[1];
  }, "duplicate zero");
  reject((value) => {
    value.cycles[3].freshness.host_boot_commitment = value.cycles[2].freshness.host_boot_commitment;
  }, "freshness replay");
  reject((value) => {
    value.cycles[1].freshness.host_key_commitment = value.cycles[0].freshness.client_key_commitment;
  }, "cross-domain replay");
  reject((value) => {
    value.cycles[1].expiry_at = "2026-08-23T12:00:01Z";
  }, "expiry refresh");
  reject((value) => {
    value.deadlines.effect_deadline_at = "2026-08-23T11:30:01Z";
  }, "deadline drift");
  reject((value) => {
    value.deadlines.expiry_at = "2026-08-23T14:00:01Z";
    value.batch.expiry_at = value.deadlines.expiry_at;
    // biome-ignore lint/suspicious/noExplicitAny: hostile expiry mutation traverses an intentionally untyped fixture
    value.cycles.forEach((cycle: any) => {
      cycle.expiry_at = value.deadlines.expiry_at;
    });
  }, "over four hours");
  reject((value) => {
    value.cost.deadline_binding_commitment = digest("wrong-deadline");
  }, "cost deadline binding");
  reject((value) => {
    value.cycles[0].cost.compute_micro_usd += 1;
    value.cycles[0].cost.total_micro_usd += 1;
    value.cost.aggregate_cost_micro_usd += 1;
  }, "ceil mismatch");
  reject((value) => {
    value.cost.aggregate_effect_duration_ns += 1;
  }, "duration aggregate");
  reject((value) => {
    value.cost.expected_upper_bound_micro_usd = 250_000;
  }, "expected equality");
  reject((value) => {
    value.cost.aggregate_cost_micro_usd = 500_000;
  }, "publishable equality");
  reject((value) => {
    value.cost.rates_micro_usd_per_hour.compute = Number.MAX_SAFE_INTEGER + 1;
  }, "unsafe rate");
});

test("historical, local, fake, partial, extra, and every forbidden public string class are rejected", () => {
  for (const [version, authority] of [
    ["cogs.aws-stage2-measurement-evidence/v1alpha1", "aws-stage2-completion"],
    ["cogs.stage2-workload-local-qualification/v2", "aws-stage2-completion"],
    ["cogs.stage2-completion-fake-verdict/v1", "synthetic-private-test-model"],
    ["cogs.aws-stage2-completion-evidence/v2", "stage4-readiness"],
  ])
    reject((value) => {
      value.version = version;
      value.authority = authority;
    }, `${version}`);
  reject((value) => {
    value.unexpected = true;
  }, "extra property");
  reject((value) => {
    value.result = "failure";
  }, "failure result");
  const forbidden = [
    `AK${"IA"}ABCDEFGHIJKLMNOP`,
    `AS${"IA"}ABCDEFGHIJKLMNOP`,
    "authorization",
    "credential",
    "123456789012",
    "arn:aws:iam::123456789012:role/x",
    "i-deadbeef12345678",
    "vpc-deadbeef12345678",
    "subnet-deadbeef12345678",
    "sg-deadbeef12345678",
    "lt-deadbeef12345678",
    "vol-deadbeef12345678",
    "eni-deadbeef12345678",
    "123e4567-e89b-12d3-a456-426614174000",
    "owner@example.invalid",
    "192.0.2.1",
    "ssh-ed25519 AAAA",
    "SHA256:fingerprint",
    "https://example.invalid/x",
    "/private/custody",
    "tool --danger value",
  ];
  for (const sensitive of forbidden)
    reject((value) => {
      value.batch.commitment = sensitive;
    }, `redaction ${sensitive}`);
});

test("historical schema, validator, and renderer remain unchanged surfaces", () => {
  const root = resolve(process.cwd());
  assert.ok(
    readFileSync(resolve(root, "schemas/aws-stage2-measurement-evidence-v1alpha1.json"), "utf8").includes("v1alpha1"),
  );
  assert.match(
    readFileSync(resolve(root, "scripts/render-aws-stage2-completion-report.ts"), "utf8"),
    /evidenceFromValidated/u,
  );
  assert.doesNotMatch(
    readFileSync(resolve(root, "scripts/render-aws-stage2-completion-report.ts"), "utf8"),
    /provisional/u,
  );
});

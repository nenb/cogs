import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { renderAwsStage2CompletionReport } from "../scripts/render-aws-stage2-completion-report-v2.ts";
import {
  CompletionEvidenceValidationError,
  parseAwsStage2CompletionEvidence,
  validateAwsStage2CompletionEvidence,
} from "../scripts/validate-aws-stage2-completion-evidence-v2.ts";

const root = join(import.meta.dirname, "..");
let rawFixture: string | undefined;
function raw(): string {
  if (rawFixture !== undefined) return rawFixture;
  const result = spawnSync("python3", ["-I", "-B", join(root, "test/aws-stage2-completion-campaign-production.py")], {
    cwd: root,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      PYTHONDONTWRITEBYTECODE: "1",
      COGS_TEST_EMIT_EVIDENCE: "1",
    },
  });
  assert.equal(result.status, 0, result.stderr);
  rawFixture = result.stdout;
  return rawFixture;
}
function issuerReport(): string {
  const result = spawnSync("python3", ["-I", "-B", join(root, "test/aws-stage2-completion-campaign-production.py")], {
    cwd: root,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      PYTHONDONTWRITEBYTECODE: "1",
      COGS_TEST_EMIT_REPORT: "1",
    },
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}
// biome-ignore lint/suspicious/noExplicitAny: hostile mutations deliberately cross the validated contract
const fixture = (): Record<string, any> => structuredClone(JSON.parse(raw()));
// biome-ignore lint/suspicious/noExplicitAny: hostile mutations deliberately cross the validated contract
function reject(change: (value: Record<string, any>) => void, label: string): void {
  const value = fixture();
  change(value);
  assert.throws(() => validateAwsStage2CompletionEvidence(value), CompletionEvidenceValidationError, label);
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

test("closure-issued canonical v2 validates and renderer requires its validator token", () => {
  const validated = parseAwsStage2CompletionEvidence(raw());
  assert.equal(validated.evidence.result, "pass");
  assert.equal(validated.evidence.cycles.length, 7);
  assert.equal(validated.evidence.inventories.length, 8);
  assert.equal(validated.evidence.cycles[0]?.workloads?.length, 21);
  assert.equal(
    validated.evidence.cycles.slice(1).every((cycle) => cycle.workloads === undefined),
    true,
  );
  const report = renderAwsStage2CompletionReport(validated);
  assert.equal(report, issuerReport(), "public renderer must match the issuer's validated-token rendering");
  assert.match(report, /Cycles: 7 \(one full, six readiness\)/u);
  assert.match(report, /Detailed inventory observations: 8/u);
  assert.doesNotMatch(report, /arn:|AKIA|ASIA|\bi-[0-9a-f]{8}|\/var\//iu);
  assert.throws(() => renderAwsStage2CompletionReport({ evidence: fixture() } as never), /validator-issued/u);
  assert.throws(() => {
    (validated.evidence as { result: string }).result = "failure";
  }, TypeError);

  // Real Unix-nanosecond values exceed JavaScript's safe-integer range; the
  // contract retains them as exact decimal strings while durations stay numeric.
  const shifted = fixture();
  const delta = 1_800_000_000_000_000_000n;
  for (const field of ["first_apply_unix_ns", "effect_deadline_unix_ns", "expires_unix_ns", "final_zero_unix_ns"])
    shifted.deadlines[field] = (BigInt(shifted.deadlines[field]) + delta).toString();
  for (const cycle of shifted.cycles)
    for (const effect of Object.values(cycle.effects) as Array<Record<string, string>>)
      for (const field of ["observed_started_unix_ns", "observed_ended_unix_ns"]) {
        const timestamp = effect[field];
        assert.ok(timestamp);
        effect[field] = (BigInt(timestamp) + delta).toString();
      }
  for (const inventory of shifted.inventories)
    for (const field of ["observed_started_unix_ns", "observed_ended_unix_ns"])
      inventory[field] = (BigInt(inventory[field]) + delta).toString();
  validateAwsStage2CompletionEvidence(shifted);
});

test("final-zero order and actual wall duration include cleanup reserve without extending effects", () => {
  const value = fixture();
  assert.ok(value.deadlines.actual_campaign_duration_ns > value.cost.aggregate_effect_duration_ns);
  assert.ok(
    BigInt(value.deadlines.final_zero_unix_ns) > BigInt(value.cycles[6].effects.destroy.observed_ended_unix_ns),
  );
  assert.ok(BigInt(value.deadlines.final_zero_unix_ns) <= BigInt(value.deadlines.expires_unix_ns));
  reject((item) => {
    item.inventories[7].observed_started_unix_ns = item.inventories[6].observed_ended_unix_ns;
  }, "final inventory does not follow cycle seven");
  reject((item) => {
    item.deadlines.final_zero_unix_ns = item.cycles[6].effects.destroy.observed_ended_unix_ns;
    item.deadlines.actual_campaign_duration_ns = Number(
      BigInt(item.deadlines.final_zero_unix_ns) - BigInt(item.deadlines.first_apply_unix_ns),
    );
    item.inventories[7].observed_ended_unix_ns = item.deadlines.final_zero_unix_ns;
  }, "final zero before final destroy");
  reject((item) => {
    item.deadlines.actual_campaign_duration_ns += 1;
    item.cost.actual_campaign_duration_ns += 1;
  }, "fabricated wall duration");
  reject((item) => {
    item.cycles[6].effects.destroy.observed_ended_unix_ns = item.deadlines.effect_deadline_unix_ns;
  }, "normal effect at deadline");
});

test("seven cycles, 21 measurements, eight detailed inventories, common bindings and freshness fail closed", () => {
  reject((value) => {
    value.cycles.pop();
  }, "six cycles");
  reject((value) => {
    value.cycles[0].workloads.pop();
  }, "twenty workloads");
  reject((value) => {
    value.cycles[1].workloads = [];
  }, "readiness workload field");
  reject((value) => {
    value.cycles[3].mode = "full";
  }, "mode drift");
  reject((value) => {
    value.inventories.pop();
  }, "seven inventories");
  reject((value) => {
    value.inventories[2].pages.pop();
  }, "inventory category omission");
  reject((value) => {
    value.inventories[2].pages[0].next_token_commitment = value.bindings.ami_commitment;
  }, "truncated pagination");
  reject((value) => {
    value.inventories[4].observer_commitment = value.inventories[3].observer_commitment;
  }, "observer replay");
  reject((value) => {
    value.cycles[4].remote.instance_commitment = value.cycles[3].remote.instance_commitment;
  }, "instance replay");
  reject((value) => {
    value.cycles[4].effects.apply.state_commitment = value.cycles[3].effects.apply.state_commitment;
  }, "cycle state graft");
  reject((value) => {
    value.cycles[2].effects.running.state_lineage_commitment = value.bindings.runtime_commitment;
  }, "within-cycle lineage drift");
  reject((value) => {
    value.cycles[4].freshness.root_volume = value.cycles[3].freshness.root_volume;
  }, "root volume replay");
  reject((value) => {
    value.cycles[2].freshness.client_key = value.cycles[2].freshness.host_key;
  }, "within-cycle SSH key graft");
});

test("summaries and every typed receipt cost are independently recomputed", () => {
  for (const field of ["min_ns", "p50_ns", "p95_ns", "max_ns"])
    reject((value) => {
      value.launch_summary[field] += 1;
    }, `launch ${field}`);
  for (const category of ["git", "build", "install"])
    reject((value) => {
      value.workload_summaries[category].p95_ns += 1;
    }, `${category} p95`);
  reject((value) => {
    value.cycles[0].cost.cost_micro_usd += 1;
    value.cost.aggregate_cost_micro_usd += 1;
  }, "cycle ceil cost");
  reject((value) => {
    value.cycles[0].cost.billable_duration_ns += 1;
  }, "billable duration");
  reject((value) => {
    value.cost.aggregate_effect_duration_ns += 1;
  }, "aggregate duration");
  reject((value) => {
    value.cost.aggregate_cost_micro_usd = value.cost.approved_maximum_micro_usd + 1;
  }, "approval maximum");
  reject((value) => {
    value.cost.aggregate_rate_micro_usd_per_hour = 118001;
  }, "fixed price drift");
});

test("failure authority, sensitive strings, noncanonical bytes, and duplicate keys are rejected", () => {
  reject((value) => {
    value.result = "failure";
  }, "failure publication");
  reject((value) => {
    value.version = "cogs.stage2-completion-synthetic-custody-verdict/v1";
  }, "synthetic version");
  for (const sensitive of [
    "arn:aws:iam::123456789012:role/x",
    "AKIAABCDEFGHIJKLMNOP",
    "i-deadbeef12345678",
    "192.0.2.1",
    "/var/lib/custody",
    "https://example.invalid/x",
  ])
    reject((value) => {
      value.batch.commitment = sensitive;
    }, sensitive);
  assert.throws(() => parseAwsStage2CompletionEvidence(raw().trim()), /final LF/u);
  assert.throws(() => parseAwsStage2CompletionEvidence(` ${raw()}`), /canonical JSON/u);
  assert.throws(
    () => parseAwsStage2CompletionEvidence('{"result":"pass","result":"failure"}\n'),
    /duplicate JSON key/u,
  );
  const value = fixture();
  assert.equal(raw(), `${canonical(value)}\n`);
});

test("issuer source accepts no public mapping and historical evidence remains additive", () => {
  const source = readFileSync(join(root, "deploy/aws-feasibility/completion_campaign_evidence_issuer.py"), "utf8");
  assert.match(source, /retained\.pop\(id\(candidate\), None\) is candidate/u);
  assert.match(source, /candidate\.execution_authority == "authenticated-aws-adapter"/u);
  assert.match(source, /def _project_test_candidate/u);
  assert.doesNotMatch(source, /^_RETAINED\s*=/mu);
  assert.match(source, /type\(candidate\) is production\.CampaignCandidate/u);
  assert.doesNotMatch(source, /def issue_completion_evidence\([^)]*(?:dict|mapping|json)/iu);
  assert.match(source, /os\.link\(staging, final/u);
  assert.match(source, /_readback\(custody, EVIDENCE_NAME, evidence\)/u);
  assert.ok(
    readFileSync(join(root, "schemas/aws-stage2-measurement-evidence-v1alpha1.json"), "utf8").includes("v1alpha1"),
  );
});

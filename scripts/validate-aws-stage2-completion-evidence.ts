import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const schema = JSON.parse(
  readFileSync(resolve(root, "schemas/aws-stage2-completion-evidence-v1.json"), "utf8"),
) as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, ownProperties: true });
addFormats(ajv);
const schemaValidator = ajv.compile(schema) as ValidateFunction<CompletionEvidence>;

const MAX_EVIDENCE_BYTES = 128 * 1024;
const BILLING_HOUR_NS = 3_600_000_000_000n;
const NORMAL_DEADLINE_NS = 5_400_000_000_000;
const MODES = ["full", "readiness", "readiness", "readiness", "readiness", "readiness", "readiness"] as const;
const FRESHNESS_FIELDS = [
  "instance_commitment",
  "root_volume_commitment",
  "launch_template_generation_commitment",
  "host_boot_commitment",
  "operation_commitment",
  "client_key_commitment",
  "host_key_commitment",
  "pre_destroy_receipt_commitment",
] as const;
const LIMITATIONS = [
  "standalone-stage-2-only",
  "not-eks-or-kubernetes",
  "not-production-release-or-general-availability",
  "not-stage-4-under-30-second-readiness",
  "not-general-capacity",
  "no-isolation-claim-beyond-measured-sandbox",
  "custody-is-local-tamper-evidence-not-external-worm",
] as const;

export type Summary = {
  samples_ns: number[];
  min_ns: number;
  p50_ns: number;
  p95_ns: number;
  max_ns: number;
};
type WorkloadRow = {
  ordinal: number;
  duration_ns: number;
  output_commitment: string;
  deleted: true;
  cycle_receipt_commitment: string;
};
type Cycle = {
  ordinal: number;
  mode: "full" | "readiness";
  cycle_commitment: string;
  receipt_commitment: string;
  expiry_at: string;
  deadline_binding_commitment: string;
  effect_started_offset_ns: number;
  effect_ended_offset_ns: number;
  duration_ns: number;
  apply_to_running_ns: number;
  kata_launch_to_ssh_ready_ns: number;
  freshness: Record<(typeof FRESHNESS_FIELDS)[number], string>;
  workloads?: Record<"git" | "build" | "install", WorkloadRow[]>;
  destroy_commitment: string;
  zero_inventory_commitment: string;
  cost: {
    billable_duration_ns: number;
    compute_micro_usd: number;
    public_ipv4_micro_usd: number;
    gp3_micro_usd: number;
    support_allowance_micro_usd: number;
    total_micro_usd: number;
  };
};
export type CompletionEvidence = {
  version: "cogs.aws-stage2-completion-evidence/v1";
  authority: "aws-stage2-completion";
  result: "pass";
  batch: { commitment: string; source_revision: string; expiry_at: string; cycle_count: 7; modes: string[] };
  bindings: Record<string, string>;
  deadlines: {
    first_apply_started_at: string;
    effect_deadline_at: string;
    expiry_at: string;
    normal_effect_deadline_seconds: 5400;
    cleanup_reserve_seconds: number;
    binding_commitment: string;
  };
  cycles: Cycle[];
  launch_summary: Summary;
  ssh_ready_summary: Summary;
  workload_summary: {
    cycle_ordinal: 1;
    receipt_commitment: string;
    git: Summary & { output_commitment: string };
    build: Summary & { output_commitment: string };
    install: Summary & { output_commitment: string };
  };
  cleanup: {
    cycle_zero_commitments: string[];
    final_zero_commitment: string;
    zero_receipt_count: 8;
    destroy_attempts: 7;
    inventory_observations: 8;
    teardown_phase_count: 13;
  };
  cost: {
    rate_table_commitment: string;
    price_evidence_commitment: string;
    deadline_binding_commitment: string;
    rates_micro_usd_per_hour: Record<"compute" | "public_ipv4" | "gp3" | "support_allowance", number>;
    expected_upper_bound_micro_usd: number;
    aggregate_duration_ns: number;
    aggregate_cost_micro_usd: number;
  };
  limitations: string[];
};

export class CompletionEvidenceValidationError extends Error {}

const validatedObjects = new WeakSet<object>();
export type ValidatedCompletionEvidence = { readonly evidence: CompletionEvidence };

function fail(message: string): never {
  throw new CompletionEvidenceValidationError(message);
}
function requireThat(condition: boolean, message: string): asserts condition {
  if (!condition) fail(message);
}
function distinct(values: string[], label: string): void {
  requireThat(new Set(values).size === values.length, `${label} commitments must be pairwise distinct`);
}
function summary(samples: number[]): Summary {
  const sorted = [...samples].sort((left, right) => left - right);
  const first = sorted[0];
  const fourth = sorted[3];
  const seventh = sorted[6];
  assert.ok(first !== undefined && fourth !== undefined && seventh !== undefined);
  return { samples_ns: samples, min_ns: first, p50_ns: fourth, p95_ns: seventh, max_ns: seventh };
}
function validateSummary(actual: Summary, samples: number[], label: string): void {
  const expected = summary(samples);
  requireThat(
    actual.samples_ns.length === 7 && actual.samples_ns.every((value, index) => value === samples[index]),
    `${label} samples mismatch`,
  );
  for (const key of ["min_ns", "p50_ns", "p95_ns", "max_ns"] as const) {
    requireThat(actual[key] === expected[key], `${label} ${key} nearest-rank mismatch`);
  }
}
function ceilCost(duration: number, rate: number): number {
  const numerator = BigInt(duration) * BigInt(rate);
  const result = (numerator + BILLING_HOUR_NS - 1n) / BILLING_HOUR_NS;
  requireThat(result <= BigInt(Number.MAX_SAFE_INTEGER), "cost arithmetic overflow");
  return Number(result);
}
function validateJsonGraph(value: unknown): void {
  const seen = new WeakSet<object>();
  let nodes = 0;
  const visit = (item: unknown, depth: number): void => {
    nodes += 1;
    requireThat(nodes <= 8_192 && depth <= 24, "public evidence graph bound exceeded");
    if (item === null || typeof item === "boolean") return;
    if (typeof item === "number") {
      requireThat(Number.isSafeInteger(item), "non-safe or non-integer number rejected");
      return;
    }
    if (typeof item === "string") {
      requireThat(Buffer.byteLength(item, "utf8") <= 16_384, "public string bound exceeded");
      return;
    }
    requireThat(typeof item === "object", "non-JSON public value rejected");
    requireThat(!seen.has(item), "cyclic or aliased public object rejected");
    seen.add(item);
    if (Array.isArray(item)) {
      requireThat(item.length <= 512, "public array bound exceeded");
      for (const child of item) visit(child, depth + 1);
      return;
    }
    const prototype = Object.getPrototypeOf(item);
    requireThat(prototype === Object.prototype || prototype === null, "non-plain public object rejected");
    const values = Object.values(item);
    requireThat(values.length <= 128, "public object-property bound exceeded");
    for (const child of values) visit(child, depth + 1);
  };
  visit(value, 0);
}
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

const sensitivePatterns: ReadonlyArray<[string, RegExp]> = [
  ["AWS access key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u],
  ["authorization material", /\b(?:authorization|bearer|credential|secret|private[-_ ]?key)\b/iu],
  ["account number", /^\d{12}$/u],
  ["ARN", /^arn:[^\s]+$/iu],
  ["cloud resource identifier", /^(?:i|vpc|subnet|sg|lt|vol|eni|mi)-[0-9a-f]{8,}$/iu],
  ["command identifier", /^(?:cmd-)?[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu],
  ["email", /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/iu],
  ["IP address", /^(?:\d{1,3}\.){3}\d{1,3}$/u],
  ["key material or fingerprint", /(?:-----BEGIN|ssh-ed25519|SHA256:)/u],
  ["URL", /^[a-z][a-z0-9+.-]*:\/\//iu],
  ["path", /^(?:\/|\.\.\/|[A-Za-z]:\\)/u],
  ["shell command material", /(?:\$\(|`|\s(?:--?[a-z][a-z-]*)(?:\s|=))/iu],
];
function scanSensitive(value: unknown, location = "/"): void {
  if (typeof value === "string") {
    for (const [label, pattern] of sensitivePatterns)
      requireThat(!pattern.test(value), `${location}: forbidden ${label}`);
    requireThat(
      [...value].every((character) => {
        const point = character.codePointAt(0) ?? -1;
        return point >= 0x20 && point <= 0x7e;
      }),
      `${location}: non-ASCII public string`,
    );
  } else if (Array.isArray(value)) {
    value.forEach((item, index) => {
      scanSensitive(item, `${location}${index}/`);
    });
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) scanSensitive(item, `${location}${key}/`);
  }
}

function validateSemantics(evidence: CompletionEvidence): void {
  scanSensitive(evidence);
  requireThat(
    evidence.batch.modes.every((mode, index) => mode === MODES[index]),
    "fixed mode vector mismatch",
  );
  requireThat(
    evidence.limitations.every((item, index) => item === LIMITATIONS[index]),
    "fixed limitations mismatch",
  );
  distinct(Object.values(evidence.bindings), "binding");

  const started = Date.parse(evidence.deadlines.first_apply_started_at);
  const deadline = Date.parse(evidence.deadlines.effect_deadline_at);
  const expiry = Date.parse(evidence.deadlines.expiry_at);
  requireThat(
    Number.isFinite(started) && deadline === started + 5_400_000,
    "normal deadline must be exactly 5,400 seconds",
  );
  requireThat(expiry > deadline + evidence.deadlines.cleanup_reserve_seconds * 1000, "expiry lacks cleanup reserve");
  requireThat(expiry - started <= 14_400_000, "expiry exceeds four hours from first apply");
  requireThat(evidence.batch.expiry_at === evidence.deadlines.expiry_at, "batch expiry binding mismatch");

  const cycleCommitments: string[] = [];
  const receiptCommitments: string[] = [];
  const destroyCommitments: string[] = [];
  const zeroCommitments: string[] = [];
  const allFreshness: string[] = [];
  let priorEnd = 0;
  for (const [index, cycle] of evidence.cycles.entries()) {
    requireThat(
      cycle.ordinal === index + 1 && cycle.mode === MODES[index],
      `cycle ${index + 1} ordering or mode mismatch`,
    );
    requireThat(
      (index === 0 && cycle.effect_started_offset_ns === 0) || cycle.effect_started_offset_ns >= priorEnd,
      `cycle ${index + 1} overlaps its predecessor`,
    );
    requireThat(
      cycle.effect_ended_offset_ns > cycle.effect_started_offset_ns &&
        cycle.effect_ended_offset_ns < NORMAL_DEADLINE_NS,
      `cycle ${index + 1} crosses the normal deadline`,
    );
    requireThat(
      cycle.duration_ns === cycle.effect_ended_offset_ns - cycle.effect_started_offset_ns,
      `cycle ${index + 1} duration binding mismatch`,
    );
    requireThat(
      cycle.apply_to_running_ns <= cycle.duration_ns && cycle.kata_launch_to_ssh_ready_ns <= cycle.duration_ns,
      `cycle ${index + 1} sample exceeds cycle duration`,
    );
    requireThat(
      cycle.expiry_at === evidence.deadlines.expiry_at &&
        cycle.deadline_binding_commitment === evidence.deadlines.binding_commitment,
      `cycle ${index + 1} deadline or expiry drift`,
    );
    requireThat(cycle.cost.billable_duration_ns === cycle.duration_ns, `cycle ${index + 1} billing duration mismatch`);
    priorEnd = cycle.effect_ended_offset_ns;
    cycleCommitments.push(cycle.cycle_commitment);
    receiptCommitments.push(cycle.receipt_commitment);
    destroyCommitments.push(cycle.destroy_commitment);
    zeroCommitments.push(cycle.zero_inventory_commitment);
    allFreshness.push(...FRESHNESS_FIELDS.map((field) => cycle.freshness[field]));

    if (index === 0) {
      requireThat(cycle.workloads !== undefined, "full cycle workloads missing");
      for (const category of ["git", "build", "install"] as const) {
        const rows = cycle.workloads[category];
        requireThat(rows.length === 7, `${category} requires seven rows`);
        for (const [rowIndex, row] of rows.entries()) {
          requireThat(
            row.ordinal === rowIndex + 1 && row.deleted === true,
            `${category} row ordering or deletion mismatch`,
          );
          requireThat(
            row.cycle_receipt_commitment === cycle.receipt_commitment,
            `${category} receipt binding mismatch`,
          );
        }
      }
    } else requireThat(cycle.workloads === undefined, `readiness cycle ${index + 1} contains workloads`);
  }
  for (const [fieldIndex, field] of FRESHNESS_FIELDS.entries()) {
    distinct(
      evidence.cycles.map((cycle) => cycle.freshness[field]),
      `freshness ${fieldIndex + 1}`,
    );
  }
  distinct(allFreshness, "domain-separated freshness");
  distinct(cycleCommitments, "cycle");
  distinct(receiptCommitments, "cycle receipt");
  distinct(destroyCommitments, "destroy");
  distinct(zeroCommitments, "cycle zero");
  distinct([...zeroCommitments, evidence.cleanup.final_zero_commitment], "all eight zero receipt");
  requireThat(
    evidence.cleanup.cycle_zero_commitments.every((value, index) => value === zeroCommitments[index]),
    "cleanup cycle-zero projection mismatch",
  );

  validateSummary(
    evidence.launch_summary,
    evidence.cycles.map((cycle) => cycle.apply_to_running_ns),
    "launch summary",
  );
  validateSummary(
    evidence.ssh_ready_summary,
    evidence.cycles.map((cycle) => cycle.kata_launch_to_ssh_ready_ns),
    "SSH-ready summary",
  );
  const full = evidence.cycles[0];
  assert.ok(full?.workloads);
  requireThat(
    evidence.workload_summary.receipt_commitment === full.receipt_commitment,
    "workload summary receipt mismatch",
  );
  for (const category of ["git", "build", "install"] as const) {
    const rows = full.workloads[category];
    const output = rows[0]?.output_commitment;
    assert.ok(output);
    requireThat(
      rows.every((row) => row.output_commitment === output),
      `${category} output pin drift`,
    );
    requireThat(
      evidence.workload_summary[category].output_commitment === output,
      `${category} summary output mismatch`,
    );
    validateSummary(
      evidence.workload_summary[category],
      rows.map((row) => row.duration_ns),
      `${category} summary`,
    );
  }

  requireThat(
    evidence.cost.rate_table_commitment === evidence.bindings.rate_table_commitment,
    "rate-table binding mismatch",
  );
  requireThat(
    evidence.cost.deadline_binding_commitment === evidence.deadlines.binding_commitment,
    "deadline-cost binding mismatch",
  );
  let aggregateDuration = 0;
  let aggregateCost = 0;
  for (const cycle of evidence.cycles) {
    const expected = {
      compute_micro_usd: ceilCost(cycle.duration_ns, evidence.cost.rates_micro_usd_per_hour.compute),
      public_ipv4_micro_usd: ceilCost(cycle.duration_ns, evidence.cost.rates_micro_usd_per_hour.public_ipv4),
      gp3_micro_usd: ceilCost(cycle.duration_ns, evidence.cost.rates_micro_usd_per_hour.gp3),
      support_allowance_micro_usd: ceilCost(
        cycle.duration_ns,
        evidence.cost.rates_micro_usd_per_hour.support_allowance,
      ),
    };
    for (const [field, value] of Object.entries(expected))
      requireThat(cycle.cost[field as keyof typeof expected] === value, `cycle ${cycle.ordinal} ${field} mismatch`);
    const total = Object.values(expected).reduce((sum, value) => sum + value, 0);
    requireThat(cycle.cost.total_micro_usd === total, `cycle ${cycle.ordinal} total cost mismatch`);
    aggregateDuration += cycle.duration_ns;
    aggregateCost += total;
  }
  requireThat(evidence.cost.aggregate_duration_ns === aggregateDuration, "aggregate duration mismatch");
  requireThat(evidence.cost.aggregate_cost_micro_usd === aggregateCost, "aggregate cost mismatch");
  requireThat(
    evidence.cost.expected_upper_bound_micro_usd >= aggregateCost &&
      evidence.cost.expected_upper_bound_micro_usd < 250_000,
    "expected cost gate mismatch",
  );
  requireThat(aggregateCost < 500_000, "publishable cost gate mismatch");
}

export function validateAwsStage2CompletionEvidence(value: unknown): ValidatedCompletionEvidence {
  let snapshot: unknown;
  try {
    snapshot = structuredClone(value);
  } catch (error) {
    throw new CompletionEvidenceValidationError("public evidence cannot be snapshotted", { cause: error });
  }
  validateJsonGraph(snapshot);
  if (!schemaValidator(snapshot)) {
    const details = (schemaValidator.errors ?? [])
      .map((error) => `${error.instancePath || "/"}: ${error.message ?? error.keyword}`)
      .join("\n");
    fail(details || "completion evidence schema rejected");
  }
  validateSemantics(snapshot);
  const token = Object.freeze({ evidence: deepFreeze(snapshot) });
  validatedObjects.add(token);
  return token;
}

export function evidenceFromValidated(value: ValidatedCompletionEvidence): CompletionEvidence {
  requireThat(
    typeof value === "object" && value !== null && validatedObjects.has(value),
    "renderer requires validator-issued evidence token",
  );
  return value.evidence;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function rejectDuplicateKeys(text: string): void {
  let offset = 0;
  const whitespace = () => {
    while (/\s/u.test(text[offset] ?? "")) offset += 1;
  };
  const stringToken = (): string => {
    const start = offset;
    requireThat(text[offset] === '"', "JSON string expected");
    offset += 1;
    while (offset < text.length) {
      if (text[offset] === "\\") {
        offset += 2;
        continue;
      }
      if (text[offset] === '"') {
        offset += 1;
        return JSON.parse(text.slice(start, offset)) as string;
      }
      offset += 1;
    }
    return fail("unterminated JSON string");
  };
  const value = (): void => {
    whitespace();
    if (text[offset] === "{") {
      offset += 1;
      whitespace();
      const keys = new Set<string>();
      if (text[offset] === "}") {
        offset += 1;
        return;
      }
      while (true) {
        whitespace();
        const key = stringToken();
        requireThat(!keys.has(key), `duplicate JSON key ${key}`);
        keys.add(key);
        whitespace();
        requireThat(text[offset] === ":", "JSON colon expected");
        offset += 1;
        value();
        whitespace();
        if (text[offset] === "}") {
          offset += 1;
          return;
        }
        requireThat(text[offset] === ",", "JSON object comma expected");
        offset += 1;
      }
    }
    if (text[offset] === "[") {
      offset += 1;
      whitespace();
      if (text[offset] === "]") {
        offset += 1;
        return;
      }
      while (true) {
        value();
        whitespace();
        if (text[offset] === "]") {
          offset += 1;
          return;
        }
        requireThat(text[offset] === ",", "JSON array comma expected");
        offset += 1;
      }
    }
    if (text[offset] === '"') {
      stringToken();
      return;
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(text.slice(offset));
    requireThat(match !== null, "JSON value expected");
    offset += match[0].length;
  };
  value();
  whitespace();
  requireThat(offset === text.length, "trailing JSON data");
}

export function parseAwsStage2CompletionEvidence(raw: string): ValidatedCompletionEvidence {
  requireThat(Buffer.byteLength(raw, "utf8") <= MAX_EVIDENCE_BYTES, "completion evidence byte bound exceeded");
  requireThat(raw.endsWith("\n") && !raw.endsWith("\n\n"), "canonical evidence requires one final LF");
  const body = raw.slice(0, -1);
  rejectDuplicateKeys(body);
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch (error) {
    throw new CompletionEvidenceValidationError("invalid completion evidence JSON", { cause: error });
  }
  requireThat(`${canonical(value)}\n` === raw, "completion evidence is not canonical JSON");
  return validateAwsStage2CompletionEvidence(value);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const path = process.argv[2];
  assert.ok(path && process.argv.length === 3, "usage: validate-aws-stage2-completion-evidence.ts EVIDENCE_JSON");
  parseAwsStage2CompletionEvidence(readFileSync(resolve(path), "utf8"));
  console.log("Validated closed AWS Stage 2 completion evidence v1.");
}

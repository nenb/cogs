import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const schema = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../schemas/aws-stage2-completion-evidence-v2.json"), "utf8"),
) as object;
const schemaValidator = new Ajv2020({ allErrors: true, strict: true, ownProperties: true }).compile(
  schema,
) as ValidateFunction<CompletionEvidence>;

const BILLING_HOUR_NS = 3_600_000_000_000n;
const MODES = ["full", "readiness", "readiness", "readiness", "readiness", "readiness", "readiness"] as const;
const CATEGORIES = [
  "ec2_instances",
  "ebs_volumes",
  "network_interfaces",
  "eni_public_associations",
  "elastic_ips",
  "security_groups",
  "vpcs",
  "subnets",
  "internet_gateways",
  "route_tables",
  "routes",
  "launch_templates",
  "key_pairs",
  "iam_roles",
  "iam_role_policies",
  "iam_policy_attachments",
  "iam_instance_profiles",
  "eventbridge_schedules",
  "eventbridge_targets",
  "budgets",
  "ssm_managed_instances",
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
const EFFECTS = ["plan", "apply", "running", "destroy"] as const;

export type Summary = { samples_ns: number[]; min_ns: number; p50_ns: number; p95_ns: number; max_ns: number };
type Effect = {
  intent_commitment: string;
  settlement_commitment: string;
  identity_commitment: string;
  state_commitment: string;
  state_lineage_commitment: string;
  observed_started_unix_ns: string;
  observed_ended_unix_ns: string;
};
type Cycle = {
  ordinal: number;
  mode: string;
  grant_commitment: string;
  cycle_commitment: string;
  plan_sha256: string;
  effects: Record<(typeof EFFECTS)[number], Effect>;
  freshness: Record<
    | "instance"
    | "root_volume"
    | "launch_template_generation"
    | "host_boot"
    | "operation"
    | "client_key"
    | "host_key"
    | "pre_destroy_receipt",
    string
  >;
  remote: {
    host_receipt_commitment: string;
    instance_commitment: string;
    operation_commitment: string;
    host_boot_commitment: string;
    apply_to_running_ns: number;
    kata_launch_to_ssh_ready_ns: number;
  };
  workloads?: Array<{ category: string; ordinal: number; duration_ns: number; commitment: string }>;
  zero_inventory_commitment: string;
  cost: {
    receipt_commitment: string;
    rate_source_commitment: string;
    usage_commitment: string;
    billable_duration_ns: number;
    cost_micro_usd: number;
  };
};
type Inventory = {
  observation_sequence: number;
  cycle_ordinal: number | null;
  observer_commitment: string;
  session_commitment: string;
  run_commitment: string;
  account_commitment: string;
  region_commitment: string;
  destroyed_state_commitment: string;
  observed_started_unix_ns: string;
  observed_ended_unix_ns: string;
  zero_commitment: string;
  pages: Array<{
    category: string;
    ordinal: number;
    request_token_commitment: string | null;
    next_token_commitment: string | null;
    page_commitment: string;
    resources: Array<{ identity_commitment: string; disposition: string; public_address_commitment: string | null }>;
  }>;
};
export type CompletionEvidence = {
  version: "cogs.aws-stage2-completion-evidence/v2";
  authority: "aws-stage2-completion";
  result: "pass";
  batch: {
    commitment: string;
    implementation_revision: string;
    control_revision: string;
    consumption_commitment: string;
    custody_root: string;
    cycle_count: 7;
    modes: string[];
  };
  bindings: Record<string, string>;
  deadlines: {
    first_apply_unix_ns: string;
    effect_deadline_unix_ns: string;
    cleanup_reserve_ns: number;
    expires_unix_ns: string;
    final_zero_unix_ns: string;
    actual_campaign_duration_ns: number;
  };
  cycles: Cycle[];
  inventories: Inventory[];
  launch_summary: Summary;
  ssh_ready_summary: Summary;
  workload_summaries: Record<"git" | "build" | "install", Summary>;
  cleanup: {
    destroy_attempts: 7;
    inventory_observations: 8;
    cycle_zero_commitments: string[];
    final_zero_commitment: string;
    inventory_categories: string[];
  };
  cost: {
    currency: "micro-USD";
    rate_components_micro_usd_per_hour: Record<string, number>;
    aggregate_rate_micro_usd_per_hour: number;
    rate_source_commitment: string;
    aggregate_effect_duration_ns: number;
    actual_campaign_duration_ns: number;
    aggregate_cost_micro_usd: number;
    approved_maximum_micro_usd: number;
  };
  limitations: string[];
};

export class CompletionEvidenceValidationError extends Error {}
const validatedObjects = new WeakSet<object>();
export type ValidatedCompletionEvidence = { readonly evidence: CompletionEvidence };

function fail(message: string): never {
  throw new CompletionEvidenceValidationError(message);
}
function check(value: boolean, message: string): asserts value {
  if (!value) fail(message);
}
function distinct(values: string[], label: string): void {
  check(new Set(values).size === values.length, `${label} commitments must be pairwise distinct`);
}
function summary(samples: number[]): Summary {
  const sorted = [...samples].sort((a, b) => a - b);
  const minimum = sorted[0];
  const median = sorted[3];
  const maximum = sorted[6];
  check(
    samples.length === 7 && minimum !== undefined && median !== undefined && maximum !== undefined,
    "summary cardinality",
  );
  return { samples_ns: samples, min_ns: minimum, p50_ns: median, p95_ns: maximum, max_ns: maximum };
}
function checkSummary(actual: Summary, samples: number[], label: string): void {
  const expected = summary(samples);
  check(
    actual.samples_ns.every((value, index) => value === samples[index]),
    `${label} samples mismatch`,
  );
  for (const key of ["min_ns", "p50_ns", "p95_ns", "max_ns"] as const)
    check(actual[key] === expected[key], `${label} ${key} mismatch`);
}
function ceilCost(duration: number, rate: number): number {
  return Number((BigInt(duration) * BigInt(rate) + BILLING_HOUR_NS - 1n) / BILLING_HOUR_NS);
}
function unixNs(value: string): bigint {
  const parsed = BigInt(value);
  check(parsed <= 18_446_744_073_709_551_615n, "Unix nanosecond value exceeds uint64");
  return parsed;
}
function elapsedNs(ended: string, started: string, label: string): number {
  const value = unixNs(ended) - unixNs(started);
  check(value > 0n && value <= BigInt(Number.MAX_SAFE_INTEGER), `${label} elapsed range`);
  return Number(value);
}
function graph(value: unknown): void {
  const seen = new WeakSet<object>();
  let nodes = 0;
  const visit = (item: unknown, depth: number): void => {
    check(++nodes <= 16_384 && depth <= 24, "public evidence graph bound exceeded");
    if (item === null || typeof item === "boolean") return;
    if (typeof item === "number") {
      check(Number.isSafeInteger(item), "unsafe public integer");
      return;
    }
    if (typeof item === "string") {
      check(Buffer.byteLength(item) <= 16_384, "public string bound");
      return;
    }
    check(typeof item === "object" && !seen.has(item), "non-JSON, cyclic, or aliased public value");
    seen.add(item);
    if (Array.isArray(item)) {
      check(item.length <= 1024, "public array bound");
      for (const child of item) visit(child, depth + 1);
    } else {
      check(
        Object.getPrototypeOf(item) === Object.prototype || Object.getPrototypeOf(item) === null,
        "non-plain public object",
      );
      check(Object.keys(item).length <= 128, "public property bound");
      for (const child of Object.values(item)) visit(child, depth + 1);
    }
  };
  visit(value, 0);
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function scan(value: unknown, location = "/"): void {
  if (typeof value === "string") {
    const forbidden = [
      /(?:AKIA|ASIA)[A-Z0-9]{16}/u,
      /arn:/iu,
      /-----BEGIN/u,
      /ssh-ed25519/u,
      /^(?:i|vpc|subnet|sg|lt|vol|eni)-[0-9a-f]{8,}$/iu,
      /^\d{12}$/u,
      /^(?:\/|\.\.\/)/u,
      /^[a-z][a-z0-9+.-]*:\/\//iu,
      /^(?:\d{1,3}\.){3}\d{1,3}$/u,
    ];
    check(
      forbidden.every((pattern) => !pattern.test(value)),
      `${location}: forbidden sensitive string`,
    );
    check(
      [...value].every((character) => {
        const point = character.codePointAt(0);
        return point !== undefined && point >= 0x20 && point <= 0x7e;
      }),
      `${location}: non-ASCII string`,
    );
  } else if (Array.isArray(value))
    value.forEach((item, index) => {
      scan(item, `${location}${index}/`);
    });
  else if (value !== null && typeof value === "object")
    for (const [key, item] of Object.entries(value)) scan(item, `${location}${key}/`);
}

function semantics(e: CompletionEvidence): void {
  scan(e);
  check(
    e.batch.modes.every((mode, index) => mode === MODES[index]),
    "fixed mode vector mismatch",
  );
  check(
    e.limitations.every((item, index) => item === LIMITATIONS[index]),
    "fixed limitations mismatch",
  );
  const firstApply = unixNs(e.deadlines.first_apply_unix_ns);
  const effectDeadline = unixNs(e.deadlines.effect_deadline_unix_ns);
  const expiry = unixNs(e.deadlines.expires_unix_ns);
  const finalZero = unixNs(e.deadlines.final_zero_unix_ns);
  check(effectDeadline > firstApply, "effect deadline order");
  check(effectDeadline + BigInt(e.deadlines.cleanup_reserve_ns) <= expiry, "cleanup reserve exceeds expiry");
  check(finalZero <= expiry, "final zero exceeds expiry");
  check(
    e.deadlines.actual_campaign_duration_ns ===
      elapsedNs(e.deadlines.final_zero_unix_ns, e.deadlines.first_apply_unix_ns, "actual campaign"),
    "actual wall duration mismatch",
  );

  const cycleCommitments: string[] = [];
  const grants: string[] = [];
  const plans: string[] = [];
  const states: string[] = [];
  const lineages: string[] = [];
  const instances: string[] = [];
  const hostReceipts: string[] = [];
  const operations: string[] = [];
  const boots: string[] = [];
  const settlements: string[] = [];
  const freshnessNames = [
    "instance",
    "root_volume",
    "launch_template_generation",
    "host_boot",
    "operation",
    "client_key",
    "host_key",
    "pre_destroy_receipt",
  ] as const;
  const freshness = Object.fromEntries(freshnessNames.map((name) => [name, [] as string[]])) as Record<
    (typeof freshnessNames)[number],
    string[]
  >;
  let priorZeroEnd = 0n;
  let aggregateDuration = 0;
  let aggregateCost = 0;
  for (const [index, cycle] of e.cycles.entries()) {
    check(cycle.ordinal === index + 1 && cycle.mode === MODES[index], `cycle ${index + 1} mode/order`);
    cycleCommitments.push(cycle.cycle_commitment);
    grants.push(cycle.grant_commitment);
    plans.push(cycle.plan_sha256);
    states.push(cycle.effects.apply.state_commitment);
    lineages.push(cycle.effects.apply.state_lineage_commitment);
    instances.push(cycle.remote.instance_commitment);
    hostReceipts.push(cycle.remote.host_receipt_commitment);
    operations.push(cycle.remote.operation_commitment);
    boots.push(cycle.remote.host_boot_commitment);
    distinct(Object.values(cycle.freshness), `cycle ${index + 1} within-cycle freshness`);
    for (const name of freshnessNames) freshness[name].push(cycle.freshness[name]);
    const { plan, apply, running, destroy } = cycle.effects;
    let priorEffectEnd: bigint | undefined;
    for (const name of EFFECTS) {
      const started = unixNs(cycle.effects[name].observed_started_unix_ns);
      const ended = unixNs(cycle.effects[name].observed_ended_unix_ns);
      check(
        started < ended && (priorEffectEnd === undefined || started > priorEffectEnd),
        `cycle ${index + 1} effect order`,
      );
      priorEffectEnd = ended;
    }
    check(priorEffectEnd !== undefined && priorEffectEnd < effectDeadline, `cycle ${index + 1} effect deadline`);
    check(
      EFFECTS.every(
        (name) =>
          cycle.effects[name].state_commitment === plan.state_commitment &&
          cycle.effects[name].state_lineage_commitment === plan.state_lineage_commitment,
      ),
      `cycle ${index + 1} state lineage`,
    );
    settlements.push(...EFFECTS.map((name) => cycle.effects[name].settlement_commitment));
    const duration = elapsedNs(destroy.observed_ended_unix_ns, apply.observed_started_unix_ns, `cycle ${index + 1}`);
    check(cycle.cost.billable_duration_ns === duration, `cycle ${index + 1} billable duration`);
    check(
      cycle.remote.apply_to_running_ns ===
        elapsedNs(running.observed_ended_unix_ns, apply.observed_started_unix_ns, `cycle ${index + 1} running`),
      `cycle ${index + 1} provider wall sample`,
    );
    check(cycle.remote.kata_launch_to_ssh_ready_ns > 0, `cycle ${index + 1} SSH sample`);
    check(cycle.cost.rate_source_commitment === e.cost.rate_source_commitment, `cycle ${index + 1} rate source`);
    check(
      cycle.cost.cost_micro_usd === ceilCost(duration, e.cost.aggregate_rate_micro_usd_per_hour),
      `cycle ${index + 1} cost recomputation`,
    );
    aggregateDuration += duration;
    aggregateCost += cycle.cost.cost_micro_usd;
    if (index === 0) {
      check(cycle.workloads?.length === 21, "exact 21 full-cycle workloads");
      const expected = ["git", "build", "install"].flatMap((category) =>
        Array.from({ length: 7 }, (_, ordinal) => `${category}:${ordinal + 1}`),
      );
      check(
        cycle.workloads
          .map((row) => `${row.category}:${row.ordinal}`)
          .every((row, rowIndex) => row === expected[rowIndex]),
        "workload category/ordinal order",
      );
    } else check(cycle.workloads === undefined, `readiness cycle ${index + 1} workloads`);
  }
  distinct(cycleCommitments, "cycle");
  distinct(grants, "grant");
  distinct(plans, "plan");
  distinct(states, "state");
  distinct(lineages, "state lineage");
  distinct(instances, "instance");
  distinct(hostReceipts, "host receipt");
  distinct(operations, "operation");
  distinct(boots, "host boot");
  distinct(settlements, "effect settlement");
  for (const name of freshnessNames) distinct(freshness[name], `${name} freshness`);

  const zeros: string[] = [];
  const observers: string[] = [];
  const sessions: string[] = [];
  const runs: string[] = [];
  for (const [index, inventory] of e.inventories.entries()) {
    check(
      inventory.observation_sequence === index + 1 && inventory.cycle_ordinal === (index < 7 ? index + 1 : null),
      `inventory ${index + 1} order`,
    );
    const inventoryStarted = unixNs(inventory.observed_started_unix_ns);
    const inventoryEnded = unixNs(inventory.observed_ended_unix_ns);
    check(
      inventoryStarted < inventoryEnded && inventoryEnded <= expiry && (index === 0 || inventoryStarted > priorZeroEnd),
      `inventory ${index + 1} wall order`,
    );
    if (index < 7) {
      const cycle = e.cycles[index];
      check(cycle !== undefined, `inventory ${index + 1} cycle missing`);
      check(
        inventory.destroyed_state_commitment === cycle.effects.destroy.state_commitment,
        `inventory ${index + 1} destroyed state`,
      );
      check(
        inventoryStarted > unixNs(cycle.effects.destroy.observed_ended_unix_ns),
        `inventory ${index + 1} precedes destroy`,
      );
      check(inventory.zero_commitment === cycle.zero_inventory_commitment, `inventory ${index + 1} cycle zero`);
    } else {
      const finalCycle = e.cycles[6];
      check(finalCycle !== undefined, "cycle seven missing");
      check(
        inventoryStarted > priorZeroEnd && inventoryEnded > unixNs(finalCycle.effects.destroy.observed_ended_unix_ns),
        "final zero does not follow cycle seven",
      );
      check(inventory.observed_ended_unix_ns === e.deadlines.final_zero_unix_ns, "final zero timestamp");
    }
    priorZeroEnd = inventoryEnded;
    const byCategory = new Map<string, typeof inventory.pages>();
    for (const page of inventory.pages) byCategory.set(page.category, [...(byCategory.get(page.category) ?? []), page]);
    check(
      CATEGORIES.every((category) => byCategory.has(category)) && byCategory.size === CATEGORIES.length,
      `inventory ${index + 1} category coverage`,
    );
    for (const category of CATEGORIES) {
      const pages = byCategory.get(category);
      check(pages !== undefined, `inventory ${index + 1} ${category} missing`);
      let token: string | null = null;
      for (const [pageIndex, page] of pages.entries()) {
        check(
          page.ordinal === pageIndex + 1 && page.request_token_commitment === token,
          `inventory ${index + 1} ${category} pagination`,
        );
        token = page.next_token_commitment;
        check(
          page.resources.every((resource) => resource.disposition === "absent" || resource.disposition === "deleted"),
          `inventory ${index + 1} nonzero resource`,
        );
      }
      check(token === null, `inventory ${index + 1} ${category} truncated`);
    }
    zeros.push(inventory.zero_commitment);
    observers.push(inventory.observer_commitment);
    sessions.push(inventory.session_commitment);
    runs.push(inventory.run_commitment);
  }
  distinct(zeros, "zero");
  distinct(observers, "observer");
  distinct(sessions, "session");
  distinct(runs, "run");
  check(
    e.cleanup.cycle_zero_commitments.every((value, index) => value === zeros[index]) &&
      e.cleanup.final_zero_commitment === zeros[7],
    "cleanup zero projection",
  );
  check(
    e.cleanup.inventory_categories.every((value, index) => value === CATEGORIES[index]),
    "inventory category projection",
  );

  checkSummary(
    e.launch_summary,
    e.cycles.map((cycle) => cycle.remote.apply_to_running_ns),
    "launch",
  );
  checkSummary(
    e.ssh_ready_summary,
    e.cycles.map((cycle) => cycle.remote.kata_launch_to_ssh_ready_ns),
    "SSH",
  );
  const workloads = e.cycles[0]?.workloads;
  check(workloads !== undefined, "full-cycle workloads missing");
  for (const category of ["git", "build", "install"] as const)
    checkSummary(
      e.workload_summaries[category],
      workloads.filter((row) => row.category === category).map((row) => row.duration_ns),
      category,
    );
  check(e.cost.aggregate_effect_duration_ns === aggregateDuration, "aggregate effect duration");
  check(e.cost.actual_campaign_duration_ns === e.deadlines.actual_campaign_duration_ns, "cost wall duration");
  check(
    e.cost.aggregate_cost_micro_usd === aggregateCost && aggregateCost <= e.cost.approved_maximum_micro_usd,
    "aggregate/approved cost",
  );
}

export function validateAwsStage2CompletionEvidence(value: unknown): ValidatedCompletionEvidence {
  let snapshot: unknown;
  try {
    snapshot = structuredClone(value);
  } catch (error) {
    throw new CompletionEvidenceValidationError("public evidence cannot be snapshotted", { cause: error });
  }
  graph(snapshot);
  if (!schemaValidator(snapshot))
    fail((schemaValidator.errors ?? []).map((error) => `${error.instancePath || "/"}: ${error.message}`).join("\n"));
  semantics(snapshot);
  const token = Object.freeze({ evidence: freeze(snapshot) });
  validatedObjects.add(token);
  return token;
}
export function evidenceFromValidated(value: ValidatedCompletionEvidence): CompletionEvidence {
  check(
    typeof value === "object" && value !== null && validatedObjects.has(value),
    "renderer requires validator-issued evidence token",
  );
  return value.evidence;
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
function duplicateKeys(text: string): void {
  // JSON.parse cannot report duplicate keys.  A small recursive scanner closes that ambiguity.
  let offset = 0;
  const ws = () => {
    while (/\s/u.test(text[offset] ?? "")) offset++;
  };
  const string = (): string => {
    const start = offset++;
    while (offset < text.length) {
      if (text[offset] === "\\") offset += 2;
      else if (text[offset++] === '"') return JSON.parse(text.slice(start, offset));
    }
    return fail("unterminated JSON string");
  };
  const value = (): void => {
    ws();
    if (text[offset] === "{") {
      offset++;
      ws();
      const keys = new Set<string>();
      if (text[offset] === "}") {
        offset++;
        return;
      }
      while (true) {
        ws();
        check(text[offset] === '"', "JSON key expected");
        const key = string();
        check(!keys.has(key), `duplicate JSON key ${key}`);
        keys.add(key);
        ws();
        check(text[offset++] === ":", "JSON colon expected");
        value();
        ws();
        if (text[offset] === "}") {
          offset++;
          return;
        }
        check(text[offset++] === ",", "JSON comma expected");
      }
    }
    if (text[offset] === "[") {
      offset++;
      ws();
      if (text[offset] === "]") {
        offset++;
        return;
      }
      while (true) {
        value();
        ws();
        if (text[offset] === "]") {
          offset++;
          return;
        }
        check(text[offset++] === ",", "JSON comma expected");
      }
    }
    if (text[offset] === '"') {
      string();
      return;
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*))/u.exec(text.slice(offset));
    check(match !== null, "JSON value expected");
    offset += match[0].length;
  };
  value();
  ws();
  check(offset === text.length, "trailing JSON data");
}
export function parseAwsStage2CompletionEvidence(raw: string): ValidatedCompletionEvidence {
  check(Buffer.byteLength(raw) <= 262_144, "completion evidence byte bound exceeded");
  check(raw.endsWith("\n") && !raw.endsWith("\n\n"), "canonical evidence requires one final LF");
  const body = raw.slice(0, -1);
  duplicateKeys(body);
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch (error) {
    throw new CompletionEvidenceValidationError("invalid completion evidence JSON", { cause: error });
  }
  check(`${canonical(value)}\n` === raw, "completion evidence is not canonical JSON");
  return validateAwsStage2CompletionEvidence(value);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const path = process.argv[2];
  assert.ok(path && process.argv.length === 3, "usage: validate-aws-stage2-completion-evidence-v2.ts EVIDENCE_JSON");
  parseAwsStage2CompletionEvidence(readFileSync(resolve(path), "utf8"));
  console.log("Validated closed AWS Stage 2 completion evidence v2.");
}

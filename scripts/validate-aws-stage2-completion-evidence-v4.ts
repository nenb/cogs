import { createHash } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

let schemaValidator: ValidateFunction<CompletionEvidence> | undefined;
function getSchemaValidator(): ValidateFunction<CompletionEvidence> {
  if (schemaValidator) return schemaValidator;
  // Initialization belongs inside the guarded CLI boundary, including require,
  // file reads, JSON decoding and compilation. AJV must never log diagnostics.
  try {
    const require = createRequire(import.meta.url);
    const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
    const raw = fs.readFileSync(
      resolve(import.meta.dirname, "../schemas/aws-stage2-completion-evidence-v4.json"),
      "utf8",
    );
    duplicateKeys(raw);
    schemaValidator = new Ajv2020({ allErrors: false, strict: true, ownProperties: true, logger: false }).compile(
      JSON.parse(raw) as object,
    ) as ValidateFunction<CompletionEvidence>;
    return schemaValidator;
  } catch {
    throw new CompletionEvidenceValidationError("completion evidence schema unavailable", "schema");
  }
}

const BILLING_HOUR_NS = 3_600_000_000_000n;
const EFFECT_WINDOW_NS = 480n * 60n * 1_000_000_000n;
const CLEANUP_RESERVE_NS = 30 * 60 * 1_000_000_000;
const MAXIMUM_CYCLE_NS = 150n * 60n * 1_000_000_000n;
const APPROVED_MAXIMUM_MICRO_USD = 1_100_000;
const MAX_BYTES = 256 * 1024;
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
const PROGRAMS = {
  full: [
    "0e62df128ab166344e4a8e20aa9c92b376fbf96ba8454f73cec66ca1b5678406",
    "35f125d7914d134854e532a08398153ffcd699426fbeeabcb7c35d7f4ec474f5",
  ],
  readiness: [
    "386f9398688cad05dfc0921ad0e5aa442cf146fd7ff16ddd82a7683244da6bab",
    "b5b71497621037e6b7eada7c581962775625d532cdc06729dfd095e6a6f7c010",
  ],
} as const;
const PARSERS = {
  full: "a134e1b00791b4cccf37206284f36dc685056f8a57aebc13173f09285292a35c",
  readiness: "500423ea45a3c12da1eaf107281a966e88f21f77701524f2d8617d0456f68e4c",
} as const;
const WORKLOAD_RESULTS = {
  git: "73ccf2bce069d96d1dbd7e927e0fbd9205dcedfdb4a8ff104eb29e3f3e9e0b7c",
  build: "08702b0d8605121987d29dd7e4941e87f0063776f20229e14c57529fd7d4ddcf",
  install: "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2",
} as const;

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
    | "client_ssh_identity"
    | "host_ssh_identity"
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
    bindings: {
      source_bindings: Record<string, string>;
      cycle_capability_sha256: string;
      program_sha256: string;
      parser_source_sha256: string;
      marker_sha256: string;
      qemu: {
        operation_token: string;
        live_mapping_sha256: string;
        runtime_identity_sha256: string;
        pre_ssh_runtime_fact_sha256: string;
        post_ssh_runtime_fact_sha256: string | null;
        qemu_argv_sha256: string;
        qemu_pid: number;
        qemu_starttime: number;
        qemu_executable_device: number;
        qemu_executable_inode: number;
        observer_qmp_device: number;
        observer_qmp_inode: number;
        kvm_device: number;
        kvm_inode: number;
        kvm_rdev: number;
        kvm_api: number;
        qmp_present: boolean;
        qmp_enabled: boolean;
      };
    };
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
  version: "cogs.aws-stage2-completion-evidence/v4";
  authority: "aws-stage2-completion";
  result: "pass";
  batch: {
    commitment: string;
    implementation_revision: string;
    control_revision: string;
    qualification_revision: string;
    consumption_commitment: string;
    custody_root: string;
    cycle_count: 7;
    modes: string[];
  };
  bindings: Record<string, string>;
  custody: {
    handoff: {
      phase_boundary_ordinal: 3;
      workflow_revision: string;
      workflow_run_id: number;
      workflow_run_attempt: 1;
      producer_job_id: number;
      consumer_job_id: number;
      continuation_commitment: string;
      continuation_file_sha256: string;
      continuation_bundle_sha256: string;
      continuation_artifact_id: number;
      continuation_artifact_digest: string;
      continuation_admission_commitment: string;
      journal_sequence: number;
      journal_tip_sha256: string;
      cycle3_zero_commitment: string;
    };
  };
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

type FailureCategory = "usage" | "file" | "json" | "schema" | "validation";
export class CompletionEvidenceValidationError extends Error {
  readonly category: FailureCategory;
  constructor(message: string, category: FailureCategory = "validation") {
    super(message);
    this.category = category;
  }
}

// Only these literal, bounded lines may cross either CLI's failure boundary.
const CLI_DIAGNOSTICS = Object.freeze({
  usage: "completion-evidence-v4: usage\n",
  file: "completion-evidence-v4: file\n",
  json: "completion-evidence-v4: json\n",
  schema: "completion-evidence-v4: schema\n",
  validation: "completion-evidence-v4: validation\n",
  internal: "completion-evidence-v4: internal\n",
});
export function completionEvidenceCliDiagnostic(error: unknown): string {
  if (error instanceof CompletionEvidenceValidationError) {
    // Do not interpolate even a nominally typed error property.
    switch (error.category) {
      case "usage":
        return CLI_DIAGNOSTICS.usage;
      case "file":
        return CLI_DIAGNOSTICS.file;
      case "json":
        return CLI_DIAGNOSTICS.json;
      case "schema":
        return CLI_DIAGNOSTICS.schema;
      case "validation":
        return CLI_DIAGNOSTICS.validation;
    }
  }
  return CLI_DIAGNOSTICS.internal;
}
export type CompletionEvidenceCliOutput = { stdout: (text: string) => void; stderr: (text: string) => void };
export const completionEvidenceCliOutput: CompletionEvidenceCliOutput = {
  stdout: (text) => {
    if (fs.writeSync(1, text) !== Buffer.byteLength(text)) throw new Error("short stdout write");
  },
  stderr: (text) => {
    if (fs.writeSync(2, text) !== Buffer.byteLength(text)) throw new Error("short stderr write");
  },
};
function readBoundedRegular(path: string, maximum: number): string {
  let descriptor: number | undefined;
  let result: string | undefined;
  let failed = false;
  try {
    descriptor = fs.openSync(resolve(path), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximum)) throw new Error();
    const raw = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < raw.length) {
      const count = fs.readSync(descriptor, raw, offset, raw.length - offset, null);
      if (count < 1) throw new Error();
      offset += count;
    }
    if (fs.readSync(descriptor, Buffer.alloc(1), 0, 1, null) !== 0) throw new Error();
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const name of ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs"] as const)
      if (before[name] !== after[name]) throw new Error();
    result = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  } catch {
    failed = true;
  }
  if (descriptor !== undefined)
    try {
      fs.closeSync(descriptor);
    } catch {
      failed = true;
    }
  if (failed || result === undefined)
    throw new CompletionEvidenceValidationError("completion evidence file unavailable", "file");
  return result;
}
export function readCompletionEvidenceFile(path: string): string {
  return readBoundedRegular(path, MAX_BYTES);
}
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
function commitment(domain: string, value: unknown, newline = false): string {
  return createHash("sha256")
    .update(domain)
    .update("\0")
    .update(canonical(value))
    .update(newline ? "\n" : "")
    .digest("hex");
}
function cycleCapability(mode: "full" | "readiness", program: string, marker: string): string {
  return createHash("sha256")
    .update("cogs.stage2-cycle-route/v1\0production\0")
    .update(mode)
    .update(Buffer.from(program, "hex"))
    .update(Buffer.from(marker, "hex"))
    .digest("hex");
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
function scan(value: unknown): void {
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
      "forbidden sensitive string",
    );
    check(
      [...value].every((character) => {
        const point = character.codePointAt(0);
        return point !== undefined && point >= 0x20 && point <= 0x7e;
      }),
      "non-ASCII string",
    );
  } else if (Array.isArray(value))
    value.forEach((item) => {
      scan(item);
    });
  else if (value !== null && typeof value === "object") for (const item of Object.values(value)) scan(item);
}

function semantics(e: CompletionEvidence): void {
  scan(e);
  const handoff = e.custody.handoff;
  check(
    handoff.phase_boundary_ordinal === 3 &&
      handoff.workflow_run_attempt === 1 &&
      handoff.producer_job_id !== handoff.consumer_job_id &&
      handoff.cycle3_zero_commitment === e.inventories[2]?.zero_commitment,
    "authenticated handoff projection",
  );
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
  check(
    e.deadlines.first_apply_unix_ns === e.cycles[0]?.effects.apply.observed_started_unix_ns,
    "first apply projection",
  );
  check(effectDeadline === firstApply + EFFECT_WINDOW_NS, "exact v6 effect deadline");
  check(e.deadlines.cleanup_reserve_ns === CLEANUP_RESERVE_NS, "exact v6 cleanup reserve");
  check(e.cost.approved_maximum_micro_usd === APPROVED_MAXIMUM_MICRO_USD, "exact v6 approved maximum");
  const cleanupDeadline = effectDeadline + BigInt(e.deadlines.cleanup_reserve_ns);
  check(cleanupDeadline <= expiry, "cleanup reserve exceeds expiry");
  check(finalZero < cleanupDeadline, "final zero exceeds cleanup deadline");
  check(
    e.cost.rate_source_commitment ===
      commitment("cogs.stage2-fixed-rate/v1", {
        micro_usd_per_hour: e.cost.aggregate_rate_micro_usd_per_hour,
      }),
    "fixed rate source commitment",
  );
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
  const runtimeIdentities: string[] = [];
  const liveMappings: string[] = [];
  const preSshRuntimeFacts: string[] = [];
  const postSshRuntimeFacts: string[] = [];
  const freshnessNames = [
    "instance",
    "root_volume",
    "launch_template_generation",
    "host_boot",
    "operation",
    "client_ssh_identity",
    "host_ssh_identity",
    "pre_destroy_receipt",
  ] as const;
  const freshness = Object.fromEntries(freshnessNames.map((name) => [name, [] as string[]])) as Record<
    (typeof freshnessNames)[number],
    string[]
  >;
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
    const previousZero = e.inventories[index - 1];
    check(
      index === 0 ||
        (previousZero !== undefined &&
          unixNs(plan.observed_started_unix_ns) > unixNs(previousZero.observed_ended_unix_ns)),
      `cycle ${index + 1} overlaps prior zero observation`,
    );
    check(plan.identity_commitment === cycle.plan_sha256, `cycle ${index + 1} plan identity`);
    // Instance resource-ID freshness has a different domain/preimage from the
    // running observation. The adapter binds remote.instance only to the latter.
    check(
      cycle.freshness.host_boot === cycle.remote.host_boot_commitment &&
        cycle.freshness.operation === cycle.remote.operation_commitment &&
        cycle.remote.instance_commitment === running.identity_commitment,
      `cycle ${index + 1} remote freshness projection`,
    );
    // These complete typed-controller preimages survive redaction. In contrast,
    // approval/package/custody and inventory-page preimages are not available;
    // their opaque digests cannot be authenticated by this public projection.
    check(
      cycle.grant_commitment ===
        commitment("cogs.stage2-cycle-launch-grant/v1", {
          batch_commitment: e.batch.commitment,
          ordinal: cycle.ordinal,
          mode: cycle.mode,
          implementation_revision: e.batch.implementation_revision,
          control_revision: e.batch.control_revision,
          static_control_sha256: e.bindings.static_control_commitment,
          rootfs_descriptor_sha256: e.bindings.rootfs_descriptor_commitment,
          ami_commitment: e.bindings.ami_commitment,
          plan_sha256: cycle.plan_sha256,
        }),
      `cycle ${index + 1} grant commitment`,
    );
    check(
      cycle.cycle_commitment ===
        commitment("cogs.stage2-production-cycle/v2", {
          grant: cycle.grant_commitment,
          effects: EFFECTS.map((name) => cycle.effects[name].settlement_commitment),
          remote: cycle.remote.host_receipt_commitment,
          zero: cycle.zero_inventory_commitment,
          cost: cycle.cost.receipt_commitment,
        }),
      `cycle ${index + 1} cycle commitment`,
    );
    check(
      cycle.cost.receipt_commitment ===
        commitment("cogs.stage2-cost-receipt/v1", {
          grant_commitment: cycle.grant_commitment,
          cycle_ordinal: cycle.ordinal,
          rate_source_commitment: cycle.cost.rate_source_commitment,
          usage_commitment: cycle.cost.usage_commitment,
          cost_micro_usd: cycle.cost.cost_micro_usd,
        }),
      `cycle ${index + 1} cost receipt commitment`,
    );
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
    const expectedState = commitment("cogs.stage2-provider-state-slot/v1", {
      batch_commitment: e.batch.commitment,
      ordinal: cycle.ordinal,
    });
    const expectedLineage = commitment("cogs.stage2-provider-state-lineage/v1", {
      batch_commitment: e.batch.commitment,
      ordinal: cycle.ordinal,
      state_slot: `cycle-${cycle.ordinal}`,
    });
    check(
      EFFECTS.every(
        (name) =>
          cycle.effects[name].state_commitment === expectedState &&
          cycle.effects[name].state_lineage_commitment === expectedLineage,
      ),
      `cycle ${index + 1} state lineage`,
    );
    settlements.push(...EFFECTS.map((name) => cycle.effects[name].settlement_commitment));
    const duration = elapsedNs(destroy.observed_ended_unix_ns, apply.observed_started_unix_ns, `cycle ${index + 1}`);
    check(
      unixNs(destroy.observed_ended_unix_ns) < unixNs(apply.observed_started_unix_ns) + MAXIMUM_CYCLE_NS,
      `cycle ${index + 1} exact v6 duration bound`,
    );
    check(cycle.cost.billable_duration_ns === duration, `cycle ${index + 1} billable duration`);
    check(
      cycle.cost.usage_commitment === commitment("cogs.stage2-provider-usage/v1", { duration_ns: duration }),
      `cycle ${index + 1} usage commitment`,
    );
    check(
      cycle.remote.apply_to_running_ns ===
        elapsedNs(running.observed_ended_unix_ns, apply.observed_started_unix_ns, `cycle ${index + 1} running`),
      `cycle ${index + 1} provider wall sample`,
    );
    check(cycle.remote.kata_launch_to_ssh_ready_ns > 0, `cycle ${index + 1} SSH sample`);
    const remoteBindings = cycle.remote.bindings;
    const source = remoteBindings.source_bindings;
    const mode = cycle.mode as "full" | "readiness";
    const [program, marker] = PROGRAMS[mode];
    check(
      commitment("cogs.stage2-source-bindings/v1", source) === e.bindings.source_bindings_commitment &&
        source.source_head === e.batch.implementation_revision &&
        source.source_manifest_sha256 === e.bindings.source_manifest_commitment &&
        source.runtime_manifest_sha256 === e.bindings.runtime_manifest_sha256 &&
        source.rootfs_descriptor_sha256 === e.bindings.rootfs_descriptor_commitment &&
        source.rootfs_package_manifest_sha256 === e.bindings.rootfs_package_manifest_commitment &&
        source.rootfs_provenance_sha256 === e.bindings.rootfs_provenance_commitment &&
        source.rootfs_publication_receipt_sha256 === e.bindings.rootfs_publication_receipt_commitment &&
        source.final_pin_sha256 === e.bindings.fixture_commitment &&
        source.guest_program_sha256 === PROGRAMS.full[0] &&
        remoteBindings.program_sha256 === program &&
        remoteBindings.parser_source_sha256 === PARSERS[mode] &&
        remoteBindings.marker_sha256 === marker &&
        remoteBindings.cycle_capability_sha256 === cycleCapability(mode, program, marker),
      `cycle ${index + 1} exact remote source/parser bindings`,
    );
    const qemu = remoteBindings.qemu;
    const {
      runtime_identity_sha256: _identity,
      pre_ssh_runtime_fact_sha256: _pre,
      post_ssh_runtime_fact_sha256: post,
      operation_token: _operation,
      live_mapping_sha256: _mapping,
      ...qemuIdentity
    } = qemu;
    check(
      qemu.operation_token === cycle.remote.operation_commitment &&
        qemu.runtime_identity_sha256 === commitment("cogs.stage2-qemu-runtime-identity/v1", qemuIdentity, true) &&
        (mode === "readiness") === (post !== null) &&
        (mode !== "readiness" || post !== qemu.pre_ssh_runtime_fact_sha256),
      `cycle ${index + 1} exact remote QEMU bindings`,
    );
    runtimeIdentities.push(qemu.runtime_identity_sha256);
    liveMappings.push(qemu.live_mapping_sha256);
    preSshRuntimeFacts.push(qemu.pre_ssh_runtime_fact_sha256);
    if (qemu.post_ssh_runtime_fact_sha256 !== null) postSshRuntimeFacts.push(qemu.post_ssh_runtime_fact_sha256);
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
          .every((row, rowIndex) => row === expected[rowIndex]) &&
          cycle.workloads.every(
            (row) => row.commitment === WORKLOAD_RESULTS[row.category as keyof typeof WORKLOAD_RESULTS],
          ),
        "workload category/ordinal/result",
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
  distinct(runtimeIdentities, "QEMU runtime identity");
  distinct(liveMappings, "live mapping");
  distinct(preSshRuntimeFacts, "pre-SSH runtime fact");
  distinct(postSshRuntimeFacts, "post-SSH runtime fact");
  check(
    postSshRuntimeFacts.length === 6 && new Set([...preSshRuntimeFacts, ...postSshRuntimeFacts]).size === 13,
    "cross-phase runtime fact replay",
  );
  for (const name of freshnessNames) distinct(freshness[name], `${name} freshness`);
  check(
    new Set([...freshness.client_ssh_identity, ...freshness.host_ssh_identity]).size === 14,
    "cross-role SSH key replay",
  );

  const zeros: string[] = [];
  const observers: string[] = [];
  const sessions: string[] = [];
  const runs: string[] = [];
  let priorZeroEnd = 0n;
  for (const [index, inventory] of e.inventories.entries()) {
    check(
      inventory.observation_sequence === index + 1 && inventory.cycle_ordinal === (index < 7 ? index + 1 : null),
      `inventory ${index + 1} order`,
    );
    const inventoryStarted = unixNs(inventory.observed_started_unix_ns);
    const inventoryEnded = unixNs(inventory.observed_ended_unix_ns);
    check(
      inventoryStarted < inventoryEnded &&
        inventoryEnded < cleanupDeadline &&
        (index === 0 || inventoryStarted > priorZeroEnd),
      `inventory ${index + 1} wall order`,
    );
    check(
      inventory.account_commitment === e.bindings.account_commitment &&
        inventory.region_commitment === e.inventories[0]?.region_commitment,
      `inventory ${index + 1} account/region binding`,
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
      check(
        inventory.destroyed_state_commitment === finalCycle.effects.destroy.state_commitment,
        "final inventory destroyed state",
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
  check(
    e.batch.custody_root ===
      commitment("cogs.stage2-production-custody/v3", {
        execution_authority: "authenticated-aws-adapter",
        approval: e.bindings.approval_commitment,
        consumption: e.batch.consumption_commitment,
        cycles: cycleCommitments,
        inventories: e.inventories.map((item) => item.zero_commitment),
        costs: e.cycles.map((item) => item.cost.receipt_commitment),
        continuation: handoff.continuation_commitment,
        continuation_sha256: handoff.continuation_file_sha256,
        continuation_bundle_sha256: handoff.continuation_bundle_sha256,
        handoff_authentication: handoff.continuation_admission_commitment,
      }),
    "campaign handoff custody root",
  );
}

export function validateAwsStage2CompletionEvidence(value: unknown): ValidatedCompletionEvidence {
  let snapshot: unknown;
  try {
    snapshot = structuredClone(value);
  } catch {
    throw new CompletionEvidenceValidationError("public evidence cannot be snapshotted");
  }
  graph(snapshot);
  if (!getSchemaValidator()(snapshot))
    throw new CompletionEvidenceValidationError("completion evidence schema mismatch", "schema");
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
  let nodes = 0;
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
  const value = (depth = 0): void => {
    check(++nodes <= 16_384 && depth <= 24, "JSON graph bound exceeded");
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
        check(!keys.has(key), "duplicate JSON key");
        keys.add(key);
        ws();
        check(text[offset++] === ":", "JSON colon expected");
        value(depth + 1);
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
        value(depth + 1);
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
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(text.slice(offset));
    check(match !== null, "JSON value expected");
    offset += match[0].length;
  };
  value();
  ws();
  check(offset === text.length, "trailing JSON data");
}
export function parseAwsStage2CompletionEvidence(raw: string): ValidatedCompletionEvidence {
  let value: unknown;
  try {
    check(Buffer.byteLength(raw) <= 262_144, "completion evidence byte bound exceeded");
    check(raw.endsWith("\n") && !raw.endsWith("\n\n"), "canonical evidence requires one final LF");
    const body = raw.slice(0, -1);
    duplicateKeys(body);
    value = JSON.parse(body);
    check(`${canonical(value)}\n` === raw, "completion evidence is not canonical JSON");
  } catch (error) {
    // Scanner/check messages are fixed; native JSON errors may contain input.
    throw new CompletionEvidenceValidationError(
      error instanceof CompletionEvidenceValidationError ? error.message : "invalid completion evidence JSON",
      "json",
    );
  }
  return validateAwsStage2CompletionEvidence(value);
}

/** In-process CLI seam: no child processes, provider commands or network. */
export function runAwsStage2CompletionEvidenceCli(
  args: readonly string[],
  output: CompletionEvidenceCliOutput = completionEvidenceCliOutput,
): 0 | 2 {
  try {
    const [path] = args;
    if (!path || args.length !== 1) throw new CompletionEvidenceValidationError("invalid arguments", "usage");
    parseAwsStage2CompletionEvidence(readCompletionEvidenceFile(path));
    output.stdout("Validated closed AWS Stage 2 completion evidence v4.\n");
    return 0;
  } catch (error) {
    try {
      output.stderr(completionEvidenceCliDiagnostic(error));
    } catch {}
    return 2;
  }
}

const NAMES = Object.freeze({
  evidence: "aws-stage2-completion-evidence-v4.json",
  report: "aws-stage2-completion-report-v4.md",
  publication: "aws-stage2-completion-publication-v2.json",
  continuation: "aws-stage2-production-continuation-v1.json",
  bundle: "aws-stage2-production-continuation-v1.bundle.json",
  admission: "aws-stage2-production-continuation-admission-v1.json",
});
const EXPECTED_NAMES: ReadonlySet<string> = new Set(Object.values(NAMES));
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const PACKAGE_MAXIMUM_CYCLE_NS = 150n * 60n * 1_000_000_000n;
const PACKAGE_EFFECT_WINDOW_NS = 480n * 60n * 1_000_000_000n;
const PACKAGE_CLEANUP_RESERVE_NS = 30n * 60n * 1_000_000_000n;
const PINNED_TRUSTED_ROOT_SHA256 = "844a1c6de3986c9f02070266b25e0d1a2fa99ceccc89f6b9ad90aae47b62a16e";
const CAMPAIGN_WORKFLOW = ".github/workflows/stage2-production-campaign.yml";
const CAMPAIGN_WORKFLOW_REF = "nenb/cogs/.github/workflows/stage2-production-campaign.yml@refs/heads/main";

type JsonObject = Record<string, unknown>;
type ExactJson = null | boolean | string | bigint | ExactJson[] | { [key: string]: ExactJson };
type JsonBigParser = { parse: (raw: string) => ExactJson };

let validators: Record<"publication" | "continuation" | "admission", ValidateFunction> | undefined;
let jsonBig: JsonBigParser | undefined;

export class CompletionPackageValidationError extends Error {}

function object(value: unknown, label: string): JsonObject {
  check(value !== null && typeof value === "object" && !Array.isArray(value), `${label} object`);
  return value as JsonObject;
}
function array(value: unknown, label: string): unknown[] {
  check(Array.isArray(value), `${label} array`);
  return value;
}
function string(value: unknown, label: string): string {
  check(typeof value === "string", `${label} string`);
  return value;
}
function integer(value: unknown, label: string): bigint {
  check(typeof value === "bigint" || (typeof value === "number" && Number.isSafeInteger(value)), `${label} integer`);
  return BigInt(value);
}
function sha256(raw: Buffer | string): string {
  return createHash("sha256").update(raw).digest("hex");
}
function asciiJsonString(value: string): string {
  return JSON.stringify(value).replace(/[\u007f-\u{10ffff}]/gu, (character) => {
    const point = character.codePointAt(0);
    check(point !== undefined, "invalid Unicode scalar");
    if (point <= 0xffff) return `\\u${point.toString(16).padStart(4, "0")}`;
    const adjusted = point - 0x10000;
    const high = 0xd800 + (adjusted >> 10);
    const low = 0xdc00 + (adjusted & 0x3ff);
    return `\\u${high.toString(16)}\\u${low.toString(16)}`;
  });
}
function packageCanonical(value: ExactJson, newline = false): string {
  let result: string;
  if (typeof value === "bigint") result = value.toString();
  else if (typeof value === "string") result = asciiJsonString(value);
  else if (value === null || typeof value === "boolean") result = JSON.stringify(value);
  else if (Array.isArray(value)) result = `[${value.map((item) => packageCanonical(item)).join(",")}]`;
  else
    result = `{${Object.entries(value)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, item]) => `${asciiJsonString(key)}:${packageCanonical(item)}`)
      .join(",")}}`;
  return newline ? `${result}\n` : result;
}
function packageCommitment(domain: string, value: ExactJson, newline = false): string {
  return createHash("sha256").update(domain).update("\0").update(packageCanonical(value, newline)).digest("hex");
}
function without(value: JsonObject, key: string): ExactJson {
  const result = { ...(value as { [name: string]: ExactJson }) };
  delete result[key];
  return result;
}
function equivalent(left: unknown, right: unknown): boolean {
  if (
    (typeof left === "bigint" || (typeof left === "number" && Number.isSafeInteger(left))) &&
    (typeof right === "bigint" || (typeof right === "number" && Number.isSafeInteger(right)))
  )
    return BigInt(left) === BigInt(right);
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") return left === right;
  if (Array.isArray(left) || Array.isArray(right))
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => equivalent(item, right[index]))
    );
  const leftObject = left as JsonObject;
  const rightObject = right as JsonObject;
  const leftKeys = Object.keys(leftObject).sort();
  const rightKeys = Object.keys(rightObject).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && equivalent(leftObject[key], rightObject[key]))
  );
}
function requireEquivalent(left: unknown, right: unknown, label: string): void {
  check(equivalent(left, right), label);
}
function exactObject(value: JsonObject): { [key: string]: ExactJson } {
  return value as { [key: string]: ExactJson };
}
function commitmentWithout(domain: string, value: JsonObject, key: string): string {
  return packageCommitment(domain, without(value, key));
}
function rawSha256(value: ExactJson): string {
  return sha256(Buffer.from(packageCanonical(value, true), "ascii"));
}

function getJsonBig(): JsonBigParser {
  if (jsonBig) return jsonBig;
  try {
    const require = createRequire(import.meta.url);
    const factory = require("json-bigint") as (options: object) => JsonBigParser;
    jsonBig = factory({
      useNativeBigInt: true,
      alwaysParseAsBig: true,
      protoAction: "error",
      constructorAction: "error",
    });
    return jsonBig;
  } catch {
    fail("exact JSON parser unavailable");
  }
}
function getValidators(): Record<"publication" | "continuation" | "admission", ValidateFunction> {
  if (validators) return validators;
  try {
    const require = createRequire(import.meta.url);
    const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
    const ajv = new Ajv2020({ allErrors: false, strict: true, ownProperties: true, logger: false });
    const compile = (name: string) => {
      const raw = fs.readFileSync(resolve(import.meta.dirname, `../schemas/${name}`), "utf8");
      return ajv.compile(JSON.parse(raw) as object);
    };
    validators = {
      publication: compile("aws-stage2-completion-publication-v2.json"),
      continuation: compile("aws-stage2-production-continuation-v1.json"),
      admission: compile("aws-stage2-production-continuation-admission-v1.json"),
    };
    return validators;
  } catch {
    fail("package schemas unavailable");
  }
}
function readExactFile(directory: string, name: string): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(join(directory, name), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor, { bigint: true });
    check(
      before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(MAX_FILE_BYTES),
      `${name} identity`,
    );
    const raw = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < raw.length) {
      const count = fs.readSync(descriptor, raw, offset, raw.length - offset, null);
      check(count > 0, `${name} short read`);
      offset += count;
    }
    check(fs.readSync(descriptor, Buffer.alloc(1), 0, 1, null) === 0, `${name} grew`);
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs"] as const)
      check(before[field] === after[field], `${name} changed`);
    return raw;
  } catch (error) {
    if (error instanceof CompletionPackageValidationError) throw error;
    throw new CompletionPackageValidationError(`${name} unavailable`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}
function parseCanonical(raw: Buffer, validator: ValidateFunction, label: string): JsonObject {
  let regular: unknown;
  let exact: ExactJson;
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
    check(text.endsWith("\n") && !text.endsWith("\n\n"), `${label} final LF`);
    regular = JSON.parse(text);
    exact = getJsonBig().parse(text);
    check(packageCanonical(exact, true) === text, `${label} canonical JSON`);
  } catch (error) {
    if (error instanceof CompletionPackageValidationError) throw error;
    fail(`${label} JSON`);
  }
  check(validator(regular), `${label} schema`);
  return object(exact, label);
}

function projectEffect(value: JsonObject): JsonObject {
  return {
    intent_commitment: value.intent_commitment,
    settlement_commitment: value.settlement_commitment,
    identity_commitment: value.identity_commitment,
    state_commitment: value.state_commitment,
    state_lineage_commitment: value.state_lineage_commitment,
    observed_started_unix_ns: integer(value.observed_started_unix_ns, "effect start").toString(),
    observed_ended_unix_ns: integer(value.observed_ended_unix_ns, "effect end").toString(),
  };
}
function projectInventory(value: JsonObject): JsonObject {
  return {
    observation_sequence: value.observation_sequence,
    cycle_ordinal: value.cycle_ordinal,
    observer_commitment: value.observer_commitment,
    session_commitment: value.session_commitment,
    run_commitment: value.run_commitment,
    account_commitment: value.account_commitment,
    region_commitment: packageCommitment("cogs.stage2-redacted-region/v1", { region: value.region as ExactJson }),
    destroyed_state_commitment: value.destroyed_state_commitment,
    observed_started_unix_ns: integer(value.observed_started_unix_ns, "inventory start").toString(),
    observed_ended_unix_ns: integer(value.observed_ended_unix_ns, "inventory end").toString(),
    zero_commitment: value.zero_commitment,
    pages: array(value.pages, "inventory pages").map((source) => {
      const page = object(source, "inventory page");
      return {
        category: page.category,
        ordinal: page.ordinal,
        request_token_commitment: page.request_token_commitment,
        next_token_commitment: page.next_token_commitment,
        page_commitment: page.page_commitment,
        resources: array(page.resources, "inventory resources").map((sourceResource) => {
          const resource = object(sourceResource, "inventory resource");
          return {
            identity_commitment: resource.identity_commitment,
            disposition: resource.disposition,
            public_address_commitment: resource.public_address_commitment,
          };
        }),
      };
    }),
  };
}

function crossValidate(
  evidence: JsonObject,
  publication: JsonObject,
  continuation: JsonObject,
  admission: JsonObject,
  raw: Record<keyof typeof NAMES, Buffer>,
): void {
  const batch = object(evidence.batch, "evidence batch");
  const bindings = object(evidence.bindings, "evidence bindings");
  const custody = object(object(evidence.custody, "evidence custody").handoff, "evidence handoff");
  const deadlines = object(evidence.deadlines, "evidence deadlines");
  const cycles = array(evidence.cycles, "evidence cycles");
  const inventories = array(evidence.inventories, "evidence inventories");
  const cost = object(evidence.cost, "evidence cost");

  check(continuation.execution_authority === "authenticated-aws-adapter", "formal continuation authority");
  check(continuation.repository === "nenb/cogs" && admission.repository === "nenb/cogs", "repository provenance");
  check(
    continuation.workflow_path === CAMPAIGN_WORKFLOW &&
      admission.workflow_path === CAMPAIGN_WORKFLOW &&
      continuation.workflow_ref === CAMPAIGN_WORKFLOW_REF &&
      continuation.event === "workflow_dispatch" &&
      continuation.ref === "refs/heads/main" &&
      admission.ref === "refs/heads/main",
    "workflow provenance",
  );
  check(
    continuation.producer_job_name === "cycles_1_3" &&
      admission.producer_job_name === "cycles_1_3" &&
      admission.consumer_job_name === "cycles_4_7",
    "job names",
  );
  check(
    equivalent(continuation.github_run_id, admission.run_id) &&
      equivalent(continuation.github_run_attempt, admission.run_attempt) &&
      equivalent(continuation.producer_job_id, admission.producer_job_id),
    "signed continuation run and producer",
  );
  check(
    continuation.workflow_revision === admission.workflow_revision &&
      continuation.workflow_revision === custody.workflow_revision,
    "signed workflow revision",
  );
  check(
    admission.artifact_name ===
      `stage2-production-continuation-${string(admission.workflow_revision, "artifact revision")}-${integer(
        admission.run_id,
        "artifact run",
      ).toString()}-1`,
    "relational continuation artifact name",
  );
  check(
    continuation.approval_artifact_name ===
      `stage2-production-approval-${string(continuation.workflow_revision, "approval revision")}-${integer(
        continuation.approval_artifact_run_id,
        "approval run",
      ).toString()}`,
    "relational approval artifact name",
  );
  check(admission.trusted_root_sha256 === PINNED_TRUSTED_ROOT_SHA256, "pinned trusted root");
  check(
    admission.signer_identity === `https://github.com/nenb/cogs/${CAMPAIGN_WORKFLOW}@refs/heads/main`,
    "signer identity",
  );

  check(sha256(raw.evidence) === publication.evidence_sha256, "publication evidence hash");
  check(sha256(raw.report) === publication.report_sha256, "publication report hash");
  check(sha256(raw.continuation) === publication.continuation_sha256, "publication continuation hash");
  check(sha256(raw.bundle) === publication.continuation_bundle_sha256, "publication bundle hash");
  check(sha256(raw.admission) === publication.continuation_admission_sha256, "publication admission hash");
  check(publication.batch_commitment === batch.commitment, "publication batch");
  check(publication.candidate_custody_root === batch.custody_root, "publication custody root");
  check(
    publication.handoff_authentication_commitment === custody.continuation_admission_commitment,
    "publication handoff authentication",
  );

  const continuationCommitment = string(continuation.continuation_commitment, "continuation commitment");
  check(
    continuationCommitment ===
      packageCommitment("cogs.stage2-production-continuation/v1", without(continuation, "continuation_commitment")),
    "continuation commitment preimage",
  );
  const admissionCommitment = string(admission.admission_commitment, "admission commitment");
  check(
    admissionCommitment ===
      packageCommitment("cogs.stage2-production-handoff-authentication/v1", without(admission, "admission_commitment")),
    "admission commitment preimage",
  );
  check(admission.continuation_sha256 === sha256(raw.continuation), "admission continuation hash");
  check(admission.bundle_sha256 === sha256(raw.bundle), "admission bundle hash");
  check(admission.continuation_commitment === continuationCommitment, "admission continuation commitment");
  check(custody.continuation_file_sha256 === admission.continuation_sha256, "evidence continuation hash");
  check(custody.continuation_bundle_sha256 === admission.bundle_sha256, "evidence bundle hash");
  check(custody.continuation_commitment === continuationCommitment, "evidence continuation commitment");
  check(custody.continuation_admission_commitment === admissionCommitment, "evidence admission commitment");

  for (const field of [
    "approval_commitment",
    "batch_commitment",
    "implementation_revision",
    "control_revision",
    "qualification_revision",
  ])
    check(continuation[field] === admission[field], `continuation/admission ${field}`);
  for (const field of ["journal_sequence", "journal_tip_sha256"])
    check(
      equivalent(continuation[field], admission[field]) && equivalent(continuation[field], custody[field]),
      `journal ${field}`,
    );
  check(continuation.batch_commitment === batch.commitment, "continuation batch");
  check(continuation.implementation_revision === batch.implementation_revision, "continuation implementation");
  check(continuation.control_revision === batch.control_revision, "continuation control");
  check(continuation.qualification_revision === batch.qualification_revision, "continuation qualification");
  check(continuation.source_manifest_sha256 === bindings.source_manifest_commitment, "continuation source manifest");
  check(continuation.approval_commitment === bindings.approval_commitment, "continuation approval");
  const consumption = object(continuation.consumption, "continuation consumption");
  check(consumption.durable_record_commitment === batch.consumption_commitment, "consumption commitment");
  check(
    consumption.authentication_receipt_sha256 === bindings.approval_authentication_commitment,
    "consumption authentication",
  );
  check(
    admission.authentication_receipt_sha256 === consumption.authentication_receipt_sha256,
    "admission authentication",
  );
  check(
    equivalent(admission.run_id, custody.workflow_run_id) &&
      equivalent(admission.run_attempt, custody.workflow_run_attempt) &&
      equivalent(continuation.github_run_id, custody.workflow_run_id) &&
      equivalent(continuation.github_run_attempt, custody.workflow_run_attempt),
    "handoff run",
  );
  check(admission.workflow_revision === custody.workflow_revision, "handoff workflow revision");
  check(equivalent(admission.producer_job_id, custody.producer_job_id), "handoff producer");
  check(equivalent(admission.consumer_job_id, custody.consumer_job_id), "handoff consumer");
  check(equivalent(admission.artifact_id, custody.continuation_artifact_id), "handoff artifact id");
  check(admission.artifact_digest === custody.continuation_artifact_digest, "handoff artifact digest");
  check(admission.cycle3_zero_commitment === custody.cycle3_zero_commitment, "handoff cycle-three zero");
  check(
    admission.cycle3_zero_commitment ===
      object(array(continuation.inventories, "continuation inventories")[2], "cycle-three inventory").zero_commitment,
    "signed cycle-three zero",
  );

  check(
    integer(continuation.first_apply_unix_ns, "continuation first apply").toString() === deadlines.first_apply_unix_ns,
    "first apply projection",
  );
  check(
    integer(continuation.effect_deadline_unix_ns, "continuation effect deadline").toString() ===
      deadlines.effect_deadline_unix_ns,
    "effect deadline projection",
  );
  check(
    integer(continuation.effect_deadline_unix_ns, "continuation effect deadline") ===
      integer(continuation.first_apply_unix_ns, "continuation first apply") + PACKAGE_EFFECT_WINDOW_NS,
    "exact continuation effect window",
  );
  check(
    integer(deadlines.cleanup_reserve_ns, "cleanup reserve") === PACKAGE_CLEANUP_RESERVE_NS,
    "exact cleanup reserve",
  );
  check(
    integer(continuation.cleanup_deadline_unix_ns, "continuation cleanup deadline") ===
      integer(continuation.effect_deadline_unix_ns, "continuation effect deadline") + PACKAGE_CLEANUP_RESERVE_NS,
    "cleanup deadline projection",
  );
  check(
    integer(continuation.cleanup_deadline_unix_ns, "continuation cleanup deadline") <=
      BigInt(string(deadlines.expires_unix_ns, "approval expiry")),
    "continuation validity deadline",
  );

  const grants = array(continuation.grants, "continuation grants");
  const effects = array(continuation.effects, "continuation effects");
  const remotes = array(continuation.remotes, "continuation remotes");
  const continuationInventories = array(continuation.inventories, "continuation inventories");
  const costs = array(continuation.costs, "continuation costs");
  const cycleCommitments = array(continuation.cycle_commitments, "continuation cycle commitments");
  check(
    grants.length === 3 &&
      effects.length === 3 &&
      remotes.length === 3 &&
      continuationInventories.length === 3 &&
      costs.length === 3 &&
      cycleCommitments.length === 3,
    "closed continuation cardinality",
  );
  const consumedRecord = {
    version: "cogs.stage2-production-approval-consumption/v1",
    approval_commitment: continuation.approval_commitment as ExactJson,
    batch_commitment: continuation.batch_commitment as ExactJson,
    consumed_unix_ns: consumption.consumed_unix_ns as ExactJson,
    first_created: true,
  };
  check(consumption.first_created === true, "first approval consumption");
  check(consumption.approval_commitment === continuation.approval_commitment, "consumed approval");
  check(consumption.durable_record_commitment === rawSha256(consumedRecord), "durable consumption record");
  check(
    integer(consumption.consumed_unix_ns, "consumed time") < integer(continuation.first_apply_unix_ns, "first apply"),
    "consumption precedes effects",
  );

  const journalEvents: Array<[string, string, ExactJson, ExactJson, string]> = [
    ["batch", "consumed", null, null, string(consumption.durable_record_commitment, "consumption commitment")],
  ];
  let previousZero: bigint | undefined;
  const unique: Record<string, string[]> = Object.fromEntries(
    [
      "state",
      "lineage",
      "instance",
      "operation",
      "boot",
      "runtime",
      "mapping",
      "pre",
      "client",
      "host",
      "resource",
    ].map((name) => [name, []]),
  );
  const postSsh: string[] = [];
  for (let index = 0; index < 3; index++) {
    const cycle = object(cycles[index], `evidence cycle ${index + 1}`);
    const grant = object(grants[index], `continuation grant ${index + 1}`);
    for (const field of ["ordinal", "mode", "plan_sha256", "grant_commitment"])
      check(equivalent(grant[field], cycle[field]), `cycle ${index + 1} grant ${field}`);
    check(grant.batch_commitment === batch.commitment, `cycle ${index + 1} grant batch`);
    check(grant.implementation_revision === batch.implementation_revision, `cycle ${index + 1} grant implementation`);
    check(grant.control_revision === batch.control_revision, `cycle ${index + 1} grant control`);
    check(
      grant.static_control_sha256 === bindings.static_control_commitment,
      `cycle ${index + 1} grant control binding`,
    );
    check(grant.rootfs_descriptor_sha256 === bindings.rootfs_descriptor_commitment, `cycle ${index + 1} grant rootfs`);
    check(grant.ami_commitment === bindings.ami_commitment, `cycle ${index + 1} grant AMI`);
    check(
      grant.grant_commitment === commitmentWithout("cogs.stage2-cycle-launch-grant/v1", grant, "grant_commitment"),
      `cycle ${index + 1} grant commitment preimage`,
    );
    check(cycleCommitments[index] === cycle.cycle_commitment, `cycle ${index + 1} commitment`);
    journalEvents.push([
      "cycle",
      "opened",
      grant.ordinal as ExactJson,
      grant.mode as ExactJson,
      string(grant.grant_commitment, "grant commitment"),
    ]);

    const cycleEffects = object(cycle.effects, `evidence effects ${index + 1}`);
    const rawEffects = array(effects[index], `continuation effects ${index + 1}`);
    let previousSettlement: string | null = null;
    for (const [effectIndex, kind] of ["plan", "apply", "running", "destroy"].entries()) {
      const rawEffect = object(rawEffects[effectIndex], `continuation ${kind}`);
      check(rawEffect.kind === kind, `cycle ${index + 1} effect kind`);
      check(
        rawEffect.grant_commitment === grant.grant_commitment &&
          rawEffect.batch_commitment === batch.commitment &&
          equivalent(rawEffect.ordinal, grant.ordinal) &&
          rawEffect.mode === grant.mode &&
          rawEffect.ami_commitment === bindings.ami_commitment &&
          rawEffect.invocation_count === 1n &&
          rawEffect.certain === true,
        `cycle ${index + 1} effect envelope`,
      );
      const expectedIntent = packageCommitment("cogs.stage2-provider-effect-intent/v1", {
        kind,
        grant: grant.grant_commitment as ExactJson,
        previous: previousSettlement,
      });
      check(rawEffect.intent_commitment === expectedIntent, `cycle ${index + 1} ${kind} intent preimage`);
      check(
        rawEffect.settlement_commitment ===
          commitmentWithout("cogs.stage2-provider-effect-settlement/v1", rawEffect, "settlement_commitment"),
        `cycle ${index + 1} ${kind} settlement preimage`,
      );
      previousSettlement = string(rawEffect.settlement_commitment, "settlement commitment");
      journalEvents.push([
        "effect",
        "intent",
        grant.ordinal as ExactJson,
        grant.mode as ExactJson,
        string(rawEffect.intent_commitment, "intent commitment"),
      ]);
      journalEvents.push([
        "effect",
        "settled",
        grant.ordinal as ExactJson,
        grant.mode as ExactJson,
        previousSettlement,
      ]);
      journalEvents.push(["receipt", kind, grant.ordinal as ExactJson, grant.mode as ExactJson, previousSettlement]);
      requireEquivalent(projectEffect(rawEffect), cycleEffects[kind], `cycle ${index + 1} ${kind} projection`);
    }
    const plan = object(rawEffects[0], "plan effect");
    const apply = object(rawEffects[1], "apply effect");
    const running = object(rawEffects[2], "running effect");
    const destroy = object(rawEffects[3], "destroy effect");
    check(
      plan.identity_commitment === grant.plan_sha256 &&
        plan.state_commitment === apply.state_commitment &&
        apply.state_commitment === running.state_commitment &&
        running.state_commitment === destroy.state_commitment &&
        plan.state_lineage_commitment === apply.state_lineage_commitment &&
        apply.state_lineage_commitment === running.state_lineage_commitment &&
        running.state_lineage_commitment === destroy.state_lineage_commitment &&
        apply.state_bytes_sha256 !== "0".repeat(64) &&
        running.state_bytes_sha256 === apply.state_bytes_sha256 &&
        integer(plan.observed_ended_unix_ns, "plan end") < integer(apply.observed_started_unix_ns, "apply start") &&
        integer(apply.observed_ended_unix_ns, "apply end") <
          integer(running.observed_started_unix_ns, "running start") &&
        integer(running.observed_ended_unix_ns, "running end") <
          integer(destroy.observed_started_unix_ns, "destroy start") &&
        (previousZero === undefined || integer(plan.observed_started_unix_ns, "plan start") > previousZero),
      `cycle ${index + 1} raw effect lineage`,
    );

    const remote = object(remotes[index], `continuation remote ${index + 1}`);
    const evidenceRemote = object(cycle.remote, `evidence remote ${index + 1}`);
    const remoteBindings = object(remote.bindings, `continuation bindings ${index + 1}`);
    check(
      remote.grant_commitment === grant.grant_commitment &&
        remote.batch_commitment === batch.commitment &&
        equivalent(remote.ordinal, grant.ordinal) &&
        remote.mode === grant.mode &&
        remote.state_commitment === apply.state_commitment &&
        remote.state_lineage_commitment === apply.state_lineage_commitment &&
        remote.instance_commitment === running.identity_commitment &&
        equivalent(remote.provider_launch_started_unix_ns, apply.observed_started_unix_ns) &&
        equivalent(remote.provider_running_observed_unix_ns, running.observed_ended_unix_ns) &&
        remote.rootfs_descriptor_sha256 === bindings.rootfs_descriptor_commitment &&
        remote.ami_commitment === bindings.ami_commitment &&
        remote.certain === true,
      `cycle ${index + 1} raw remote envelope`,
    );
    const source = object(remoteBindings.source, "remote source bindings");
    const qemu = object(remoteBindings.qemu, "remote qemu bindings");
    check(
      packageCommitment("cogs.stage2-source-bindings/v1", exactObject(source)) ===
        bindings.source_bindings_commitment &&
        source.source_head === batch.implementation_revision &&
        source.source_manifest_sha256 === bindings.source_manifest_commitment &&
        source.runtime_manifest_sha256 === bindings.runtime_manifest_sha256 &&
        source.rootfs_descriptor_sha256 === bindings.rootfs_descriptor_commitment &&
        source.rootfs_package_manifest_sha256 === bindings.rootfs_package_manifest_commitment &&
        source.rootfs_provenance_sha256 === bindings.rootfs_provenance_commitment &&
        source.rootfs_publication_receipt_sha256 === bindings.rootfs_publication_receipt_commitment &&
        source.final_pin_sha256 === bindings.fixture_commitment,
      `cycle ${index + 1} raw source bindings`,
    );
    const qemuIdentity: { [key: string]: ExactJson } = {};
    for (const name of [
      "qemu_argv_sha256",
      "qemu_pid",
      "qemu_starttime",
      "qemu_executable_device",
      "qemu_executable_inode",
      "observer_qmp_device",
      "observer_qmp_inode",
      "kvm_device",
      "kvm_inode",
      "kvm_rdev",
      "kvm_api",
      "qmp_present",
      "qmp_enabled",
    ])
      qemuIdentity[name] = qemu[name] as ExactJson;
    check(
      qemu.operation_token === remote.operation_commitment &&
        qemu.runtime_identity_sha256 === packageCommitment("cogs.stage2-qemu-runtime-identity/v1", qemuIdentity, true),
      `cycle ${index + 1} raw runtime identity`,
    );
    requireEquivalent(
      array(remote.workloads, "remote workloads"),
      cycle.workloads === undefined ? [] : cycle.workloads,
      `cycle ${index + 1} raw workloads`,
    );
    requireEquivalent(
      {
        host_receipt_commitment: remote.host_receipt_commitment,
        instance_commitment: remote.instance_commitment,
        operation_commitment: remote.operation_commitment,
        host_boot_commitment: remote.host_boot_commitment,
        apply_to_running_ns:
          integer(remote.provider_running_observed_unix_ns, "remote running") -
          integer(remote.provider_launch_started_unix_ns, "remote launch"),
        kata_launch_to_ssh_ready_ns:
          integer(remote.ssh_ready_observed_boottime_ns, "remote SSH") -
          integer(remote.kata_launch_started_boottime_ns, "remote Kata"),
        bindings: {
          source_bindings: remoteBindings.source,
          cycle_capability_sha256: remoteBindings.cycle_capability_sha256,
          program_sha256: remoteBindings.program_sha256,
          parser_source_sha256: remoteBindings.parser_source_sha256,
          marker_sha256: remoteBindings.marker_sha256,
          qemu: remoteBindings.qemu,
        },
      },
      evidenceRemote,
      `cycle ${index + 1} remote projection`,
    );

    const continuationInventory = object(continuationInventories[index], `continuation inventory ${index + 1}`);
    check(
      continuationInventory.batch_commitment === batch.commitment &&
        equivalent(continuationInventory.observation_sequence, grant.ordinal) &&
        equivalent(continuationInventory.cycle_ordinal, grant.ordinal) &&
        continuationInventory.account_commitment === bindings.account_commitment &&
        continuationInventory.region === "us-east-1" &&
        continuationInventory.destroyed_state_commitment === destroy.state_commitment &&
        integer(continuationInventory.observed_started_unix_ns, "inventory start") >
          integer(destroy.observed_ended_unix_ns, "destroy end") &&
        integer(continuationInventory.observed_ended_unix_ns, "inventory end") <
          integer(continuation.cleanup_deadline_unix_ns, "cleanup deadline") &&
        (previousZero === undefined ||
          integer(continuationInventory.observed_started_unix_ns, "inventory start") > previousZero) &&
        continuationInventory.certain === true,
      `cycle ${index + 1} raw inventory envelope`,
    );
    const rawPages = array(continuationInventory.pages, "raw inventory pages");
    for (const rawPageValue of rawPages) {
      const rawPage = object(rawPageValue, "raw inventory page");
      check(
        rawPage.page_commitment === commitmentWithout("cogs.stage2-inventory-page/v2", rawPage, "page_commitment"),
        `cycle ${index + 1} page commitment`,
      );
    }
    const zeroFields: { [key: string]: ExactJson } = {
      batch_commitment: continuationInventory.batch_commitment as ExactJson,
      observation_sequence: continuationInventory.observation_sequence as ExactJson,
      cycle_ordinal: continuationInventory.cycle_ordinal as ExactJson,
      observer_commitment: continuationInventory.observer_commitment as ExactJson,
      session_commitment: continuationInventory.session_commitment as ExactJson,
      run_commitment: continuationInventory.run_commitment as ExactJson,
      account_commitment: continuationInventory.account_commitment as ExactJson,
      region: continuationInventory.region as ExactJson,
      destroyed_state_commitment: continuationInventory.destroyed_state_commitment as ExactJson,
      observed_started_unix_ns: continuationInventory.observed_started_unix_ns as ExactJson,
      observed_ended_unix_ns: continuationInventory.observed_ended_unix_ns as ExactJson,
      page_commitments: rawPages.map((value) => object(value, "raw page").page_commitment as ExactJson),
    };
    check(
      continuationInventory.zero_commitment === packageCommitment("cogs.stage2-zero-inventory/v2", zeroFields),
      `cycle ${index + 1} zero commitment`,
    );
    requireEquivalent(
      projectInventory(continuationInventory),
      inventories[index],
      `cycle ${index + 1} inventory projection`,
    );
    previousZero = integer(continuationInventory.observed_ended_unix_ns, "inventory end");
    const rawCost = object(costs[index], `continuation cost ${index + 1}`);
    const evidenceCost = object(cycle.cost, `evidence cost ${index + 1}`);
    for (const field of ["receipt_commitment", "rate_source_commitment", "usage_commitment", "cost_micro_usd"])
      check(equivalent(rawCost[field], evidenceCost[field]), `cycle ${index + 1} cost ${field}`);
    check(
      rawCost.grant_commitment === grant.grant_commitment &&
        equivalent(rawCost.cycle_ordinal, grant.ordinal) &&
        rawCost.receipt_commitment === commitmentWithout("cogs.stage2-cost-receipt/v1", rawCost, "receipt_commitment"),
      `cycle ${index + 1} raw cost receipt`,
    );
    const duration =
      integer(object(rawEffects[3], "destroy").observed_ended_unix_ns, "destroy end") -
      integer(object(rawEffects[1], "apply").observed_started_unix_ns, "apply start");
    check(duration > 0n && duration < PACKAGE_MAXIMUM_CYCLE_NS, `cycle ${index + 1} duration bound`);
    check(
      integer(evidenceCost.billable_duration_ns, "billable duration") === duration,
      `cycle ${index + 1} billable duration`,
    );
    check(
      rawCost.usage_commitment === packageCommitment("cogs.stage2-provider-usage/v1", { duration_ns: duration }),
      `cycle ${index + 1} usage commitment`,
    );
    const expectedCycle = packageCommitment("cogs.stage2-production-cycle/v2", {
      grant: grant.grant_commitment as ExactJson,
      effects: rawEffects.map((value) => object(value, "raw effect").settlement_commitment as ExactJson),
      remote: remote.host_receipt_commitment as ExactJson,
      zero: continuationInventory.zero_commitment as ExactJson,
      cost: rawCost.receipt_commitment as ExactJson,
    });
    check(cycleCommitments[index] === expectedCycle, `cycle ${index + 1} raw cycle commitment`);
    journalEvents.push([
      "cycle",
      "sealed",
      grant.ordinal as ExactJson,
      grant.mode as ExactJson,
      string(cycleCommitments[index], "cycle commitment"),
    ]);
    const runningResources = Object.fromEntries(
      array(running.resource_commitments, "running resources").map((row) => {
        const pair = array(row, "resource pair");
        return [string(pair[0], "resource name"), string(pair[1], "resource commitment")];
      }),
    );
    for (const [name, value] of [
      ["state", apply.state_commitment],
      ["lineage", apply.state_lineage_commitment],
      ["instance", remote.instance_commitment],
      ["operation", remote.operation_commitment],
      ["boot", remote.host_boot_commitment],
      ["runtime", qemu.runtime_identity_sha256],
      ["mapping", qemu.live_mapping_sha256],
      ["pre", qemu.pre_ssh_runtime_fact_sha256],
      ["client", remote.client_key_commitment],
      ["host", remote.host_key_commitment],
      ["resource", runningResources.instance],
    ] as const)
      unique[name]?.push(string(value, `${name} identity`));
    if (qemu.post_ssh_runtime_fact_sha256 !== null)
      postSsh.push(string(qemu.post_ssh_runtime_fact_sha256, "post-SSH identity"));
  }
  check(
    integer(continuation.first_apply_unix_ns, "continuation first apply") ===
      integer(
        object(array(effects[0], "first effects")[1], "first apply").observed_started_unix_ns,
        "first apply time",
      ),
    "first apply raw binding",
  );
  let journalSequence = 0n;
  let journalTip = "0".repeat(64);
  for (const [category, event, ordinal, mode, commitment] of journalEvents) {
    const row = {
      version: "cogs.stage2-production-campaign-journal/v1",
      sequence: journalSequence,
      previous_sha256: journalTip,
      category,
      event,
      ordinal,
      mode,
      commitment,
    };
    journalTip = rawSha256(row);
    journalSequence += 1n;
  }
  check(
    integer(continuation.journal_sequence, "journal sequence") === journalSequence &&
      continuation.journal_tip_sha256 === journalTip,
    "raw journal checkpoint",
  );
  check(
    Object.values(unique).every((values) => values.length === 3 && new Set(values).size === 3) &&
      postSsh.length === 2 &&
      new Set(postSsh).size === 2 &&
      new Set([...(unique.pre ?? []), ...postSsh]).size === 5 &&
      new Set([...(unique.client ?? []), ...(unique.host ?? [])]).size === 6,
    "continuation freshness",
  );
  check(
    integer(continuation.cumulative_cost_micro_usd, "continuation cumulative cost") ===
      costs.reduce<bigint>((sum, item) => sum + integer(object(item, "continuation cost").cost_micro_usd, "cost"), 0n),
    "continuation cumulative cost",
  );
  check(integer(cost.approved_maximum_micro_usd, "approved maximum") === 1_100_000n, "exact approved maximum");
}

function renderPackageReport(value: CompletionEvidence): string {
  const lines = [
    "# AWS Stage 2 completion report v4",
    "",
    "Status: pass-only rendering of validated, redacted completion evidence.",
    "",
    "## Batch",
    "",
    `- Implementation revision: \`${value.batch.implementation_revision}\``,
    `- Batch commitment: \`${value.batch.commitment}\``,
    "- Cycles: 7 (one full, six readiness)",
    "- Fixed handoff boundary: after cycle 3",
    `- Continuation artifact digest: \`${value.custody.handoff.continuation_artifact_digest}\``,
    `- Handoff authentication commitment: \`${value.custody.handoff.continuation_admission_commitment}\``,
    "",
    "## Measurements",
    "",
    "| Cycle | Mode | Apply to running | Kata launch to SSH ready | Cost |",
    "| ---: | --- | ---: | ---: | ---: |",
    ...value.cycles.map(
      (cycle) =>
        `| ${cycle.ordinal} | ${cycle.mode} | ${cycle.remote.apply_to_running_ns} ns | ${cycle.remote.kata_launch_to_ssh_ready_ns} ns | ${cycle.cost.cost_micro_usd} micro-USD |`,
    ),
    "",
    "- Full-cycle workload measurements: 21",
    `- Actual first-apply through final-zero duration: ${value.deadlines.actual_campaign_duration_ns} ns`,
    "",
    "## Cleanup and cost",
    "",
    "- State-bound destroy attempts: 7",
    "- Detailed inventory observations: 8",
    `- Final zero commitment: \`${value.cleanup.final_zero_commitment}\``,
    `- Aggregate cost: ${value.cost.aggregate_cost_micro_usd} micro-USD`,
    "",
    "## Limitations",
    "",
    ...value.limitations.map((item) => `- ${item}`),
  ];
  return `${lines.join("\n")}\n`;
}

export function validateAwsStage2CompletionPackage(directoryPath: string): void {
  let directory: string;
  try {
    directory = fs.realpathSync(resolve(directoryPath));
    const identity = fs.lstatSync(directory);
    check(identity.isDirectory() && !identity.isSymbolicLink(), "package directory identity");
    const entries = fs.readdirSync(directory);
    check(
      entries.length === EXPECTED_NAMES.size && entries.every((name) => EXPECTED_NAMES.has(name)),
      "exact package inventory",
    );
  } catch (error) {
    if (error instanceof CompletionPackageValidationError) throw error;
    fail("package directory unavailable");
  }
  const raw = Object.fromEntries(
    Object.entries(NAMES).map(([key, name]) => [key, readExactFile(directory, name)]),
  ) as Record<keyof typeof NAMES, Buffer>;
  let validated: ValidatedCompletionEvidence;
  try {
    validated = parseAwsStage2CompletionEvidence(raw.evidence.toString("utf8"));
  } catch (error) {
    if (error instanceof CompletionEvidenceValidationError) fail("evidence validation");
    fail("evidence validation internal");
  }
  check(raw.report.toString("utf8") === renderPackageReport(validated.evidence), "deterministic report");
  const schema = getValidators();
  const publication = parseCanonical(raw.publication, schema.publication, "publication");
  const continuation = parseCanonical(raw.continuation, schema.continuation, "continuation");
  const admission = parseCanonical(raw.admission, schema.admission, "admission");
  crossValidate(validated.evidence as unknown as JsonObject, publication, continuation, admission, raw);
}

export function runAwsStage2CompletionPackageCli(args: readonly string[]): 0 | 2 {
  try {
    const [directory] = args;
    if (!directory || args.length !== 1) fail("usage");
    validateAwsStage2CompletionPackage(directory);
    process.stdout.write("Validated closed AWS Stage 2 completion package v4.\n");
    return 0;
  } catch {
    process.stderr.write("completion-package-v4: rejected\n");
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  process.exitCode =
    args[0] === "--package" ? runAwsStage2CompletionPackageCli(args.slice(1)) : runAwsStage2CompletionEvidenceCli(args);
}

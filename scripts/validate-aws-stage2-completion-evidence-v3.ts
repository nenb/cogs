import { createHash } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
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
      resolve(import.meta.dirname, "../schemas/aws-stage2-completion-evidence-v3.json"),
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
  version: "cogs.aws-stage2-completion-evidence/v3";
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
  usage: "completion-evidence-v3: usage\n",
  file: "completion-evidence-v3: file\n",
  json: "completion-evidence-v3: json\n",
  schema: "completion-evidence-v3: schema\n",
  validation: "completion-evidence-v3: validation\n",
  internal: "completion-evidence-v3: internal\n",
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
  check(effectDeadline > firstApply, "effect deadline order");
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
    check(cycle.cost.billable_duration_ns === duration, `cycle ${index + 1} billable duration`);
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
    output.stdout("Validated closed AWS Stage 2 completion evidence v3.\n");
    return 0;
  } catch (error) {
    try {
      output.stderr(completionEvidenceCliDiagnostic(error));
    } catch {}
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = runAwsStage2CompletionEvidenceCli(process.argv.slice(2));
}

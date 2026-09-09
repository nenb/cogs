import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs, { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  renderAwsStage2CompletionReport,
  runAwsStage2CompletionReportCli,
} from "../scripts/render-aws-stage2-completion-report-v3.ts";
import { parseAwsStage2CompletionEvidence as parseHistorical } from "../scripts/validate-aws-stage2-completion-evidence-v2.ts";
import {
  CompletionEvidenceValidationError,
  completionEvidenceCliDiagnostic,
  parseAwsStage2CompletionEvidence,
  runAwsStage2CompletionEvidenceCli,
  validateAwsStage2CompletionEvidence,
} from "../scripts/validate-aws-stage2-completion-evidence-v3.ts";

const root = join(import.meta.dirname, "..");
const fakeAwsAccessKey = ["AKIA", "ABCDEFGHIJKLMNOP"].join("");
// Generated only by the explicitly test-only in-process controller harness.
const raw = (): string =>
  readFileSync(join(root, "test/fixtures/stage2-completion/production-v3-test-only.json"), "utf8");
const issuerReport = (): string =>
  readFileSync(join(root, "test/fixtures/stage2-completion/production-v3-test-only.md"), "utf8");
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

const cliEvidence = join(root, "test/fixtures/stage2-completion/production-v3-test-only.json");
const cliRoutes = [
  { run: runAwsStage2CompletionEvidenceCli, args: [cliEvidence] },
  { run: runAwsStage2CompletionReportCli, args: [cliEvidence, "/sensitive/report.md"] },
] as const;

function captureCli(run: typeof runAwsStage2CompletionEvidenceCli, args: readonly string[]) {
  let stdout = "";
  let stderr = "";
  const code = run(args, {
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
  });
  return { code, stdout, stderr };
}
function cliFailure(category: string) {
  return { code: 2, stdout: "", stderr: `completion-evidence-v3: ${category}\n` };
}

// Run before the first successful validation: initialization must be lazy and
// guarded on BOTH CLI routes. No subprocesses or on-disk fixture changes.
test("CLI catches schema read, malformed, duplicate and compile failures without leaking diagnostics", (t) => {
  const sensitive = `/secret/${fakeAwsAccessKey}/schema.json`;
  for (const schemaFailure of [
    new Error(`${sensitive}\nstack and exception text`),
    "{bad JSON",
    '{"type":"object","type":"string"}',
    `{"type":${JSON.stringify(sensitive)}}`,
    `{"$ref":${JSON.stringify(sensitive)}}`,
  ]) {
    for (const { run, args } of cliRoutes) {
      let reads = 0;
      t.mock.method(fs, "readFileSync", () => {
        reads += 1;
        if (schemaFailure instanceof Error) throw schemaFailure;
        return schemaFailure;
      });
      assert.deepEqual(captureCli(run, args), cliFailure("schema"));
      assert.equal(reads, 1, "must exercise schema initialization inside the boundary");
      t.mock.restoreAll();
    }
  }
});

test("CLI input read is bounded, no-follow, regular, single-link, and exact", () => {
  const directory = fs.mkdtempSync(join(tmpdir(), "cogs-evidence-v3-"));
  try {
    const oversized = join(directory, "oversized.json");
    fs.writeFileSync(oversized, Buffer.alloc(256 * 1024 + 1, 0x20));
    const symlink = join(directory, "symlink.json");
    fs.symlinkSync(cliEvidence, symlink);
    const base = join(directory, "base.json");
    const linked = join(directory, "linked.json");
    fs.writeFileSync(base, raw());
    fs.linkSync(base, linked);
    for (const path of [oversized, symlink, linked])
      assert.deepEqual(captureCli(runAwsStage2CompletionEvidenceCli, [path]), cliFailure("file"));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("test-only canonical v3 projection validates and renderer requires its validator token", () => {
  assert.throws(() => parseHistorical(raw()), /version|runtime/u);
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

test("all six cycle boundaries require a plan strictly after the prior zero ends", () => {
  for (let index = 1; index < 7; index++) {
    for (const boundaryOffset of [-1n, 0n, 1n]) {
      const value = fixture();
      const cycle = value.cycles[index];
      cycle.effects.plan.observed_started_unix_ns = (
        BigInt(value.inventories[index - 1].observed_ended_unix_ns) + boundaryOffset
      ).toString();
      if (boundaryOffset > 0n) validateAwsStage2CompletionEvidence(value);
      else assert.throws(() => parseAwsStage2CompletionEvidence(`${canonical(value)}\n`), /overlaps prior zero/u);
    }
    const value = fixture();
    const prior = value.cycles[index - 1];
    const cycle = value.cycles[index];
    // Keep within-cycle ordering, durations, summaries, costs, and inventories
    // unchanged while moving the entire next effect interval onto the prior one.
    for (const effect of ["plan", "apply", "running", "destroy"])
      for (const field of ["observed_started_unix_ns", "observed_ended_unix_ns"])
        cycle.effects[effect][field] = prior.effects[effect][field];
    assert.throws(() => parseAwsStage2CompletionEvidence(`${canonical(value)}\n`), /overlaps prior zero/u);
  }
  reject((value) => {
    value.deadlines.first_apply_unix_ns = (BigInt(value.deadlines.first_apply_unix_ns) - 1n).toString();
    value.deadlines.actual_campaign_duration_ns++;
    value.cost.actual_campaign_duration_ns++;
  }, "independently fabricated first apply with coherent wall duration");
  reject((value) => {
    const deadline = BigInt(value.deadlines.effect_deadline_unix_ns) + BigInt(value.deadlines.cleanup_reserve_ns);
    value.inventories[7].observed_ended_unix_ns = deadline.toString();
    value.deadlines.final_zero_unix_ns = deadline.toString();
    value.deadlines.actual_campaign_duration_ns = Number(deadline - BigInt(value.deadlines.first_apply_unix_ns));
    value.cost.actual_campaign_duration_ns = value.deadlines.actual_campaign_duration_ns;
  }, "final zero at cleanup deadline, even before expiry");
});

test("every available binding rejects an independent schema-valid contradictory digest", () => {
  // Each mutation stands alone; another contradictory field must not mask it.
  const paths: string[][] = [
    ...["commitment", "implementation_revision", "control_revision"].map((key) => ["batch", key]),
    ...[
      "source_manifest_commitment",
      "source_bindings_commitment",
      "static_control_commitment",
      "rootfs_descriptor_commitment",
      "rootfs_package_manifest_commitment",
      "rootfs_provenance_commitment",
      "rootfs_publication_receipt_commitment",
      "runtime_manifest_sha256",
      "fixture_commitment",
      "account_commitment",
      "ami_commitment",
    ].map((key) => ["bindings", key]),
    ["cost", "rate_source_commitment"],
  ];
  const original = fixture();
  for (let index = 0; index < 7; index++) {
    const prefix = ["cycles", String(index)];
    paths.push(
      ...["grant_commitment", "cycle_commitment", "plan_sha256", "zero_inventory_commitment"].map((key) => [
        ...prefix,
        key,
      ]),
      ...["plan", "apply", "running", "destroy"].flatMap((effect) =>
        ["state_commitment", "state_lineage_commitment", "settlement_commitment"].map((key) => [
          ...prefix,
          "effects",
          effect,
          key,
        ]),
      ),
      [...prefix, "effects", "plan", "identity_commitment"],
      [...prefix, "effects", "running", "identity_commitment"],
      ...["host_receipt_commitment", "host_boot_commitment", "operation_commitment", "instance_commitment"].map(
        (key) => [...prefix, "remote", key],
      ),
      ...["host_boot", "operation"].map((key) => [...prefix, "freshness", key]),
      ...["receipt_commitment", "rate_source_commitment", "usage_commitment"].map((key) => [...prefix, "cost", key]),
      ...Object.keys(original.cycles[index].remote.bindings.source_bindings).map((key) => [
        ...prefix,
        "remote",
        "bindings",
        "source_bindings",
        key,
      ]),
      ...["cycle_capability_sha256", "program_sha256", "parser_source_sha256", "marker_sha256"].map((key) => [
        ...prefix,
        "remote",
        "bindings",
        key,
      ]),
      ...["runtime_identity_sha256", "operation_token", "qemu_argv_sha256"].map((key) => [
        ...prefix,
        "remote",
        "bindings",
        "qemu",
        key,
      ]),
      ["cleanup", "cycle_zero_commitments", String(index)],
    );
  }
  for (let index = 0; index < 8; index++)
    for (const key of ["account_commitment", "region_commitment", "destroyed_state_commitment", "zero_commitment"])
      paths.push(["inventories", String(index), key]);
  paths.push(["cleanup", "final_zero_commitment"]);
  for (const path of paths) {
    const value = fixture();
    const parent = path.slice(0, -1).reduce((item, key) => item[key], value);
    const key = path.at(-1);
    assert.ok(key);
    const replacement = (String(parent[key]).startsWith("e") ? "f" : "e").repeat(parent[key].length);
    assert.notEqual(parent[key], replacement);
    parent[key] = replacement;
    assert.throws(
      () => parseAwsStage2CompletionEvidence(`${canonical(value)}\n`),
      (error: unknown) => error instanceof CompletionEvidenceValidationError && error.category === "validation",
      path.join("."),
    );
  }

  // Fixed-rate binding cannot be bypassed by coherently replacing every copy.
  reject((value) => {
    value.cost.rate_source_commitment = "e".repeat(64);
    for (const cycle of value.cycles) cycle.cost.rate_source_commitment = value.cost.rate_source_commitment;
  }, "coherent contradictory fixed-rate source");
  reject((value) => {
    const substituted = "e".repeat(64);
    for (const effect of Object.values(value.cycles[2].effects) as Array<{ state_commitment: string }>)
      effect.state_commitment = substituted;
    value.inventories[2].destroyed_state_commitment = substituted;
  }, "coherent contradictory state slot");
  reject((value) => {
    const substituted = "e".repeat(64);
    for (const effect of Object.values(value.cycles[2].effects) as Array<{ state_lineage_commitment: string }>)
      effect.state_lineage_commitment = substituted;
  }, "coherent contradictory state lineage");
  reject((value) => {
    value.cycles[0].workloads[0].commitment = "e".repeat(64);
  }, "wrong workload result commitment");
  // Rehashing all source projections must not bypass their top-level equalities.
  for (const key of [
    "source_manifest_sha256",
    "runtime_manifest_sha256",
    "rootfs_descriptor_sha256",
    "rootfs_package_manifest_sha256",
    "rootfs_provenance_sha256",
    "rootfs_publication_receipt_sha256",
    "final_pin_sha256",
  ])
    reject((value) => {
      for (const cycle of value.cycles) cycle.remote.bindings.source_bindings[key] = "e".repeat(64);
      value.bindings.source_bindings_commitment = createHash("sha256")
        .update("cogs.stage2-source-bindings/v1\0")
        .update(canonical(value.cycles[0].remote.bindings.source_bindings))
        .digest("hex");
    }, `rehashed contradictory ${key}`);
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
  for (const field of ["live_mapping_sha256", "pre_ssh_runtime_fact_sha256", "post_ssh_runtime_fact_sha256"])
    reject((value) => {
      value.cycles[4].remote.bindings.qemu[field] = value.cycles[3].remote.bindings.qemu[field];
    }, `${field} replay`);
  reject((value) => {
    value.cycles[4].remote.bindings.qemu.post_ssh_runtime_fact_sha256 =
      value.cycles[3].remote.bindings.qemu.pre_ssh_runtime_fact_sha256;
  }, "pre fact replayed as post");
  reject((value) => {
    value.cycles[4].remote.bindings.qemu.pre_ssh_runtime_fact_sha256 =
      value.cycles[3].remote.bindings.qemu.post_ssh_runtime_fact_sha256;
  }, "post fact replayed as pre");
  reject((value) => {
    value.cycles[4].effects.apply.state_commitment = value.cycles[3].effects.apply.state_commitment;
  }, "cycle state graft");
  reject((value) => {
    value.cycles[2].effects.running.state_lineage_commitment = value.bindings.runtime_manifest_sha256;
  }, "within-cycle lineage drift");
  reject((value) => {
    value.cycles[4].freshness.instance = value.cycles[3].freshness.instance;
  }, "instance resource replay");
  reject((value) => {
    value.cycles[4].freshness.root_volume = value.cycles[3].freshness.root_volume;
  }, "root volume replay");
  reject((value) => {
    value.cycles[2].freshness.client_ssh_identity = value.cycles[2].freshness.host_ssh_identity;
  }, "within-cycle SSH key graft");
  reject((value) => {
    value.cycles[4].freshness.client_ssh_identity = value.cycles[3].freshness.host_ssh_identity;
  }, "cross-cycle cross-role SSH key replay");
});

test("public schema preserves private QEMU and workload bounds", () => {
  for (const [label, change] of [
    ["QEMU PID 1", (value) => (value.cycles[0].remote.bindings.qemu.qemu_pid = 1)],
    ["zero KVM device identity", (value) => (value.cycles[0].remote.bindings.qemu.kvm_rdev = 0)],
    [
      "workload duration above private bound",
      (value) => (value.cycles[0].workloads[0].duration_ns = 1_200_000_000_001),
    ],
  ] as Array<[string, (value: ReturnType<typeof fixture>) => void]>) {
    const value = fixture();
    change(value);
    assert.throws(
      () => parseAwsStage2CompletionEvidence(`${canonical(value)}\n`),
      (error: unknown) => error instanceof CompletionEvidenceValidationError && error.category === "schema",
      label,
    );
  }
});

test("serialized evidence independently revalidates exact remote source, parser, and QEMU bindings", () => {
  const value = fixture();
  const readiness = value.cycles[1].remote.bindings;
  assert.notEqual(readiness.qemu.pre_ssh_runtime_fact_sha256, readiness.qemu.post_ssh_runtime_fact_sha256);
  assert.equal(readiness.source_bindings.source_head, value.batch.implementation_revision);
  assert.equal(readiness.source_bindings.runtime_manifest_sha256, value.bindings.runtime_manifest_sha256);
  assert.equal(
    new Set(
      value.cycles.map((cycle: (typeof value.cycles)[number]) => cycle.remote.bindings.qemu.runtime_identity_sha256),
    ).size,
    7,
  );
  assert.notEqual(readiness.qemu.runtime_identity_sha256, value.bindings.runtime_manifest_sha256);
  reject((item) => {
    item.version = "cogs.aws-stage2-completion-evidence/v2";
  }, "historical version");
  reject((item) => {
    item.bindings.runtime_commitment = item.bindings.runtime_manifest_sha256;
    delete item.bindings.runtime_manifest_sha256;
  }, "historical batch runtime commitment");
  reject((item) => {
    const source = item.cycles[1].remote.bindings.source_bindings;
    source.runtime_attestation_sha256 = source.runtime_manifest_sha256;
    delete source.runtime_manifest_sha256;
  }, "historical live source binding");
  reject((item) => {
    item.bindings.runtime_manifest_sha256 = "0".repeat(64);
  }, "static manifest drift");
  reject((item) => {
    item.cycles[1].remote.bindings.source_bindings.host_attestation_sha256 = "0".repeat(64);
  }, "authenticated source projection drift");
  reject((item) => {
    item.cycles[1].remote.bindings.parser_source_sha256 = "0".repeat(64);
  }, "authenticated parser projection drift");
  reject((item) => {
    item.cycles[1].remote.bindings.qemu.qemu_pid += 1;
  }, "immutable QEMU identity drift");
  reject((item) => {
    item.cycles[1].remote.bindings.qemu.post_ssh_runtime_fact_sha256 =
      item.cycles[1].remote.bindings.qemu.pre_ssh_runtime_fact_sha256;
  }, "post-SSH observation replay");
  reject((item) => {
    item.cycles[2].remote.bindings.qemu.runtime_identity_sha256 =
      item.cycles[1].remote.bindings.qemu.runtime_identity_sha256;
  }, "cross-cycle QEMU identity replay");
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
    fakeAwsAccessKey,
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

test("CLI failures have exact bounded allowlisted stderr and exit 2, without subprocesses", () => {
  const valid = raw();
  const sensitive = `arn:aws:iam::123456789012:role/secret\n${fakeAwsAccessKey}\n/secret/key`;
  const hugeKey = `${sensitive}${"x".repeat(120_000)}`;
  const duplicate = (key: string) => `{${JSON.stringify(key)}:0,${JSON.stringify(key)}:1}\n`;
  for (const key of [sensitive, hugeKey, "__proto__"]) {
    const body = duplicate(key);
    assert.ok(Buffer.byteLength(body) <= 262_144, "exercise duplicate rejection, not just the input bound");
    assert.throws(
      () => parseAwsStage2CompletionEvidence(body),
      (error: unknown) =>
        error instanceof CompletionEvidenceValidationError &&
        error.category === "json" &&
        error.message === "duplicate JSON key" &&
        error.cause === undefined,
    );
  }
  const schemaError = fixture();
  schemaError.cycles[1].remote.bindings.source_bindings[sensitive] = { [sensitive]: sensitive };
  const semanticError = fixture();
  semanticError.bindings.rootfs_publication_receipt_commitment = "e".repeat(64);
  const cases = [
    { body: duplicate(sensitive), category: "json" },
    { body: duplicate(hugeKey), category: "json" },
    { body: duplicate("x".repeat(140_000)), category: "json" }, // byte bound
    { body: '{"secret":0,"\\u0073ecret":1}\n', category: "json" },
    { body: `{"nested":${duplicate(sensitive).trim()}}\n`, category: "json" },
    { body: `{"${sensitive}":`, category: "json" },
    { body: `{"key":"\\q${sensitive}"}\n`, category: "json" },
    { body: "{\n", category: "json" },
    { body: "[1,]\n", category: "json" },
    { body: "true false\n", category: "json" },
    { body: `${"[".repeat(10_000)}0${"]".repeat(10_000)}\n`, category: "json" },
    { body: "", category: "json" },
    { body: valid.trim(), category: "json" },
    { body: ` ${valid}`, category: "json" },
    { body: `\uFEFF${valid}`, category: "json" },
    { body: "null\n", category: "schema" },
    { body: "{}\n", category: "schema" },
    { body: `${canonical(schemaError)}\n`, category: "schema" },
    { body: `${canonical(semanticError)}\n`, category: "validation" },
  ];
  const directory = fs.mkdtempSync(join(tmpdir(), "cogs-evidence-cli-"));
  try {
    for (const { run, args } of cliRoutes) {
      for (const invalidArgs of [[], [""], [...args, sensitive]])
        assert.deepEqual(captureCli(run, invalidArgs), cliFailure("usage"));
      const missing = join(directory, "missing.json");
      const missingArgs = args.length === 1 ? [missing] : [missing, join(directory, "missing.md")];
      assert.deepEqual(captureCli(run, missingArgs), cliFailure("file"));
      for (const [index, { body, category }] of cases.entries()) {
        const input = join(directory, `case-${index}.json`);
        const output = join(directory, `case-${index}.md`);
        fs.writeFileSync(input, body);
        const actual = captureCli(run, args.length === 1 ? [input] : [input, output]);
        const observedCategory = body.length === 0 || Buffer.byteLength(body) > 262_144 ? "file" : category;
        assert.deepEqual(actual, cliFailure(observedCategory));
        assert.ok(Buffer.byteLength(actual.stderr) <= 35);
        assert.equal(fs.existsSync(output), false);
      }
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
  assert.deepEqual(completionEvidenceCliDiagnostic(new Error(sensitive)), "completion-evidence-v3: internal\n");
  assert.equal(completionEvidenceCliDiagnostic({ category: sensitive }), "completion-evidence-v3: internal\n");
  assert.equal(
    completionEvidenceCliDiagnostic(
      Object.assign(new CompletionEvidenceValidationError(sensitive), { category: sensitive }),
    ),
    "completion-evidence-v3: internal\n",
  );
  assert.deepEqual(captureCli(runAwsStage2CompletionEvidenceCli, [cliEvidence]), {
    code: 0,
    stdout: "Validated closed AWS Stage 2 completion evidence v3.\n",
    stderr: "",
  });
  let diagnostic = "";
  assert.equal(
    runAwsStage2CompletionEvidenceCli([cliEvidence], {
      stdout: () => {
        throw new Error(sensitive);
      },
      stderr: (text) => {
        diagnostic += text;
      },
    }),
    2,
  );
  assert.equal(diagnostic, "completion-evidence-v3: internal\n");
  assert.equal(
    runAwsStage2CompletionEvidenceCli([], {
      stdout: () => {},
      stderr: () => {
        throw new Error(sensitive);
      },
    }),
    2,
  );
  assert.equal(
    runAwsStage2CompletionReportCli([], {
      stdout: () => {},
      stderr: () => {
        throw new Error(sensitive);
      },
    }),
    2,
  );
});

test("renderer holds and verifies output directory/file custody across writes and failures", (t) => {
  const directory = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "cogs-report-v3-")));
  const realOpen = fs.openSync.bind(fs);
  const realWrite = fs.writeSync.bind(fs);
  const realFsync = fs.fsyncSync.bind(fs);
  const realClose = fs.closeSync.bind(fs);
  const realRealpath = fs.realpathSync.bind(fs);
  try {
    for (const failure of [
      "file-open",
      "write",
      "short",
      "file-fsync",
      "file-close",
      "directory-open",
      "directory-fsync",
      "directory-close",
      "replacement",
      "none",
    ]) {
      const destination = join(directory, `${failure}.md`);
      const fail = (phase: string) => {
        if (failure === phase) throw new Error(`/secret/output ${fakeAwsAccessKey}`);
      };
      let written = "";
      let fileDescriptor = -1;
      let directoryDescriptor = -1;
      t.mock.method(fs, "openSync", (path: fs.PathLike, flags: string | number, mode?: number) => {
        if (resolve(String(path)) === resolve(directory)) {
          fail("directory-open");
          directoryDescriptor = realOpen(path, flags, mode);
          return directoryDescriptor;
        }
        if (resolve(String(path)) === resolve(destination)) {
          fail("file-open");
          fileDescriptor = realOpen(path, flags, mode);
          return fileDescriptor;
        }
        return realOpen(path, flags, mode);
      });
      t.mock.method(fs, "writeSync", (fd: number, buffer: Buffer) => {
        if (fd !== fileDescriptor) return realWrite(fd, buffer);
        fail("write");
        const selected = failure === "short" ? buffer.subarray(0, -1) : buffer;
        const count = realWrite(fd, selected);
        written += selected.toString("utf8");
        return count;
      });
      t.mock.method(fs, "fsyncSync", (fd: number) => {
        if (fd === fileDescriptor) fail("file-fsync");
        else if (fd === directoryDescriptor) {
          fail("directory-fsync");
          realFsync(fd);
          if (failure === "replacement") {
            fs.unlinkSync(destination);
            const replacement = realOpen(destination, "wx", 0o400);
            realWrite(replacement, Buffer.from("substituted\n"));
            realClose(replacement);
          }
          return;
        }
        return realFsync(fd);
      });
      t.mock.method(fs, "closeSync", (fd: number) => {
        const file = fd === fileDescriptor;
        const parent = fd === directoryDescriptor;
        realClose(fd);
        if (file) fail("file-close");
        if (parent) fail("directory-close");
      });
      const actual = captureCli(runAwsStage2CompletionReportCli, [cliEvidence, destination]);
      assert.deepEqual(actual, failure === "none" ? { code: 0, stdout: "", stderr: "" } : cliFailure("file"));
      if (failure === "none") {
        assert.equal(written, issuerReport());
        assert.equal(fs.readFileSync(destination, "utf8"), issuerReport());
      }
      t.mock.restoreAll();
    }
    let resolutions = 0;
    t.mock.method(fs, "realpathSync", (path: fs.PathLike) => {
      const value = realRealpath(path);
      if (resolve(String(value)) === resolve(directory) && ++resolutions === 3) return join(directory, "substituted");
      return value;
    });
    assert.deepEqual(
      captureCli(runAwsStage2CompletionReportCli, [cliEvidence, join(directory, "ancestor-race.md")]),
      cliFailure("file"),
    );
    t.mock.restoreAll();
    const target = join(directory, "target");
    const alias = join(directory, "alias");
    fs.mkdirSync(target, 0o700);
    fs.symlinkSync(target, alias, "dir");
    assert.deepEqual(
      captureCli(runAwsStage2CompletionReportCli, [cliEvidence, join(alias, "report.md")]),
      cliFailure("file"),
    );
    assert.equal(fs.existsSync(join(target, "report.md")), false);
    fs.chmodSync(target, 0o750);
    assert.deepEqual(
      captureCli(runAwsStage2CompletionReportCli, [cliEvidence, join(target, "report.md")]),
      cliFailure("file"),
    );
    const unsafe = join(directory, "unsafe");
    const privateChild = join(unsafe, "private");
    fs.mkdirSync(privateChild, { recursive: true, mode: 0o700 });
    fs.chmodSync(unsafe, 0o777);
    const unsafeOutput = join(privateChild, "report.md");
    assert.deepEqual(captureCli(runAwsStage2CompletionReportCli, [cliEvidence, unsafeOutput]), cliFailure("file"));
    assert.equal(fs.existsSync(unsafeOutput), false);
    fs.chmodSync(unsafe, 0o700);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
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

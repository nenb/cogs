import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import {
  buildStage5DestructiveFixtureSuite,
  canonicalStage5DestructiveBytes,
  runStage5DestructiveHarness,
  STAGE5_DESTRUCTIVE_FAULTS,
  STAGE5_DESTRUCTIVE_LIMITS,
  STAGE5_DESTRUCTIVE_ROUTES,
  STAGE5_DESTRUCTIVE_SOURCE_PATHS,
  type Stage5DestructiveReport,
  validateStage5DestructiveFixtureBytes,
  validateStage5DestructiveReportBytes,
} from "../scripts/stage5-destructive-harness.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const fixturePath = resolve(root, "test/fixtures/stage5-destructive/suite-v1.canonical-json");
const reportPath = resolve(root, "docs/security-evidence/stage5-destructive-harness-report.canonical-json");
const fixtureSchema = require("../schemas/stage5-destructive-fixture-suite-v1.json") as object;
const reportSchema = require("../schemas/stage5-destructive-report-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
ajv.addSchema(fixtureSchema);
const validateFixtureSchema = ajv.getSchema(
  "https://cogs.dev/schemas/stage5-destructive-fixture-suite-v1.json",
) as ValidateFunction;
const validateReportSchema = ajv.compile(reportSchema) as ValidateFunction;

type MutableAction = { seq: number; actor: string; action: string; resource: string | null };
type MutableCase = {
  id: string;
  fault: string;
  profile: string;
  applicability: string;
  prompt_state: string;
  owned_resources: string[];
  actions: MutableAction[];
};
type MutableSource = { path: string; bytes: Uint8Array };
type MutableSuite = {
  version: string;
  authority: string;
  execution: string;
  routes: Record<string, boolean>;
  cases: MutableCase[];
};

function bytes(path: string): Uint8Array {
  return new Uint8Array(readFileSync(path));
}

function suite(): MutableSuite {
  return JSON.parse(readFileSync(fixturePath, "utf8")) as MutableSuite;
}

function sources(): MutableSource[] {
  return STAGE5_DESTRUCTIVE_SOURCE_PATHS.map((path) => ({ path, bytes: bytes(resolve(root, path)) }));
}

function run(value = bytes(fixturePath), sourceSet = sources()): Stage5DestructiveReport {
  const result = runStage5DestructiveHarness(value, sourceSet);
  if (!result.ok) assert.fail(result.reason_code);
  assert.equal(validateReportSchema(result.report), true, JSON.stringify(validateReportSchema.errors));
  return result.report;
}

function validateMutation(
  mutate: (value: MutableSuite) => void,
  reason: ReturnType<typeof validateStage5DestructiveFixtureBytes>["reason_code"],
): void {
  const value = suite();
  mutate(value);
  const verdict = validateStage5DestructiveFixtureBytes(canonicalStage5DestructiveBytes(value));
  assert.equal(verdict.valid, false);
  assert.equal(verdict.reason_code, reason);
}

function action(value: MutableSuite, caseIndex: number, actionName: string): MutableAction {
  const fixture = value.cases[caseIndex];
  assert.ok(fixture);
  const found = fixture.actions.find((candidate) => candidate.action === actionName);
  assert.ok(found);
  return found;
}

test("the canonical fixture suite and committed report are deterministic and schema-valid", () => {
  const built = buildStage5DestructiveFixtureSuite();
  const canonical = canonicalStage5DestructiveBytes(built);
  assert.deepEqual(canonical, bytes(fixturePath));
  assert.equal(validateFixtureSchema(built), true, JSON.stringify(validateFixtureSchema.errors));
  assert.equal(validateFixtureSchema(suite()), true, JSON.stringify(validateFixtureSchema.errors));

  const verdict = validateStage5DestructiveFixtureBytes(canonical);
  assert.deepEqual(verdict, {
    valid: true,
    reason_code: "STAGE5_DESTRUCTIVE_SUITE_VALID",
    suite_sha256: verdict.suite_sha256,
  });
  assert.match(verdict.suite_sha256 ?? "", /^[a-f0-9]{64}$/u);
  assert.equal(Object.isFrozen(built), true);
  assert.equal(Object.isFrozen(built.cases[0]), true);

  const generated = run(canonical);
  const committed = JSON.parse(readFileSync(reportPath, "utf8")) as unknown;
  assert.deepEqual(generated, committed);
});

test("all required faults have separated functional and authoritative-local applicability without authority promotion", () => {
  const report = run();
  assert.deepEqual(STAGE5_DESTRUCTIVE_FAULTS, [
    "process",
    "proxy",
    "openbao",
    "otlp",
    "wal",
    "disk",
    "sse",
    "jsonl",
    "git",
    "skill",
    "hostile-output",
  ]);
  assert.equal(report.cases.length, 22);
  for (const fault of STAGE5_DESTRUCTIVE_FAULTS) {
    const cases = report.cases.filter((candidate) => candidate.fault === fault);
    assert.equal(cases.length, 2, fault);
    assert.deepEqual(
      cases.map(({ profile, applicability }) => ({ profile, applicability })),
      [
        { profile: "insecure-container", applicability: "functional-insecure" },
        { profile: "linux-kvm", applicability: "authoritative-local-linux-kvm" },
      ],
    );
    assert.ok(cases.every((candidate) => candidate.evidence_eligible === false));
  }
  assert.deepEqual(report.applicability, [
    {
      profile: "insecure-container",
      class: "functional-insecure",
      case_count: 11,
      environment_observed: false,
      authority_claimed: false,
    },
    {
      profile: "linux-kvm",
      class: "authoritative-local-linux-kvm",
      case_count: 11,
      environment_observed: false,
      authority_claimed: false,
    },
  ]);
  assert.equal(report.summary.authoritative_runtime_cases, 0);
  assert.equal(report.qualified, false);
  assert.equal(report.release_evidence, false);
  assert.equal(report.release_eligible, false);
});

test("fault outcomes match the Stage 3/Stage 5 fail-closed and bounded-degradation contracts", () => {
  const report = run();
  const byFault = (fault: string) => {
    const result = report.cases.find(
      (candidate) => candidate.fault === fault && candidate.profile === "insecure-container",
    );
    assert.ok(result);
    return result;
  };
  assert.deepEqual(
    ["proxy", "openbao", "wal"].map((fault) => byFault(fault).credentialed_egress),
    ["denied", "denied", "denied"],
  );
  assert.deepEqual(
    ["process", "proxy", "openbao", "wal", "jsonl", "skill"].map((fault) => byFault(fault).admission),
    ["revoked", "revoked", "revoked", "revoked", "revoked", "revoked"],
  );
  assert.equal(byFault("otlp").ordinary_work, "continued");
  assert.equal(byFault("otlp").reason_code, "OTLP_BOUNDED_DROP_ORDINARY_WORK_CONTINUED");
  assert.equal(byFault("disk").reason_code, "DISK_WRITE_FAILED_WITHOUT_PARTIAL_PUBLICATION");
  assert.equal(byFault("sse").reason_code, "SSE_GAP_REQUIRES_HISTORY_NOT_PROMPT_REPLAY");
  assert.equal(byFault("git").reason_code, "GIT_CORRUPTION_WARNED_TURN_PRESERVED");
  assert.equal(byFault("skill").reason_code, "OVERSIZE_SKILL_REJECTED_BEFORE_PROMPT");
  assert.equal(byFault("hostile-output").reason_code, "HOSTILE_OUTPUT_BOUNDED_INERT_AND_OMITTED");
});

test("unknown prompt outcomes are explicit and never replayed", () => {
  const report = run();
  const unknown = report.cases.filter((candidate) => candidate.prompt_outcome === "unknown-reported");
  assert.equal(unknown.length, 4);
  assert.deepEqual(new Set(unknown.map((candidate) => candidate.fault)), new Set(["process", "jsonl"]));
  assert.ok(report.cases.every((candidate) => candidate.unknown_prompt_replay_count === 0));
  assert.equal(report.summary.unknown_prompt_outcomes, 4);
  assert.equal(report.summary.unknown_prompt_replays, 0);

  validateMutation((value) => {
    action(value, 0, "forbid-unknown-prompt-replay").action = "admit-operation";
  }, "STAGE5_DESTRUCTIVE_TRANSITION_INVALID");
  validateMutation((value) => {
    const fixture = value.cases[0];
    assert.ok(fixture);
    fixture.actions.splice(-1, 0, {
      seq: fixture.actions.length - 1,
      actor: "parent",
      action: "admit-operation",
      resource: null,
    });
    const last = fixture.actions.at(-1);
    assert.ok(last);
    last.seq += 1;
  }, "STAGE5_DESTRUCTIVE_TRANSITION_INVALID");
});

test("only the parent acquires and cleans every owned resource exactly once in reverse order", () => {
  const value = suite();
  for (const fixture of value.cases) {
    const acquired = fixture.actions
      .filter((candidate) => candidate.action === "acquire-owned-resource")
      .map((candidate) => candidate.resource);
    const cleaned = fixture.actions
      .filter((candidate) => candidate.action === "cleanup-owned-resource")
      .map((candidate) => candidate.resource);
    assert.deepEqual(acquired, fixture.owned_resources);
    assert.deepEqual(cleaned, [...fixture.owned_resources].reverse());
    assert.ok(
      fixture.actions
        .filter(
          (candidate) => candidate.action === "acquire-owned-resource" || candidate.action === "cleanup-owned-resource",
        )
        .every((candidate) => candidate.actor === "parent"),
    );
    assert.equal(fixture.actions.at(-1)?.action, "close-fixture");
  }
  const report = run();
  for (const result of report.cases) {
    assert.equal(result.cleanup.owner, "fixture-parent");
    assert.equal(result.cleanup.acquired, result.cleanup.attempted);
    assert.equal(result.cleanup.attempted, result.cleanup.completed);
    assert.equal(result.cleanup.duplicate_attempts, 0);
    assert.equal(result.cleanup.foreign_mutations, 0);
    assert.equal(result.cleanup.orphaned_owned_resources, 0);
    assert.equal(result.cleanup.exact_reverse_order, true);
  }

  validateMutation((candidate) => {
    action(candidate, 0, "cleanup-owned-resource").actor = "fault";
  }, "STAGE5_DESTRUCTIVE_TRANSITION_INVALID");
  validateMutation((candidate) => {
    const fixture = candidate.cases[0];
    assert.ok(fixture);
    const cleanup = fixture.actions.filter((item) => item.action === "cleanup-owned-resource");
    assert.equal(cleanup.length, 2);
    const first = cleanup[0];
    const second = cleanup[1];
    assert.ok(first);
    assert.ok(second);
    [first.resource, second.resource] = [second.resource, first.resource];
  }, "STAGE5_DESTRUCTIVE_TRANSITION_INVALID");
  validateMutation((candidate) => {
    const fixture = candidate.cases[0];
    assert.ok(fixture);
    fixture.actions.splice(
      fixture.actions.findIndex((item) => item.action === "cleanup-owned-resource"),
      1,
    );
  }, "STAGE5_DESTRUCTIVE_TRANSITION_INVALID");
  validateMutation((candidate) => {
    const fixture = candidate.cases[0];
    assert.ok(fixture);
    const cleanup = fixture.actions.find((item) => item.action === "cleanup-owned-resource");
    assert.ok(cleanup);
    fixture.actions.splice(-1, 0, { ...cleanup });
  }, "STAGE5_DESTRUCTIVE_TRANSITION_INVALID");
});

test("case inventory, profile pairing, fault identity, and sequence replay fail closed", () => {
  validateMutation((value) => {
    const first = value.cases[0];
    const second = value.cases[1];
    assert.ok(first);
    assert.ok(second);
    second.id = first.id;
  }, "STAGE5_DESTRUCTIVE_CASE_INVENTORY_INVALID");
  validateMutation((value) => {
    value.cases.reverse();
  }, "STAGE5_DESTRUCTIVE_CASE_INVENTORY_INVALID");
  validateMutation((value) => {
    const first = value.cases[0];
    assert.ok(first);
    first.profile = "linux-kvm";
    first.applicability = "authoritative-local-linux-kvm";
  }, "STAGE5_DESTRUCTIVE_CASE_INVENTORY_INVALID");
  validateMutation((value) => {
    const first = value.cases[0];
    assert.ok(first);
    first.fault = "proxy";
  }, "STAGE5_DESTRUCTIVE_CASE_INVENTORY_INVALID");
  validateMutation((value) => {
    const first = value.cases[0];
    assert.ok(first);
    const event = first.actions[1];
    assert.ok(event);
    event.seq = 0;
  }, "STAGE5_DESTRUCTIVE_TRANSITION_INVALID");
  validateMutation((value) => {
    value.cases.pop();
  }, "STAGE5_DESTRUCTIVE_INVALID_SHAPE");
});

test("the aggregation is strict source-bound metadata only", () => {
  const report = run();
  assert.deepEqual(
    report.source_binding.sources.map((source) => source.path),
    STAGE5_DESTRUCTIVE_SOURCE_PATHS,
  );
  assert.match(report.source_binding.source_set_sha256, /^[a-f0-9]{64}$/u);
  assert.ok(report.cases.every((candidate) => candidate.source_set_sha256 === report.source_binding.source_set_sha256));
  const serialized = JSON.stringify(report);
  for (const forbidden of [
    "prompt_text",
    "request_body",
    "query_string",
    "raw_output",
    "source_content",
    "credential_value",
    "session_export",
    "PRIVATE KEY",
  ]) {
    assert.doesNotMatch(serialized, new RegExp(forbidden, "u"));
  }

  const changedSources = sources();
  const first = changedSources[0];
  assert.ok(first);
  first.bytes = new Uint8Array([...first.bytes, 0x0a]);
  const changed = run(bytes(fixturePath), changedSources);
  assert.notEqual(changed.source_binding.source_set_sha256, report.source_binding.source_set_sha256);
  assert.notEqual(changed.source_binding.sources[0]?.sha256, report.source_binding.sources[0]?.sha256);

  const mismatchedFixtureSource = sources();
  const fixtureSource = mismatchedFixtureSource.at(-1);
  assert.ok(fixtureSource);
  fixtureSource.bytes = new Uint8Array([...fixtureSource.bytes, 0x0a]);
  assert.deepEqual(runStage5DestructiveHarness(bytes(fixturePath), mismatchedFixtureSource), {
    ok: false,
    reason_code: "STAGE5_DESTRUCTIVE_SOURCE_BINDING_INVALID",
  });

  for (const sourceMutation of [
    (items: MutableSource[]) => items.pop(),
    (items: MutableSource[]) => items.reverse(),
    (items: MutableSource[]) => {
      const firstItem = items[0];
      assert.ok(firstItem);
      firstItem.path = "DESIGN-copy.md";
    },
    (items: MutableSource[]) => {
      const firstItem = items[0];
      assert.ok(firstItem);
      firstItem.bytes = new Uint8Array();
    },
  ]) {
    const items = sources();
    sourceMutation(items);
    assert.deepEqual(runStage5DestructiveHarness(bytes(fixturePath), items), {
      ok: false,
      reason_code: "STAGE5_DESTRUCTIVE_SOURCE_BINDING_INVALID",
    });
  }
});

test("report ingestion re-aggregates exact sources and rejects replay, duplicate, authority, cleanup, and binding mutations", () => {
  const reportBytes = bytes(reportPath);
  assert.deepEqual(validateStage5DestructiveReportBytes(reportBytes, bytes(fixturePath), sources()), {
    valid: true,
    reason_code: "STAGE5_DESTRUCTIVE_SUITE_VALID",
  });

  const mutations: Array<(report: Record<string, unknown>) => void> = [
    (report) => {
      const cases = report.cases as Array<Record<string, unknown>>;
      const first = cases[0];
      const second = cases[1];
      assert.ok(first);
      assert.ok(second);
      second.id = first.id;
    },
    (report) => {
      (report.summary as Record<string, unknown>).unknown_prompt_replays = 1;
    },
    (report) => {
      const first = (report.cases as Array<Record<string, unknown>>)[0];
      assert.ok(first);
      first.profile = "linux-kvm";
    },
    (report) => {
      const first = (report.cases as Array<Record<string, unknown>>)[0];
      assert.ok(first);
      (first.cleanup as Record<string, unknown>).owner = "child";
    },
    (report) => {
      (report.source_binding as Record<string, unknown>).source_set_sha256 = "0".repeat(64);
    },
    (report) => {
      report.release_eligible = true;
    },
    (report) => {
      report.unreviewed = true;
    },
  ];
  for (const mutate of mutations) {
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as Record<string, unknown>;
    mutate(report);
    assert.deepEqual(
      validateStage5DestructiveReportBytes(canonicalStage5DestructiveBytes(report), bytes(fixturePath), sources()),
      { valid: false, reason_code: "STAGE5_DESTRUCTIVE_REPORT_BINDING_INVALID" },
    );
  }

  const staleSources = sources();
  const first = staleSources[0];
  assert.ok(first);
  first.bytes = new Uint8Array([...first.bytes, 0x0a]);
  assert.deepEqual(validateStage5DestructiveReportBytes(reportBytes, bytes(fixturePath), staleSources), {
    valid: false,
    reason_code: "STAGE5_DESTRUCTIVE_REPORT_BINDING_INVALID",
  });

  for (const noncanonical of [
    reportBytes.slice(0, -1),
    new Uint8Array([0xef, 0xbb, 0xbf, ...reportBytes]),
    new Uint8Array([...reportBytes, 0x0a]),
    new TextEncoder().encode(JSON.stringify(JSON.parse(new TextDecoder().decode(reportBytes)), null, 2)),
  ]) {
    assert.equal(
      validateStage5DestructiveReportBytes(noncanonical, bytes(fixturePath), sources()).reason_code,
      "STAGE5_DESTRUCTIVE_REPORT_INVALID",
    );
  }
  let traps = 0;
  const proxied = new Proxy(reportBytes, {
    get() {
      traps += 1;
      throw new Error("must not execute");
    },
  });
  assert.equal(
    validateStage5DestructiveReportBytes(proxied, bytes(fixturePath), sources()).reason_code,
    "STAGE5_DESTRUCTIVE_REPORT_INVALID",
  );
  assert.equal(traps, 0);
});

test("cloud, provider, cluster, deployment, model, retry, scheduler, and controller routes are structurally absent", () => {
  const report = run();
  assert.deepEqual(STAGE5_DESTRUCTIVE_ROUTES, {
    cloud: false,
    provider: false,
    cluster: false,
    deployment: false,
    external_model: false,
    scheduler: false,
    controller: false,
    retry: false,
  });
  assert.deepEqual(report.routes, STAGE5_DESTRUCTIVE_ROUTES);
  const implementation = readFileSync(resolve(root, "scripts/stage5-destructive-harness.ts"), "utf8");
  assert.doesNotMatch(
    implementation,
    /node:(?:child_process|cluster|dgram|dns|fs|http|https|net|tls)|@aws-sdk|kubernetes/u,
  );
  assert.doesNotMatch(implementation, /process\.(?:env|cwd)|fetch\s*\(/u);
});

test("canonical byte ingestion rejects oversize, malformed, noncanonical, and proxied bytes", () => {
  const canonical = bytes(fixturePath);
  for (const invalid of [
    canonical.slice(0, -1),
    new Uint8Array([0xef, 0xbb, 0xbf, ...canonical]),
    new TextEncoder().encode(`${new TextDecoder().decode(canonical)}\n`),
    new TextEncoder().encode("{not-json}\n"),
  ]) {
    assert.equal(validateStage5DestructiveFixtureBytes(invalid).valid, false);
  }
  assert.equal(
    validateStage5DestructiveFixtureBytes(new Uint8Array(STAGE5_DESTRUCTIVE_LIMITS.maxFixtureBytes + 1)).reason_code,
    "STAGE5_DESTRUCTIVE_BOUNDED_IO_VIOLATION",
  );
  assert.equal(
    validateStage5DestructiveFixtureBytes(new Uint8Array()).reason_code,
    "STAGE5_DESTRUCTIVE_BOUNDED_IO_VIOLATION",
  );

  let traps = 0;
  const proxied = new Proxy(canonical, {
    get() {
      traps += 1;
      throw new Error("must not run");
    },
    getPrototypeOf() {
      traps += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(validateStage5DestructiveFixtureBytes(proxied).reason_code, "STAGE5_DESTRUCTIVE_INVALID_BYTES");
  assert.equal(traps, 0);
});

test("getter, Proxy, hostile prototype, symbol, sparse, cycle, depth, key, string, and aggregate inputs fail closed", () => {
  let getterInvoked = false;
  const getter = suite() as MutableSuite & { hostile?: unknown };
  Object.defineProperty(getter, "hostile", {
    enumerable: true,
    get() {
      getterInvoked = true;
      throw new Error("must not execute");
    },
  });
  assert.throws(() => canonicalStage5DestructiveBytes(getter), /plain JSON object/u);
  assert.equal(getterInvoked, false);

  let proxyTraps = 0;
  const proxied = new Proxy(suite(), {
    ownKeys() {
      proxyTraps += 1;
      throw new Error("must not execute");
    },
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error("must not execute");
    },
  });
  assert.throws(() => canonicalStage5DestructiveBytes(proxied), /plain JSON object/u);
  assert.equal(proxyTraps, 0);

  const hostilePrototype = suite();
  Object.setPrototypeOf(hostilePrototype, { inherited: true });
  assert.throws(() => canonicalStage5DestructiveBytes(hostilePrototype), /plain JSON object/u);

  const symbol = suite() as MutableSuite & { [key: symbol]: boolean };
  symbol[Symbol("hostile")] = true;
  assert.deepEqual(
    canonicalStage5DestructiveBytes(symbol),
    canonicalStage5DestructiveBytes(buildStage5DestructiveFixtureSuite()),
    "non-JSON symbol metadata is ignored without unbounded reflection",
  );

  const sparse = suite();
  sparse.cases.length += 1;
  assert.throws(() => canonicalStage5DestructiveBytes(sparse), /plain JSON object/u);

  const cyclic = suite() as MutableSuite & { cycle?: unknown };
  cyclic.cycle = cyclic;
  assert.throws(() => canonicalStage5DestructiveBytes(cyclic), /bound/u);

  const longString = suite();
  longString.authority = "x".repeat(STAGE5_DESTRUCTIVE_LIMITS.maxStringBytes + 1);
  assert.throws(() => canonicalStage5DestructiveBytes(longString), /bound/u);

  const longKey = suite() as MutableSuite & Record<string, unknown>;
  longKey["k".repeat(STAGE5_DESTRUCTIVE_LIMITS.maxPropertyKeyBytes + 1)] = true;
  assert.throws(() => canonicalStage5DestructiveBytes(longKey), /bound/u);

  const tooDeep = suite() as MutableSuite & { deep?: unknown };
  let cursor: Record<string, unknown> = {};
  tooDeep.deep = cursor;
  for (let index = 0; index <= STAGE5_DESTRUCTIVE_LIMITS.maxDepth; index += 1) {
    const next: Record<string, unknown> = {};
    cursor.next = next;
    cursor = next;
  }
  assert.throws(() => canonicalStage5DestructiveBytes(tooDeep), /bound/u);

  const tooMany = suite() as MutableSuite & { many?: unknown };
  tooMany.many = Object.fromEntries(
    Array.from({ length: STAGE5_DESTRUCTIVE_LIMITS.maxPropertiesPerObject + 1 }, (_, index) => [`k${index}`, true]),
  );
  assert.throws(() => canonicalStage5DestructiveBytes(tooMany), /bound/u);
});

test("hostile source containers, getters, byte proxies, and oversized source sets are rejected without trap execution", () => {
  const getterSources = sources();
  let getterInvoked = false;
  Object.defineProperty(getterSources[0], "bytes", {
    enumerable: true,
    get() {
      getterInvoked = true;
      throw new Error("must not execute");
    },
  });
  assert.equal(runStage5DestructiveHarness(bytes(fixturePath), getterSources).ok, false);
  assert.equal(getterInvoked, false);

  const proxiedSources = new Proxy(sources(), {
    get() {
      throw new Error("must not execute");
    },
  });
  assert.equal(runStage5DestructiveHarness(bytes(fixturePath), proxiedSources).ok, false);

  const byteProxySources = sources();
  let byteTraps = 0;
  const first = byteProxySources[0];
  assert.ok(first);
  first.bytes = new Proxy(first.bytes, {
    get() {
      byteTraps += 1;
      throw new Error("must not execute");
    },
  });
  assert.equal(runStage5DestructiveHarness(bytes(fixturePath), byteProxySources).ok, false);
  assert.equal(byteTraps, 0);

  const oversized = sources();
  const firstOversized = oversized[0];
  assert.ok(firstOversized);
  firstOversized.bytes = new Uint8Array(STAGE5_DESTRUCTIVE_LIMITS.maxSourceBytes + 1);
  assert.equal(runStage5DestructiveHarness(bytes(fixturePath), oversized).ok, false);

  const extended = sources();
  Object.defineProperty(extended, "hostile", { value: true, enumerable: true });
  assert.equal(runStage5DestructiveHarness(bytes(fixturePath), extended).ok, false);
});

test("intrinsic byte capture rejects typed-array impostors, shared/resizable/detached views, and never reads shadowed getters", () => {
  const canonical = bytes(fixturePath);
  let shadowedByteGetterReads = 0;
  for (const key of ["byteLength", "buffer"] as const) {
    Object.defineProperty(canonical, key, {
      configurable: true,
      get() {
        shadowedByteGetterReads += 1;
        throw new Error("must not execute");
      },
    });
  }
  assert.equal(validateStage5DestructiveFixtureBytes(canonical).valid, true);
  assert.equal(shadowedByteGetterReads, 0);
  assert.equal(validateStage5DestructiveFixtureBytes(readFileSync(fixturePath)).valid, false, "Buffer subclass");

  let impostorReads = 0;
  const typedArrayImpostor = Object.create(Uint8Array.prototype) as Uint8Array;
  Object.defineProperty(typedArrayImpostor, "byteLength", {
    get() {
      impostorReads += 1;
      throw new Error("must not execute");
    },
  });
  assert.equal(validateStage5DestructiveFixtureBytes(typedArrayImpostor).valid, false);
  assert.equal(impostorReads, 0);

  let arrayImpostorReads = 0;
  const arrayImpostor = Object.create(Array.prototype) as MutableSource[];
  Object.defineProperty(arrayImpostor, "length", {
    get() {
      arrayImpostorReads += 1;
      throw new Error("must not execute");
    },
  });
  assert.equal(runStage5DestructiveHarness(bytes(fixturePath), arrayImpostor).ok, false);
  assert.equal(arrayImpostorReads, 0);

  const shadowedReport = bytes(reportPath);
  Object.defineProperty(shadowedReport, "byteLength", {
    get() {
      shadowedByteGetterReads += 1;
      throw new Error("must not execute");
    },
  });
  assert.equal(validateStage5DestructiveReportBytes(shadowedReport, bytes(fixturePath), sources()).valid, true);
  assert.equal(shadowedByteGetterReads, 0);

  if (typeof SharedArrayBuffer !== "undefined") {
    const shared = new Uint8Array(new SharedArrayBuffer(intrinsicTestLength(canonical)));
    assert.equal(validateStage5DestructiveFixtureBytes(shared).valid, false);
    assert.equal(validateStage5DestructiveReportBytes(shared, bytes(fixturePath), sources()).valid, false);
    const sharedSources = sources();
    const first = sharedSources[0];
    assert.ok(first);
    first.bytes = shared;
    assert.equal(runStage5DestructiveHarness(bytes(fixturePath), sharedSources).ok, false);
  }

  const resizableBuffer = new ArrayBuffer(intrinsicTestLength(canonical), {
    maxByteLength: intrinsicTestLength(canonical) + 1,
  });
  if (resizableBuffer.resizable) {
    const resizable = new Uint8Array(resizableBuffer);
    resizable.set(canonical);
    assert.equal(validateStage5DestructiveFixtureBytes(resizable).valid, false);
  }

  const detachedBuffer = new ArrayBuffer(intrinsicTestLength(canonical));
  const detached = new Uint8Array(detachedBuffer);
  detached.set(canonical);
  structuredClone(detachedBuffer, { transfer: [detachedBuffer] });
  assert.equal(validateStage5DestructiveFixtureBytes(detached).valid, false);

  const sourceWithShadow = sources();
  const firstSource = sourceWithShadow[0];
  assert.ok(firstSource);
  let sourceByteLengthReads = 0;
  Object.defineProperty(firstSource.bytes, "byteLength", {
    get() {
      sourceByteLengthReads += 1;
      throw new Error("must not execute");
    },
  });
  assert.equal(runStage5DestructiveHarness(bytes(fixturePath), sourceWithShadow).ok, true);
  assert.equal(sourceByteLengthReads, 0);

  const implementation = readFileSync(resolve(root, "scripts/stage5-destructive-harness.ts"), "utf8");
  assert.doesNotMatch(implementation, /Reflect\.ownKeys|Object\.getOwnPropertyDescriptors/u);
});

function intrinsicTestLength(value: Uint8Array): number {
  return Uint8Array.prototype.slice.call(value).length;
}

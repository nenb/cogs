import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { type SecurityResultSemanticsInput, validateSecurityResultSemantics } from "./security-result-semantics.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;
const parseYaml = (require("yaml") as { parse(source: string): unknown }).parse;
const root = resolve(import.meta.dirname, "..");
const schemaDir = resolve(root, "schemas");
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);

const schemaFiles = readdirSync(schemaDir)
  .filter((name) => name.endsWith(".json"))
  .sort();
for (const name of schemaFiles) {
  ajv.addSchema(JSON.parse(readFileSync(resolve(schemaDir, name), "utf8")));
}

const digest = `sha256:${"a".repeat(64)}`;
const opaque = "opaque-123";
const integration = {
  version: "cogs.integration/v1alpha1",
  id: "github-clone",
  preset_revision: digest,
  dns: { mode: "proxy-connect-authority", guest_resolution: false },
  rules: [
    {
      name: "github-api",
      host: "github.com",
      port: 443,
      methods: ["GET"],
      path_patterns: ["/*"],
      path_policy: { strategy: "segment-glob", normalization: "reject-ambiguous" },
      query_policy: { mode: "deny" },
      redirects: { mode: "deny", max_hops: 0, allowed_hosts: [] },
      inject_auth: true,
    },
  ],
  auth: {
    type: "bearer_header",
    header: "Authorization",
    prefix: "Bearer ",
    placeholder: "COGS_PLACEHOLDER_GITHUB",
    secret_handle: "users/opaque/integrations/github",
  },
};

type ClosureTool = Record<string, unknown> & { objects: Array<Record<string, unknown>> };
type ClosureReport = Record<string, unknown> & { tools: ClosureTool[] };
const closureGolden = JSON.parse(
  readFileSync(resolve(root, "test/fixtures/outcome-two/reports/runtime-closure-v1.canonical.jsonl"), "utf8"),
) as ClosureReport;

const validSamples: Record<string, unknown> = {
  "trusted-runtime-closure-v1.json": closureGolden,
  "egress-case-manifest-v1alpha1.json": {
    version: "cogs.egress-cases/v1alpha1",
    cases: [
      {
        id: "route.allowed",
        group: "identity-route",
        timeout_ms: 5000,
        profiles: ["insecure-container", "linux-kvm"],
        dependencies: ["identity", "authorization"],
      },
    ],
  },
  "integration-v1alpha1.json": integration,
  "launch-v1alpha1.json": {
    version: "cogs.dev/v1alpha1",
    user_id: opaque,
    session_id: "session-123",
    workspace_id: "workspace-123",
    sandbox: {
      ssh_endpoint: "sandbox.internal:22",
      ssh_host_key: `SHA256:${"A".repeat(43)}`,
      client_key_path: "/run/cogs/ssh/id",
      proxy_auth_handle: "sessions/session-123/proxy-capability",
    },
    model: { provider: "anthropic", id: "model-id", credential_handle: "users/opaque/models/anthropic" },
    skills: {
      shared_revision: digest,
      shared_path: "/shared/skills",
      user_revision: digest,
      user_path: "/user/skills",
    },
    integrations: [integration],
    limits: { cpu: 2, memory_bytes: 4_294_967_296, tool_timeout_seconds: 900, max_tool_output_bytes: 1_048_576 },
  },
  "events-v1alpha1.json": {
    version: "cogs.event/v1alpha1",
    seq: 0,
    timestamp: "2026-07-10T12:00:00Z",
    session_id: "session-123",
    kind: "run_settled",
    correlation_id: "correlation-123",
    payload: {},
  },
  "policy-v1alpha1.json": {
    version: "cogs.policy/v1alpha1",
    action: "tool.dispatch",
    user: opaque,
    session: "session-123",
    resource: "bash",
    attributes: { tool: "bash" },
  },
  "policy-decision-v1alpha1.json": {
    version: "cogs.policy-decision/v1alpha1",
    decision_id: digest,
    allow: true,
    reason: "allowed",
  },
  "export-manifest-v1alpha1.json": {
    version: "cogs.export/v1alpha1",
    cogs_version: "0.0.0",
    pi_version: "0.80.6",
    session_id: "session-123",
    created_at: "2026-07-10T12:00:00Z",
    mode: "raw",
    files: [
      { path: "git-map.json", sha256: "b".repeat(64), bytes: 1 },
      { path: "session.jsonl", sha256: "a".repeat(64), bytes: 1 },
      { path: "skills.json", sha256: "c".repeat(64), bytes: 1 },
      { path: "transform-report.json", sha256: "d".repeat(64), bytes: 1 },
      { path: "warnings.json", sha256: "e".repeat(64), bytes: 1 },
    ],
    skills: { shared_revision: digest, user_revision: digest },
    attachments_included: false,
  },
  "guest-probe-result-v1alpha1.json": {
    version: "cogs.guest-probe/v1alpha1",
    operation: "tcp",
    outcome: "reached",
    detail_code: "connected",
    duration_ms: 10,
    root: true,
    artifact_sha256: "a".repeat(64),
  },
  "git-mapping-v1alpha1.json": {
    version: "cogs.git-mapping/v1alpha1",
    repo: "repo-123",
    commit: "a".repeat(40),
    session: "session-123",
    entry: "abcdef12",
    turn: 1,
    observed_at: "2026-07-10T12:00:00Z",
    confidence: "exact",
  },
  "security-report-v1alpha1.json": JSON.parse(
    readFileSync(resolve(root, "docs/security-evidence/example-report.json"), "utf8"),
  ),
};

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
const hash = (value: unknown) => createHash("sha256").update(canonical(value)).digest("hex");
const nativeChecks = {
  A: "elf_real python_closure_exact map_files_trusted mapped_closure_equal mapping_stable helper_reaped cleanup_restored",
  B: "gzip_source_exact gzip_sealed_exec zstd_source_exact zstd_sealed_exec decompression_deterministic network_denied children_exact cleanup_restored",
  C: "nofile_measured nofile_normalized fd_198_exact fd_4096_exact close_range_exact cloexec_exact inheritance_exact limit_restored cleanup_restored",
  D: "pdeathsig_armed parent_handshake_exact before_release_death after_release_death starttime_revalidated session_owned process_group_owned term_kill_bounded all_reaped cleanup_restored",
  E: "mount_view_exact checkout_read_only user_namespace_exact pid_namespace_exact mount_namespace_exact network_namespace_exact pid_one capabilities_zero noroot_locked nnp_set seccomp_socket_denied seccomp_io_uring_denied no_acquisition_route checkout_unchanged all_reaped mounts_restored cleanup_restored",
  integration: "closure_prepared handoff_exact gzip_deterministic zstd_deterministic marker_exact no_linked_evidence cleanup_restored",
} as const;
const nativeJobId = { A: "native-qualification-a", B: "native-qualification-b", C: "native-qualification-c",
  D: "native-qualification-d", E: "native-qualification-e", integration: "native-closure-integration" } as const;
const markerHash = "6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8";
function nativeMetadata(job: keyof typeof nativeChecks): unknown[] {
  const objects = [
    { role: "executable", sha256: "1".repeat(64), size_bytes: 11, soname: null, needed: ["ld.so"] },
    { role: "loader", sha256: "2".repeat(64), size_bytes: 12, soname: "ld.so", needed: [] },
  ];
  const normalized = objects.map(({ size_bytes, ...row }) => ({ ...row, size: size_bytes }));
  const mapped = objects.map(({ role, sha256 }) => ({ role, sha256 }));
  if (job === "A") return [
    ...objects.map((row, index) => ({ kind: "object", id: `python-object-${index}`, ...row })),
    { kind: "summary", closure_sha256: hash(normalized), mapping_sha256: hash(mapped.map(({ role, sha256 }) => [role, sha256])),
      mapped_sequence: mapped },
  ];
  if (job === "B") {
    const tools = ["gzip", "zstd"].map((id, index) => {
      const rows = structuredClone(objects); const executable = rows[0]; assert.ok(executable);
      executable.sha256 = `${index + 3}`.repeat(64);
      const view = rows.map(({ size_bytes, ...row }) => ({ ...row, size: size_bytes }));
      const mapping = hash(view.map(({ role, sha256 }) => [role, sha256]));
      return { id, objects: rows, closure_sha256: hash(view), mapping_sha256: mapping,
        source_sha256: executable.sha256, source_size_bytes: 11, sealed_sha256: executable.sha256,
        sealed_size_bytes: 11, seal_mask: 63, execution_mapping_sha256: mapping, output_sha256: markerHash };
    });
    const parserObjects = structuredClone(objects);
    const parserView = parserObjects.map(({ size_bytes, ...row }) => ({ ...row, size: size_bytes }));
    const closureView = (row: typeof tools[number]) => ({ closure_sha256: row.closure_sha256,
      objects: row.objects.map(({ size_bytes, ...item }) => ({ ...item, size: size_bytes })),
      seal_profile: "linux-memfd-exec-seals-v1", sealed_executable: true, tool: row.id });
    const gzip = tools[0]; const zstd = tools[1]; assert.ok(gzip); assert.ok(zstd);
    const digestView = [{ closure_sha256: hash(parserView), objects: parserView, seal_profile: null,
      sealed_executable: false, tool: "python3-parser" }, closureView(zstd), closureView(gzip)];
    return [...tools, { kind: "summary", id: "trusted-closure", closure_sha256: hash(digestView),
      parser: { closure_sha256: hash(parserView), objects: parserObjects } }];
  }
  if (job === "E") return [{ id: "sandbox-policy", role: "policy",
    sha256: "aacfce0e5eeb2fb79a1708b32f5383f89b381898ad7e6bd911905d87483b6bb2", size_bytes: 0 }];
  if (job === "integration") return [
    { id: "closure", role: "digest", sha256: "7".repeat(64), size_bytes: 0 },
    { id: "gzip_output", role: "digest", sha256: markerHash, size_bytes: 0 },
    { id: "source_set", role: "digest", sha256: "8".repeat(64), size_bytes: 0 },
    { id: "zstd_output", role: "digest", sha256: markerHash, size_bytes: 0 },
  ];
  return [];
}
function nativeReport(job: keyof typeof nativeChecks, pass: boolean): Record<string, unknown> {
  const checks = nativeChecks[job].split(" ").map((id) => ({ id, outcome: "pass" }));
  const cleanup = Object.fromEntries("descriptors children paths mounts namespaces limits checkout".split(" ").map((key) => [key, true]));
  if (!pass) { const first = checks[0]; assert.ok(first); first.outcome = "fail"; cleanup.paths = false; }
  return { version: "cogs.native-qualification/v1alpha1", job,
    source: { head_sha: "a".repeat(40), checkout_sha: "a".repeat(40), driver_blob_sha256: "b".repeat(64), common_blob_sha256: "c".repeat(64) },
    envelope: { repository: "owner/repo", head_repository: "owner/repo", event_name: "pull_request", github_sha: "d".repeat(40),
      event_merge_sha: "d".repeat(40), base_sha: "e".repeat(40), run_id: 1, run_attempt: 1, pull_request_number: 1 },
    workflow: { path: ".github/workflows/ci.yml", blob_sha256: "f".repeat(64), workflow_sha: "a".repeat(40), job_id: nativeJobId[job] },
    runner: { image: "ubuntu-24.04", image_version: "20260720.1", kernel_release: "6.8.0-100-generic", architecture: "x86_64" },
    authority: "exact-run-native-qualification", result: pass ? "pass" : "fail", checks,
    metadata: pass ? nativeMetadata(job) : [],
    operation: { result_sha256: "6".repeat(64), source_set_sha256: job === "integration" ? "8".repeat(64) : "7".repeat(64) },
    failure_phase: pass ? null : "schema-test",
    diagnostics_sha256: pass ? null : "9".repeat(64), cleanup };
}

function validatorFor(file: string): ValidateFunction {
  const schema = JSON.parse(readFileSync(resolve(schemaDir, file), "utf8")) as { $id: string };
  const validator = ajv.getSchema(schema.$id);
  assert.ok(validator, `schema ${file} was not registered`);
  return validator;
}

// Compile every registered schema, including historical and candidate evidence
// versions that do not belong in the general-purpose valid sample table.
for (const name of schemaFiles) validatorFor(name);

const nativeValidator = validatorFor("native-qualification-report-v1alpha1.json");
for (const job of Object.keys(nativeChecks) as Array<keyof typeof nativeChecks>) {
  for (const pass of [true, false]) {
    const sample = nativeReport(job, pass);
    assert.equal(nativeValidator(sample), true, `native ${job}/${pass}: ${ajv.errorsText(nativeValidator.errors)}`);
    const hostile = structuredClone(sample); (hostile.checks as unknown[]).reverse();
    assert.equal(nativeValidator(hostile), false, `native ${job} check order`);
    if (pass) {
      // biome-ignore lint/suspicious/noExplicitAny: isolated hostile JSON mutations intentionally cross types
      const mutations: Array<[string, (value: Record<string, any>) => void]> = [
        ["job", (value) => { value.job = job === "A" ? "B" : "A"; }],
        ["job id", (value) => { value.workflow.job_id = "wrong-job"; }],
        ["source", (value) => { value.source.head_sha = "bad"; }],
        ["envelope", (value) => { value.envelope.event_name = "push"; }],
        ["check missing", (value) => { value.checks.pop(); }],
        ["check extra", (value) => { value.checks.push({ id: "extra", outcome: "pass" }); }],
        ["check outcome", (value) => { value.checks[0].outcome = "fail"; }],
        ["failure phase", (value) => { value.failure_phase = "contradiction"; }],
        ["diagnostics", (value) => { value.diagnostics_sha256 = "9".repeat(64); }],
        ["metadata extra", (value) => { value.metadata.push({}); }],
        ["operation result", (value) => { value.operation.result_sha256 = "bad"; }],
        ["operation source", (value) => { value.operation.source_set_sha256 = "bad"; }],
      ];
      for (const key of "descriptors children paths mounts namespaces limits checkout".split(" ")) {
        mutations.push([`cleanup ${key}`, (value) => { value.cleanup[key] = false; }]);
      }
      for (const [name, mutate] of mutations) {
        const mutation = structuredClone(sample); mutate(mutation);
        assert.equal(nativeValidator(mutation), false, `native ${job} isolated ${name}`);
      }
    }
  }
}
const nativeMask = nativeReport("B", true);
const firstMask = (nativeMask.metadata as Array<Record<string, unknown>>)[0]; assert.ok(firstMask); firstMask.seal_mask = 15;
assert.equal(nativeValidator(nativeMask), false, "native B historical mask");
const nativeOversize = nativeReport("A", true);
const firstObject = (nativeOversize.metadata as Array<Record<string, unknown>>)[0]; assert.ok(firstObject);
firstObject.size_bytes = 134_217_729;
assert.equal(nativeValidator(nativeOversize), false, "native A object bound");
const nativeSummary = nativeReport("B", true);
(nativeSummary.metadata as unknown[]).pop();
assert.equal(nativeValidator(nativeSummary), false, "native B aggregate/parser summary required");
const nativePolicy = nativeReport("E", true);
const policyRow = (nativePolicy.metadata as Array<Record<string, unknown>>)[0]; assert.ok(policyRow);
policyRow.sha256 = "6".repeat(64);
assert.equal(nativeValidator(nativePolicy), false, "native E fixed policy digest");
for (const id of ["gzip_output", "zstd_output"]) {
  const nativeOutput = nativeReport("integration", true);
  const row = (nativeOutput.metadata as Array<Record<string, unknown>>).find((item) => item.id === id); assert.ok(row);
  row.sha256 = "9".repeat(64);
  assert.equal(nativeValidator(nativeOutput), false, `native integration exact ${id}`);
}

for (const [file, sample] of Object.entries(validSamples)) {
  const validate = validatorFor(file);
  assert.equal(validate(sample), true, `${file}: ${ajv.errorsText(validate.errors)}`);

  const withUnknown = { ...(sample as Record<string, unknown>), unexpected_security_field: true };
  assert.equal(validate(withUnknown), false, `${file} must reject unknown top-level fields`);
}

function closureMutation(scope: string): ClosureReport {
  const value = structuredClone(closureGolden);
  const firstTool = value.tools.at(0);
  assert.ok(firstTool);
  const [executable, loader, library] = firstTool.objects;
  assert.ok(executable);
  assert.ok(loader);
  assert.ok(library);
  if (scope === "report") value.source_generations = [];
  if (scope === "object") executable.source_generation = {};
  if (scope === "role") loader.role = "library";
  if (scope === "soname") library.soname = "bad name";
  if (scope === "needed") executable.needed = Array(129).fill("lib.so");
  if (scope === "tool") value.tools.reverse();
  return value;
}
const closureMutations = ["report", "object", "role", "soname", "needed", "tool"].map(closureMutation);
const closureValidator = validatorFor("trusted-runtime-closure-v1.json");
for (const mutation of closureMutations) assert.equal(closureValidator(mutation), false);

const decisionValidator = validatorFor("policy-decision-v1alpha1.json");
for (const invalidDecision of [
  { version: "cogs.policy-decision/v1alpha1", decision_id: digest, allow: true, reason: "invalid_envelope" },
  { version: "cogs.policy-decision/v1alpha1", decision_id: digest, allow: false, reason: "allowed" },
]) {
  assert.equal(decisionValidator(invalidDecision), false, "policy decisions must couple allow with reason");
}

const launchValidator = validatorFor("launch-v1alpha1.json");
const launchWithInlineSecret = structuredClone(validSamples["launch-v1alpha1.json"]) as Record<string, unknown>;
launchWithInlineSecret.secret = "real-secret-must-never-be-inline";
assert.equal(launchValidator(launchWithInlineSecret), false, "launch documents must reject inline secret fields");

const reportValidator = validatorFor("security-report-v1alpha1.json");
const invalidAuthority = structuredClone(validSamples["security-report-v1alpha1.json"]) as Record<string, unknown>;
invalidAuthority.authority = "authoritative-local";
assert.equal(reportValidator(invalidAuthority), false, "insecure profiles cannot claim authoritative evidence");

assert.deepEqual(
  validateSecurityResultSemantics({ result: "pass", release_eligible: true, dependency_modes: { audit: "stubbed" } }),
  [
    "a passing test with a stubbed dependency requires result=stubbed",
    "release-eligible test dependencies must all be real",
  ],
);
assert.deepEqual(
  validateSecurityResultSemantics({ result: "fail", release_eligible: false, dependency_modes: { audit: "stubbed" } }),
  [],
  "a real mechanism failure must remain fail even when a dependency is stubbed",
);
const exampleReport = validSamples["security-report-v1alpha1.json"] as { tests: SecurityResultSemanticsInput[] };
for (const result of exampleReport.tests) assert.deepEqual(validateSecurityResultSemantics(result), []);

for (const reportPath of process.argv.slice(2)) {
  const report = JSON.parse(readFileSync(resolve(reportPath), "utf8")) as {
    authority: string;
    profile: string;
    started_at: string;
    completed_at: string;
    environment: { metadata?: Record<string, unknown> };
    tests: Array<SecurityResultSemanticsInput & { id: string }>;
  };
  assert.equal(reportValidator(report), true, `${reportPath}: ${ajv.errorsText(reportValidator.errors)}`);
  assert.ok(
    Date.parse(report.completed_at) >= Date.parse(report.started_at),
    `${reportPath}: completion precedes start`,
  );
  assert.equal(
    new Set(report.tests.map((test) => test.id)).size,
    report.tests.length,
    `${reportPath}: duplicate test IDs`,
  );
  for (const [index, result] of report.tests.entries()) {
    assert.deepEqual(
      validateSecurityResultSemantics(result),
      [],
      `${reportPath}: invalid test semantics at index ${index}`,
    );
    if (result.release_eligible) {
      assert.notEqual(
        report.authority,
        "functional-only",
        `${reportPath}: functional profiles cannot be release eligible`,
      );
    }
    if (result.id === "runner.kvm-acceleration" && result.result === "pass") {
      for (const field of ["kvm_present", "kvm_enabled", "guest_root", "distinct_boot_ids"]) {
        assert.equal(
          report.environment.metadata?.[field],
          true,
          `${reportPath}: passing KVM evidence requires ${field}=true`,
        );
      }
    }
  }
}

type WorkflowStep = { id?: string; uses?: string; with?: Record<string, unknown>; env?: Record<string, string>; run?: string };
type WorkflowJob = { if?: string; needs?: string | string[]; outputs?: Record<string, string>; steps: WorkflowStep[] };
type WorkflowTrigger = { workflow_dispatch: { inputs: { reviewed_sha: { description: string; required: boolean; type: string } } } };
const workflowPath = resolve(root, ".github/workflows/ci.yml");
const workflow = parseYaml(readFileSync(workflowPath, "utf8")) as {
  on: WorkflowTrigger;
  jobs: Record<string, WorkflowJob>;
};
const workflowJob = (id: string): WorkflowJob => {
  const job = workflow.jobs[id];
  assert.ok(job, `workflow job ${id}`);
  return job;
};
const jobNeeds = (job: WorkflowJob): string[] => job.needs === undefined ? [] :
  typeof job.needs === "string" ? [job.needs] : job.needs;
const checkoutRef = (job: WorkflowJob): unknown =>
  job.steps.find((step) => step.uses?.startsWith("actions/checkout@"))?.with?.ref;
const cliStep = (job: WorkflowJob, selector: string): WorkflowStep => {
  const step = job.steps.find((candidate) => candidate.run?.includes(selector));
  assert.ok(step, `workflow CLI ${selector}`);
  return step;
};
const authorityId = "native-qualification-eligibility";
const nativeJobs = [
  ["native-qualification-a", "scripts/native-qualification/job-a-runtime-mappings.py"],
  ["native-qualification-b", "scripts/native-qualification/job-b-compression.py"],
  ["native-qualification-c", "scripts/native-qualification/job-c-descriptors.py"],
  ["native-qualification-d", "scripts/native-qualification/job-d-process-lifecycle.py"],
  ["native-qualification-e", "scripts/native-qualification/job-e-sandbox.py"],
  ["native-closure-integration", "scripts/native-qualification/thin-integration.py"],
] as const;
assert.deepEqual(workflow.on.workflow_dispatch.inputs.reviewed_sha, {
  description: "Exact externally reviewed commit SHA to qualify",
  required: true,
  type: "string",
});
const authority = workflowJob(authorityId);
const authorityCondition = "github.event_name == 'workflow_dispatch' && github.run_attempt == 1 && " +
  "github.actor == github.triggering_actor && github.actor == vars.NATIVE_QUALIFICATION_ACTOR && " +
  "github.event.sender.login == github.actor && github.ref_type == 'branch' && " +
  "github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && github.ref_protected == true && " +
  "github.workflow_ref == format('{0}/.github/workflows/ci.yml@{1}', github.repository, github.ref) && " +
  "github.workflow_sha == github.sha";
assert.equal(authority.if, authorityCondition);
assert.equal(authority.steps.some((step) => step.uses?.startsWith("actions/checkout@")), false);
assert.equal(authority.outputs?.reviewed_sha, "${{ steps.authority.outputs.reviewed_sha }}");
const authorityStep = authority.steps.find((step) => step.id === "authority");
assert.ok(authorityStep);
assert.equal(authorityStep.env?.REVIEWED_SHA, "${{ inputs.reviewed_sha }}");
assert.match(authorityStep.run ?? "", /\[\[ "\$REVIEWED_SHA" =~ \^\[0-9a-f\]\{40\}\$ \]\]/u);
const reviewedRef = "${{ needs.native-qualification-eligibility.outputs.reviewed_sha }}";
const nativeIds = nativeJobs.map(([id]) => id);
const effectIds = ["native-c1", ...nativeIds];
const nativeInventory = Object.keys(workflow.jobs).filter((id) => id.startsWith("native-"));
assert.deepEqual(nativeInventory.sort(), [authorityId, ...effectIds, "native-qualification-required"].sort(),
  "every native job is included in the authority proof");
for (const id of effectIds) {
  const job = workflowJob(id);
  assert.ok(jobNeeds(job).includes(authorityId), `${id}: dispatch authority dependency`);
  assert.doesNotMatch(JSON.stringify(job), /github\.event\.pull_request/u, `${id}: no PR authority`);
}
for (const [id, driver] of nativeJobs) {
  const job = workflowJob(id);
  const invoke = cliStep(job, "--workflow-bound");
  assert.equal(invoke.env?.NQ_DRIVER, driver);
  assert.equal(invoke.env?.NQ_HEAD_SHA, reviewedRef);
}
const finalJob = workflowJob("native-qualification-required");
assert.equal(finalJob.if, "${{ always() && needs.native-qualification-eligibility.result == 'success' }}");
assert.equal(checkoutRef(finalJob), reviewedRef);
const finalStep = cliStep(finalJob, "--require-final-results");
for (const id of ["quality", authorityId, ...nativeIds]) {
  assert.ok(Object.values(finalStep.env ?? {}).some((value) => value.includes(`needs.${id}.result`)), id);
}
type AuthorityContext = {
  event: string; attempt: number; actor: string; triggeringActor: string; sender: string; configuredActor: string;
  ref: string; refType: string; defaultBranch: string; protected: boolean; workflowRef: string; repository: string;
  workflowSha: string; sha: string; reviewedSha: string;
};
const selected = (context: AuthorityContext): boolean => context.event === "workflow_dispatch" && context.attempt === 1 &&
  context.actor === context.triggeringActor && context.actor === context.configuredActor && context.sender === context.actor &&
  context.refType === "branch" && context.ref === `refs/heads/${context.defaultBranch}` && context.protected &&
  context.workflowRef === `${context.repository}/.github/workflows/ci.yml@${context.ref}` &&
  context.workflowSha === context.sha && /^[0-9a-f]{40}$/u.test(context.reviewedSha);
const dispatch: AuthorityContext = {
  event: "workflow_dispatch",
  attempt: 1,
  actor: "reviewer",
  triggeringActor: "reviewer",
  sender: "reviewer",
  configuredActor: "reviewer",
  ref: "refs/heads/main",
  refType: "branch",
  defaultBranch: "main",
  protected: true,
  workflowRef: "owner/repo/.github/workflows/ci.yml@refs/heads/main",
  repository: "owner/repo",
  workflowSha: "b".repeat(40),
  sha: "b".repeat(40),
  reviewedSha: "a".repeat(40),
};
assert.equal(selected({ ...dispatch, event: "pull_request" }), false, "pull request never dispatches native");
const pullRequestOutcomes: Record<string, string> = { quality: "success", [authorityId]: "skipped" };
for (const id of effectIds) {
  assert.equal(jobNeeds(workflowJob(id)).every((dependency) => pullRequestOutcomes[dependency] === "success"), false,
    `${id}: unreachable on pull_request`);
  pullRequestOutcomes[id] = "skipped";
}
for (const context of [
  { ...dispatch, attempt: 2 },
  { ...dispatch, actor: "caller" },
  { ...dispatch, configuredActor: "" },
  { ...dispatch, ref: "refs/heads/topic" },
  { ...dispatch, protected: false },
  { ...dispatch, workflowSha: "c".repeat(40) },
  { ...dispatch, reviewedSha: "not-a-sha" },
]) assert.equal(selected(context), false, "dispatch authority fails closed");
assert.equal(selected(dispatch), true, "explicit protected-default-branch dispatch is selected");
const outcomes: Record<string, string> = { quality: "success", [authorityId]: "success" };
for (const id of effectIds) {
  assert.equal(jobNeeds(workflowJob(id)).every((dependency) => outcomes[dependency] === "success"), true, `${id}: selected`);
  assert.equal(checkoutRef(workflowJob(id)), reviewedRef, `${id}: exact external head`);
  outcomes[id] = "success";
}

console.log(`Validated ${schemaFiles.length} schemas, valid examples, negative cases, report semantics, and native workflow gates.`);

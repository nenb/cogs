import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const parseYaml = (require("yaml") as { parse(source: string): unknown }).parse;
const path = ".github/workflows/outcome-two-native-b.yml";
const source = readFileSync(path, "utf8");
type Step = {
  id?: string;
  uses?: string;
  if?: string;
  env?: Record<string, string>;
  run?: string;
  with?: Record<string, unknown>;
};
type Job = { if?: string; needs?: string | string[]; steps: Step[] };
const workflow = parseYaml(source) as {
  on: Record<string, unknown>;
  permissions: Record<string, string>;
  jobs: Record<string, Job>;
};
const authorityId = "native-qualification-eligibility";
const gha = (value: string) => `\${{ ${value} }}`;
const reviewedRef = gha("needs.native-qualification-eligibility.outputs.reviewed_sha");
const steps = (job: Job, selector: (step: Step) => boolean): Step => {
  const result = job.steps.find(selector);
  assert.ok(result);
  return result;
};

test("fast B workflow retains protected-main exact-head authority", () => {
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(workflow.permissions, { contents: "read" });
  assert.deepEqual(Object.keys(workflow.jobs).sort(), ["native-qualification-b", authorityId]);
  const authority = workflow.jobs[authorityId];
  assert.ok(authority);
  const condition =
    "github.event_name == 'workflow_dispatch' && github.run_attempt == 1 && " +
    "github.actor == github.triggering_actor && github.actor == vars.NATIVE_QUALIFICATION_ACTOR && " +
    "github.event.sender.login == github.actor && github.ref_type == 'branch' && " +
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && github.ref_protected == true && " +
    "github.workflow_ref == format('{0}/.github/workflows/outcome-two-native-b.yml@{1}', github.repository, github.ref) && " +
    "github.workflow_sha == github.sha";
  assert.equal(authority.if, condition);
  assert.equal(
    authority.steps.some((step) => step.uses?.startsWith("actions/checkout@")),
    false,
  );
  const gate = steps(authority, (step) => step.id === "authority");
  assert.equal(gate.env?.REVIEWED_SHA, gha("inputs.reviewed_sha"));
  assert.equal(gate.env?.AUTHORIZED_ACTOR, gha("vars.NATIVE_QUALIFICATION_ACTOR"));
  assert.match(gate.run ?? "", /\[\[ "\$REVIEWED_SHA" =~ \^\[0-9a-f\]\{40\}\$ \]\]/u);
  assert.ok(gate.run?.includes('test "$REVIEWED_SHA" = "$ENVELOPE_SHA"'));

  type Context = {
    event: string;
    attempt: number;
    actor: string;
    triggering: string;
    sender: string;
    configured: string;
    ref: string;
    refType: string;
    defaultBranch: string;
    protected: boolean;
    workflowRef: string;
    repository: string;
    workflowSha: string;
    sha: string;
    reviewed: string;
  };
  const selected = (value: Context) =>
    value.event === "workflow_dispatch" &&
    value.attempt === 1 &&
    value.actor === value.triggering &&
    value.actor === value.configured &&
    value.sender === value.actor &&
    value.refType === "branch" &&
    value.ref === `refs/heads/${value.defaultBranch}` &&
    value.protected &&
    value.workflowRef === `${value.repository}/${path}@${value.ref}` &&
    value.workflowSha === value.sha &&
    value.reviewed === value.sha &&
    /^[0-9a-f]{40}$/u.test(value.reviewed);
  const exact: Context = {
    event: "workflow_dispatch",
    attempt: 1,
    actor: "reviewer",
    triggering: "reviewer",
    sender: "reviewer",
    configured: "reviewer",
    ref: "refs/heads/main",
    refType: "branch",
    defaultBranch: "main",
    protected: true,
    workflowRef: `owner/repo/${path}@refs/heads/main`,
    repository: "owner/repo",
    workflowSha: "a".repeat(40),
    sha: "a".repeat(40),
    reviewed: "a".repeat(40),
  };
  assert.equal(selected(exact), true);
  for (const hostile of [
    { ...exact, event: "push" },
    { ...exact, attempt: 2 },
    { ...exact, actor: "other" },
    { ...exact, configured: "" },
    { ...exact, ref: "refs/heads/topic" },
    { ...exact, protected: false },
    { ...exact, workflowSha: "b".repeat(40) },
    { ...exact, reviewed: "b".repeat(40) },
    { ...exact, reviewed: "A".repeat(40) },
  ])
    assert.equal(selected(hostile), false);
});

test("native report schema admits the fast path only for Job B", () => {
  type PathRule = { const?: string; enum?: string[] };
  type SchemaNode = { properties: { path?: PathRule; workflow?: SchemaNode } };
  const schema = JSON.parse(readFileSync("schemas/native-qualification-report-v1alpha1.json", "utf8")) as {
    $defs: Record<string, SchemaNode>;
  };
  const fast = ".github/workflows/outcome-two-native-b.yml";
  const workflowRule = schema.$defs.workflow?.properties.path;
  const jobBRule = schema.$defs.jobB?.properties.workflow?.properties.path;
  assert.deepEqual(workflowRule?.enum, [".github/workflows/ci.yml", fast]);
  assert.deepEqual(jobBRule?.enum, [".github/workflows/ci.yml", fast]);
  for (const job of ["jobA", "jobC", "jobD", "jobE", "jobIntegration"]) {
    const rule = schema.$defs[job]?.properties.workflow?.properties.path;
    assert.equal(rule?.const, ".github/workflows/ci.yml", job);
  }
});

test("fast B workflow reuses the bounded capability and settlement transaction", () => {
  const job = workflow.jobs["native-qualification-b"];
  assert.ok(job);
  assert.deepEqual(job.needs, [authorityId]);
  const checkout = steps(job, (step) => step.uses?.startsWith("actions/checkout@") === true);
  assert.equal(checkout.with?.ref, reviewedRef);
  assert.equal(checkout.with?.["fetch-depth"], 0);
  assert.equal(checkout.with?.["persist-credentials"], false);
  const invoke = steps(job, (step) => step.env?.NQ_DRIVER !== undefined);
  assert.equal(invoke.env?.NQ_DRIVER, "scripts/native-qualification/job-b-compression.py");
  assert.equal(invoke.env?.NQ_HEAD_SHA, reviewedRef);
  const run = (invoke.run ?? "").replace(/\\\n\s+/gu, " ");
  const ordered = [
    "HEAD^{commit}",
    "refs/remotes/origin/$NQ_DEFAULT_BRANCH^{commit}",
    "sudo -n --close-from=3",
    "/usr/bin/prlimit --nofile=65536:65536 --",
    "/usr/bin/setpriv",
    '--reuid="$runner_uid"',
    '--regid="$runner_gid"',
    "--clear-groups",
    "--inh-caps=+sys_admin",
    "--ambient-caps=+sys_admin",
    "/usr/bin/env -i",
    "NQ_WORKFLOW_PATH=.github/workflows/outcome-two-native-b.yml",
    '"$NQ_DRIVER" --workflow-bound',
  ];
  const positions = ordered.map((token) => run.indexOf(token));
  assert.ok(positions.every((position) => position >= 0));
  assert.deepEqual(
    positions,
    positions.toSorted((left, right) => left - right),
  );
  const cleanup = steps(job, (step) => step.run?.includes("common.py --cleanup B") === true);
  assert.equal(cleanup.if, gha("always()"));
  assert.equal(cleanup.env?.NQ_UPLOAD_ARTIFACT_ID, gha("steps.upload.outputs.artifact-id"));
  assert.equal(cleanup.env?.NQ_UPLOAD_ARTIFACT_SHA256, gha("steps.upload.outputs.artifact-digest"));
  const settlement = steps(job, (step) => step.run?.includes("CLEANUP_OUTCOME") === true);
  assert.equal(settlement.if, gha("always()"));
  assert.doesNotMatch(
    source,
    /pull_request:|\bpush:|native-qualification-[acde]:|native-closure-integration:|quality:|aws|opentofu|ssm|provider|deploy/iu,
  );
});

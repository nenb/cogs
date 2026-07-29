import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const parseYaml = (require("yaml") as { parse(source: string): unknown }).parse;
const root = resolve(import.meta.dirname, "..");
const workflowDirectory = resolve(root, ".github/workflows");
const forbiddenRuns = [
  ["legacy validation entry", /validate\.sh/iu],
  ["installer entry", /install-opentofu/iu],
  ["infrastructure tool reference", /\b(?:opentofu|tofu|terraform)\b/iu],
  ["AWS CLI command", /(?:^|[\s;&|()])(?:command\s+)?(?:\.{0,2}\/|\/[\w./-]*\/)?aws(?=$|[\s;&|()])/iu],
  ["infrastructure fixture path", /(?:^|[\s"'`])(?:\.\/)?deploy\/aws-feasibility(?:\/|$|[\s"'`])/iu],
] as const;

type WorkflowStep = { name?: unknown; run?: unknown };
type WorkflowJob = { steps?: unknown };
type Workflow = { jobs?: unknown };

function workflowRuns(path: string): Array<{ job: string; step: string; run: string }> {
  const parsed = parseYaml(readFileSync(path, "utf8")) as Workflow;
  assert.ok(parsed.jobs && typeof parsed.jobs === "object" && !Array.isArray(parsed.jobs), `${path}: parsed jobs`);
  const runs: Array<{ job: string; step: string; run: string }> = [];
  for (const [jobName, value] of Object.entries(parsed.jobs as Record<string, WorkflowJob>)) {
    assert.ok(Array.isArray(value.steps), `${path}: parsed steps for ${jobName}`);
    for (const [index, rawStep] of value.steps.entries()) {
      assert.ok(
        rawStep && typeof rawStep === "object" && !Array.isArray(rawStep),
        `${path}: parsed step ${jobName}/${index}`,
      );
      const step = rawStep as WorkflowStep;
      if (step.run === undefined) continue;
      assert.ok(typeof step.run === "string", `${path}: string run command ${jobName}/${index}`);
      runs.push({ job: jobName, step: typeof step.name === "string" ? step.name : String(index), run: step.run });
    }
  }
  return runs;
}

test("parsed workflow run commands cannot invoke infrastructure validation", () => {
  const workflowPaths = readdirSync(workflowDirectory)
    .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
    .sort()
    .map((name) => resolve(workflowDirectory, name));
  assert.ok(workflowPaths.length > 0, "workflow inventory");

  for (const path of workflowPaths) {
    for (const { job, step, run } of workflowRuns(path)) {
      for (const [label, pattern] of forbiddenRuns) {
        assert.doesNotMatch(run, pattern, `${path}: ${job}/${step} must not invoke ${label}`);
      }
    }
  }
});

test("forbidden run-command guards reject direct, wrapped, and path-based invocations", () => {
  for (const command of [
    "./deploy/aws-feasibility/validate.sh",
    "bash deploy/aws-feasibility/plan.sh",
    "./scripts/install-opentofu.sh",
    "./tofu validate",
    "/usr/bin/terraform init",
    "command aws sts get-caller-identity",
  ]) {
    assert.ok(
      forbiddenRuns.some(([, pattern]) => pattern.test(command)),
      `guarded command: ${command}`,
    );
  }
});

test("parsed Quality job selects only the bounded static feasibility source checker", () => {
  const path = resolve(workflowDirectory, "ci.yml");
  const runs = workflowRuns(path);
  const selected = runs.filter(({ run }) => run.includes("feasibility-source:check"));
  assert.deepEqual(
    selected.map(({ job, run }) => ({ job, run })),
    [{ job: "quality", run: "npm run feasibility-source:check" }],
  );

  const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
    scripts?: Record<string, unknown>;
  };
  assert.equal(packageJson.scripts?.["feasibility-source:check"], "tsx scripts/check-feasibility-source.ts");
});

test("bounded feasibility checker performs static parsing only", () => {
  const result = spawnSync(resolve(root, "node_modules/.bin/tsx"), ["scripts/check-feasibility-source.ts"], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, PI_OFFLINE: "1" },
    timeout: 15_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(
    result.stdout,
    /^Statically checked 14 bounded feasibility fixture sources without infrastructure execution\.\n$/u,
  );
});

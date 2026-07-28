/* biome-ignore-all lint/suspicious/noExplicitAny: deterministic JSON Schema witness walker */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const predecessor = "bec0a19b0b984f88ab9c2effc5059f3737915caa";
const workflowPath = ".github/workflows/ci.yml";
const schemaPath = "schemas/native-qualification-report-v1alpha1.json";
const jobs = [
  ["A", "native-qualification-a", "job-a-runtime-mappings", 300],
  ["B", "native-qualification-b", "job-b-compression", 350],
  ["C", "native-qualification-c", "job-c-descriptors", 250],
  ["D", "native-qualification-d", "job-d-process-lifecycle", 350],
  ["E", "native-qualification-e", "job-e-sandbox", 450],
  ["integration", "native-closure-integration", "thin-integration", 350],
] as const;
const cleanupKeys = ["descriptors", "children", "paths", "mounts", "namespaces", "limits", "checkout"];
const workflow = readFileSync(workflowPath, "utf8");
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validate = ajv.compile(schema);

function block(id: string) {
  const start = workflow.indexOf(`  ${id}:`);
  assert.notEqual(start, -1, id);
  const tail = workflow.slice(start + id.length + 3);
  const next = /\n {2}[a-z0-9-]+:\n/u.exec(tail);
  return workflow.slice(start, next ? start + id.length + 3 + (next.index ?? 0) : undefined);
}

function schemaWitness(node: any, hint: any = {}, key = ""): any {
  if (node.$ref) {
    const value = schemaWitness(schema.$defs[node.$ref.split("/").at(-1)], hint, key);
    const siblings = { ...node };
    delete siblings.$ref;
    return Object.keys(siblings).length ? Object.assign(value, schemaWitness(siblings, value, key)) : value;
  }
  if (node.const !== undefined) return node.const;
  if (node.enum) return node.enum.includes(hint) ? hint : node.enum[0];
  if ((node.oneOf || node.anyOf) && !node.properties && !node.allOf) {
    const alternatives = node.oneOf ?? node.anyOf;
    const wanted = alternatives.find((value: any) => {
      const referenced = value.$ref ? schema.$defs[value.$ref.split("/").at(-1)] : value;
      const text = JSON.stringify(referenced);
      return (
        (!hint?.job || !text.includes('"job"') || text.includes(`"const":"${hint.job}"`)) &&
        (!hint?.result || !text.includes('"result"') || text.includes(`"const":"${hint.result}"`))
      );
    });
    return schemaWitness(wanted ?? alternatives[0], hint, key);
  }
  const type = Array.isArray(node.type) ? node.type.find((value: string) => value !== "null") : node.type;
  if (type === "object" || node.properties || node.allOf) {
    const properties = node.properties ?? {};
    const names =
      node.additionalProperties === false
        ? Object.keys(properties).filter((name) => hint?.[name] !== undefined)
        : Object.keys(hint ?? {});
    const entries = names.map((name) => [name, hint[name]]);
    const value = Object.fromEntries(entries) as Record<string, any>;
    const constrained = Object.keys(properties);
    for (const name of new Set([...(node.required ?? []), ...constrained])) {
      value[name] = schemaWitness(properties[name], value[name], name);
    }
    for (const rule of node.allOf ?? []) {
      const condition = rule.if?.properties ?? {};
      const matches = Object.entries(condition).every(
        ([name, expected]: [string, any]) => expected.const === undefined || hint?.[name] === expected.const,
      );
      const selected = rule.if ? (matches ? rule.then : rule.else) : rule;
      if (selected) Object.assign(value, schemaWitness(selected, { ...hint, ...value }, key));
    }
    return value;
  }
  if (type === "array" || node.items || node.prefixItems) {
    if (node.prefixItems) return node.prefixItems.map((item: unknown) => schemaWitness(item, {}, key));
    const length = node.minItems ?? (Array.isArray(hint) ? hint.length : 0);
    return Array.from({ length }, (_, index) =>
      schemaWitness(node.contains && index === length - 1 ? node.contains : node.items, hint?.[index], key),
    );
  }
  if (type === "integer" || type === "number") return node.minimum ?? 1;
  if (type === "boolean") return true;
  if (type === "null") return null;
  const pattern = node.pattern ?? "";
  if (pattern.includes("40}")) return "1".repeat(40);
  if (pattern.includes("64}")) return "a".repeat(64);
  if (key === "repository" || key.endsWith("_repository")) return "owner/repository";
  if (key === "driver_path") return "scripts/native-qualification/x.py";
  if (key === "kernel_release") return "6.8.0-100-generic";
  return "x";
}

function report(job: (typeof jobs)[number][0], result: "pass" | "fail") {
  const value = schemaWitness(schema, { job, result }) as Record<string, any>;
  for (const check of value.checks) check.outcome = "pass";
  for (const key of cleanupKeys) value.cleanup[key] = true;
  value.failure_phase = null;
  value.diagnostics_sha256 = null;
  if (result === "fail") {
    value.checks[0].outcome = "fail";
    value.cleanup[cleanupKeys[0]] = false;
    value.failure_phase = "portable-test";
    value.diagnostics_sha256 = "d".repeat(64);
  }
  return value;
}

test("workflow and all six drivers share one fail-closed workflow ABI", () => {
  for (const [job, id, driver] of jobs) {
    const declaration = block(id);
    const source = readFileSync(`scripts/native-qualification/${driver}.py`, "utf8");
    assert.ok(declaration.includes(`NQ_DRIVER: scripts/native-qualification/${driver}.py`), id);
    assert.match(declaration, /["']\$NQ_DRIVER["']\s+--workflow-bound/u, id);
    assert.match(source, /["']--workflow-bound["']/u, driver);
    assert.doesNotMatch(source, /["']--(?:native|native-fixed)["']/u, driver);
    assert.match(source, new RegExp(`WorkflowContext\\.from_environ\\(["']${job}["'], __file__\\)`, "u"), driver);
    assert.match(source, /finalize_report\(/u, driver);
    assert.doesNotMatch(source, /dict\.fromkeys\([^)]*CLEANUP_KEYS[^)]*,\s*True\s*\)/u, driver);
    assert.doesNotMatch(source, /\{[^}\n]*:\s*True\s+for[^}\n]*CLEANUP_KEYS[^}\n]*\}/u, driver);
    assert.doesNotMatch(declaration, /github\.run_attempt\s*==|head\.repo\.full_name\s*==/u, id);
  }
  const eligibility = [...workflow.matchAll(/^ {2}([a-z0-9-]*eligibility[a-z0-9-]*):$/gmu)].at(0)?.[1];
  const required = [...workflow.matchAll(/^ {2}([a-z0-9-]*(?:required|final|result)[a-z0-9-]*):$/gmu)].at(0)?.[1];
  assert.ok(eligibility && required, "explicit eligibility and final required jobs");
  const admission = block(eligibility);
  for (const token of ["pull_request", "run_attempt", "head.repo.full_name"]) assert.ok(admission.includes(token));
  const final = block(required);
  assert.match(final, /if:\s*\$\{\{\s*always\(\)\s*\}\}/u);
  for (const id of ["quality", eligibility, ...jobs.map((entry) => entry[1])]) assert.ok(final.includes(id), id);
  assert.match(final, /result[\s\S]*success|success[\s\S]*result/u);
});

test("the discriminated schema accepts authentic pass and fail only", () => {
  for (const [job, id] of jobs) {
    const passing = report(job, "pass");
    const failing = report(job, "fail");
    const ids = passing.checks.map((check: any) => check.id);
    assert.equal(new Set(ids).size, ids.length, `${job}: duplicate schema checks`);
    assert.equal(passing.workflow.job_id, id);
    assert.equal(validate(passing), true, `${job}/pass: ${ajv.errorsText(validate.errors)}`);
    assert.equal(validate(failing), true, `${job}/fail: ${ajv.errorsText(validate.errors)}`);
    const contradiction = structuredClone(passing);
    contradiction.checks[0].outcome = "fail";
    assert.equal(validate(contradiction), false, `${job}: pass/fail contradiction`);
    const reordered = structuredClone(passing);
    reordered.checks.reverse();
    assert.equal(validate(reordered), false, `${job}: reordered checks`);
    const falseFailure = structuredClone(failing);
    for (const check of falseFailure.checks) check.outcome = "pass";
    for (const key of cleanupKeys) falseFailure.cleanup[key] = true;
    assert.equal(validate(falseFailure), false, `${job}: all-success failure`);
  }
});

test("native surfaces remain readable and within ADR 0090 highs", () => {
  const highs = new Map<string, number>([
    [workflowPath, 300],
    [schemaPath, 300],
    ["scripts/native-qualification/common.py", 400],
    ...jobs.map(([, , driver, high]) => [`scripts/native-qualification/${driver}.py`, high] as const),
    ["test/native-qualification-common.test.ts", 200],
    ["test/native-qualification-a.test.ts", 120],
    ["test/native-qualification-b.test.ts", 120],
    ["test/native-qualification-c.test.ts", 120],
    ["test/native-qualification-d.test.ts", 150],
    ["test/native-qualification-e.test.ts", 180],
    ["test/native-qualification-integration.test.ts", 150],
  ]);
  const diff = spawnSync("git", ["diff", "--numstat", predecessor, "--", ...highs.keys()], { encoding: "utf8" });
  assert.equal(diff.status, 0, diff.stderr);
  const additions = new Map(
    diff.stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((row) => {
        const [added, , path] = row.split("\t");
        return [path, Number(added)] as const;
      }),
  );
  let subtotal = 0;
  for (const [path, high] of highs) {
    const added = additions.get(path) ?? 0;
    subtotal += added;
    assert.ok(added <= high, `${path}: ${added}/${high}`);
    const lines = readFileSync(path, "utf8").split("\n");
    const width = path === workflowPath ? 200 : path.endsWith(".py") ? 160 : 120;
    assert.ok(
      lines.every((line) => line.length <= width),
      `${path}: line exceeds ${width} columns`,
    );
  }
  assert.ok(subtotal <= 4_000, `native subtotal: ${subtotal}/4000`);
});

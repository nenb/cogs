import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = process.cwd();
const python = "/usr/bin/python3";
const predecessor = "bec0a19b0b984f88ab9c2effc5059f3737915caa";
const suites = [
  "outcome-two-runtime-closure-portable.py",
  "outcome-two-mapped-closure-portable.py",
  "outcome-two-sealing-portable.py",
  "outcome-two-lifecycle-portable.py",
  "outcome-two-recovery-portable.py",
  "outcome-two-runtime-report-portable.py",
  "outcome-two-trusted-launcher-portable.py",
] as const;
const highs = new Map<string, number>([
  ["deploy/aws-feasibility/remote/completion_elf.py", 320],
  ["deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py", 2_100],
  ["deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py", 1_900],
  ["schemas/trusted-runtime-closure-v1.json", 260],
  ["scripts/validate-schemas.ts", 30],
  ["test/outcome-two-runtime-closure-portable.py", 350],
  ["test/outcome-two-mapped-closure-portable.py", 300],
  ["test/outcome-two-sealing-portable.py", 300],
  ["test/outcome-two-lifecycle-portable.py", 550],
  ["test/outcome-two-recovery-portable.py", 550],
  ["test/outcome-two-runtime-report-portable.py", 400],
  ["test/outcome-two-trusted-launcher-portable.py", 800],
  ["test/outcome-two-portable.test.ts", 170],
]);
const env = { PYTHONDONTWRITEBYTECODE: "1", PYTHONHASHSEED: "0" };

function run(arguments_: string[], timeout: number) {
  return spawnSync(python, arguments_, {
    cwd: root,
    env,
    encoding: "utf8",
    timeout,
    maxBuffer: 4_194_304,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function requireSuccess(result: ReturnType<typeof run>, label: string) {
  assert.equal(result.error, undefined, `${label} spawn failed: ${result.error?.message}`);
  assert.equal(result.status, 0, `${label} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
}

function git(arguments_: string[]) {
  return spawnSync("git", arguments_, { cwd: root, encoding: "utf8" });
}

test("Outcome 2 portable hostile suites are bounded and optimization-safe", () => {
  for (const suite of suites) {
    const path = join(root, "test", suite);
    const result = run(["-I", "-B", path], 30_000);
    requireSuccess(result, suite);
    assert.match(result.stdout, /Outcome 2 .* portable tests passed/u, suite);

    const optimized = run(["-O", "-I", "-B", path], 5_000);
    assert.equal(optimized.error, undefined, `${suite} optimized run exceeded its bound`);
    assert.notEqual(optimized.status, 0, `${suite} accepted optimized Python`);
    assert.match(optimized.stderr, /optimized (?:mode is forbidden|Python)/u, suite);
  }
});

test("Outcome 2 AJV gate validates the production-schema mutation corpus", () => {
  const reportSuite = join(root, "test", "outcome-two-runtime-report-portable.py");
  const result = run(["-I", "-B", reportSuite, "--schema-corpus"], 5_000);
  requireSuccess(result, "report schema corpus producer");
  const rows = result.stdout
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line) as { id: string; schema: boolean; value: unknown });
  assert.ok(rows.length > 1);
  assert.equal(new Set(rows.map((row) => row.id)).size, rows.length, "duplicate schema case");

  const schemaPath = join(root, "schemas", "trusted-runtime-closure-v1.json");
  const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as { $id: string };
  assert.equal(schema.$id, "https://cogs.dev/schemas/trusted-runtime-closure-v1.json");
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  ajv.addSchema(schema);
  const validate = ajv.getSchema(schema.$id);
  assert.ok(validate, "production schema was not registered in AJV");
  for (const row of rows) {
    assert.equal(
      validate(row.value),
      row.schema,
      `${row.id}: production schema diverged: ${JSON.stringify(validate.errors)}`,
    );
  }
});

test("Outcome 2 dead routes and unsafe lifecycle compatibility stay deleted", () => {
  const production = [
    "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py",
    ...suites.map((suite) => `test/${suite}`),
  ].map((path) => readFileSync(join(root, path), "utf8"));
  const banned = [
    /_drive_fixed_/u,
    /_T2_SEQUENCE/u,
    /_seal_source/u,
    /\.operation\s*\(/u,
    /lambda\s*:\s*None/u,
    /waitpid\s*\([^)]*,\s*0\s*\)/u,
    /except[^:]*:\s*(?:\n\s*){0,3}os\.close\s*\(/u,
    /^\s*[A-Za-z_]\w*\s*:[^#\n]+;\s*[A-Za-z_]\w*\s*:/mu,
    /^(?![ \t]*(?:"""[^\n]*"""|'''[^\n]*''')[ \t]*$)[^#\n]*;/mu,
    /\btrip\s*\(/u,
    /RuntimeLauncherError\([\s\S]{0,200}(?:row|self\.row)\["intended_code"\]/u,
    /record\([^)]*(?:row|self\.row)\["sentinel"\]/u,
  ];
  for (const source of production) {
    for (const pattern of banned) assert.doesNotMatch(source, pattern);
  }
  assert.match(
    production.at(-1) ?? "",
    /def invoke\(self\):\n\s+method = self\.row\["production_method"\][\s\S]*?handlers\[method\]\(\)/u,
  );
});

test("Outcome 2 gross lines and fixture lines remain within exact ADR 0089 highs", () => {
  const paths = [...highs.keys()];
  const diff = git(["diff", "--numstat", predecessor, "--", ...paths]);
  assert.equal(diff.status, 0, diff.stderr);
  const additions = new Map(
    diff.stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((row) => {
        const [added, _deleted, path] = row.split("\t");
        assert.notEqual(added, "-", `${path}: binary counted surface`);
        return [path, Number(added)] as const;
      }),
  );
  let subtotal = 0;
  for (const [path, high] of highs) {
    const added = additions.get(path) ?? 0;
    assert.ok(added <= high, `${path}: ${added} gross lines exceeds ${high}`);
    subtotal += added;
  }

  const fixtures = git(["ls-files", "test/fixtures/outcome-two"]);
  assert.equal(fixtures.status, 0, fixtures.stderr);
  const fixturePaths = fixtures.stdout.trim().split("\n").filter(Boolean);
  for (const path of fixturePaths.filter((path) => path.endsWith(".jsonl"))) {
    const rows = readFileSync(join(root, path), "utf8").trimEnd().split("\n");
    rows.forEach((row, index) => {
      assert.doesNotThrow(() => JSON.parse(row), `${path}:${index + 1} is not one JSON value`);
    });
  }
  const fixtureLines = fixturePaths.reduce((total, path) => {
    const bytes = readFileSync(join(root, path));
    return total + bytes.reduce((lines, byte) => lines + Number(byte === 10), 0);
  }, 0);
  assert.ok(fixtureLines <= 900, `fixture aggregate: ${fixtureLines} lines exceeds 900`);
  assert.ok(subtotal + fixtureLines <= 8_930, `trusted/portable subtotal exceeds 8930`);
});

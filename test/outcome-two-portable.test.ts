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
  ["deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py", 3_100],
  ["deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py", 4_700],
  ["scripts/native-qualification/common.py", 1_920],
  ["schemas/trusted-runtime-closure-v1.json", 700],
  ["scripts/validate-schemas.ts", 300],
  ["test/outcome-two-runtime-closure-portable.py", 1_000],
  ["test/outcome-two-mapped-closure-portable.py", 700],
  ["test/outcome-two-sealing-portable.py", 450],
  ["test/outcome-two-lifecycle-portable.py", 1_800],
  ["test/outcome-two-recovery-portable.py", 1_500],
  ["test/outcome-two-runtime-report-portable.py", 550],
  ["test/outcome-two-trusted-launcher-portable.py", 3_200],
  ["test/outcome-two-portable.test.ts", 400],
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
    const result = run(["-I", "-B", path], 60_000);
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

const readableSurfaces = [
  "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
  "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py",
  "scripts/native-qualification/common.py",
  "scripts/native-qualification/job-a-runtime-mappings.py",
  "scripts/native-qualification/job-b-compression.py",
  "scripts/native-qualification/job-c-descriptors.py",
  "scripts/native-qualification/job-d-process-lifecycle.py",
  "scripts/native-qualification/job-e-sandbox.py",
  "scripts/native-qualification/thin-integration.py",
] as const;

const readabilityScan = String.raw`
import ast
import io
import sys
import tokenize
from pathlib import Path

claim_suffixes = ("Result", "Observation", "Receipt", "Evidence")
allocators = {"open", "memfd_create", "pipe", "pipe2", "socketpair", "accept", "accept4", "dup", "clone3_pidfd", "clone_pidfd", "pidfd_open"}
adoption_words = ("Lease", "adopt", "register", "append", "extend", "transfer", "return", "socket(fileno")
errors = []

def call_name(call):
    function = call.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return ""

def is_allocator(value):
    if not isinstance(value, ast.Call):
        return False
    name = call_name(value)
    if name in allocators:
        return True
    if name != "fcntl" or len(value.args) < 2:
        return False
    command = ast.unparse(value.args[1])
    return "F_DUPFD" in command

def assigned_names(statement):
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return (), None
    value = statement.value
    if not is_allocator(value):
        return (), None
    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    names = []
    for target in targets:
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                names.append(node.id)
    return tuple(names), value

def blocks(node):
    for _field, value in ast.iter_fields(node):
        if isinstance(value, list) and value and all(isinstance(item, ast.stmt) for item in value):
            yield value
            for statement in value:
                yield from blocks(statement)
        elif isinstance(value, ast.AST):
            yield from blocks(value)

def scan(path):
    source = Path(path).read_text()
    tree = ast.parse(source, path)
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for token in tokens:
        if token.type == tokenize.OP and token.string == ";":
            errors.append(f"{path}:{token.start[0]}: semicolon-packed transition")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node)
        if name.endswith(claim_suffixes) and len(node.args) > 1:
            errors.append(f"{path}:{node.lineno}: positional security claim {name}")
    lines = source.splitlines()
    for block in blocks(tree):
        for index, statement in enumerate(block):
            names, _allocation = assigned_names(statement)
            if not names:
                continue
            following = block[index + 1:index + 1 + max(2, len(names))]
            text = "\n".join(
                "\n".join(lines[item.lineno - 1:item.end_lineno])
                for item in following
                if getattr(item, "end_lineno", None) is not None
            )
            adopted = all(name in text for name in names)
            adopted = adopted and any(word in text for word in adoption_words)
            if not adopted:
                errors.append(f"{path}:{statement.lineno}: allocation lacks visible adoption/recovery")

for filename in sys.argv[1:]:
    scan(filename)
if errors:
    raise SystemExit("\n".join(errors))
`;

test("Outcome 2 security transitions stay AST-readable on every production client", () => {
  const result = run(["-I", "-B", "-c", readabilityScan, ...readableSurfaces], 5_000);
  requireSuccess(result, "Outcome 2 AST readability scan");
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
    /def execute_row\(module, row\):[\s\S]*?adapters\[row\["production_method"\]\]\(module, row, created\)/u,
  );
});

test("Outcome 2 gross lines and fixture lines remain within the authorized implementation highs", () => {
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
  assert.ok(fixtureLines <= 1_500, `fixture aggregate: ${fixtureLines} lines exceeds 1500`);
  assert.ok(subtotal + fixtureLines <= 20_500, `trusted/portable subtotal exceeds 20500`);
});

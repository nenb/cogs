import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const fixture = resolve(root, "deploy/aws-feasibility");
const hclFiles = [".terraform.lock.hcl", "main.tf", "outputs.tf", "variables.tf", "versions.tf"];
const shellFiles = [
  "apply.sh",
  "destroy.sh",
  "inventory.sh",
  "plan.sh",
  "run-measurement-campaign.sh",
  "run-measurement-validation.sh",
  "run-runtime-validation.sh",
  "validate.sh",
];
const pythonFiles = ["check-plan.py"];
const files = [...hclFiles, ...shellFiles, ...pythonFiles];
const maximumFileBytes = 256 * 1024;
const maximumTotalBytes = 1024 * 1024;
const sourceInventory = readdirSync(fixture)
  .filter((name) => name === ".terraform.lock.hcl" || /\.(?:py|sh|tf)$/u.test(name))
  .sort();
assert.deepEqual(sourceInventory, [...files].sort(), "complete bounded fixture source inventory");
const sources = new Map<string, string>();
let totalBytes = 0;

function source(name: string): string {
  const cached = sources.get(name);
  if (cached !== undefined) return cached;
  const path = resolve(fixture, name);
  const stat = statSync(path);
  assert.ok(stat.isFile(), `${name}: regular file`);
  assert.ok(stat.size > 0 && stat.size <= maximumFileBytes, `${name}: bounded nonempty source`);
  totalBytes += stat.size;
  const text = readFileSync(path, "utf8");
  assert.ok(text.endsWith("\n"), `${name}: final newline`);
  assert.doesNotMatch(text, /\0|\r/u, `${name}: portable text source`);
  sources.set(name, text);
  return text;
}

function checkHclStructure(name: string, text: string): void {
  const pairs: Record<string, string> = { "{": "}", "[": "]", "(": ")" };
  const closing = new Set(Object.values(pairs));
  const stack: string[] = [];
  let quoted = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    const next = text[index + 1];
    if (lineComment) {
      if (character === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (character === "*" && next === "/") {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') quoted = false;
      continue;
    }
    if (character === '"') quoted = true;
    else if (character === "#" || (character === "/" && next === "/")) lineComment = true;
    else if (character === "/" && next === "*") {
      blockComment = true;
      index += 1;
    } else if (character !== undefined && character in pairs) stack.push(pairs[character] ?? "");
    else if (character !== undefined && closing.has(character)) {
      assert.equal(character, stack.pop(), `${name}: balanced ${character} at byte ${index}`);
    }
  }

  assert.equal(quoted, false, `${name}: closed quoted source`);
  assert.equal(blockComment, false, `${name}: closed block comment`);
  assert.deepEqual(stack, [], `${name}: balanced delimiters`);
  assert.match(text, /^(?:terraform|provider|data|locals|check|resource|variable|output)\b/mu, `${name}: HCL block`);
  assert.doesNotMatch(text, /[ \t]+$/mu, `${name}: no trailing whitespace`);
}

for (const name of hclFiles) checkHclStructure(name, source(name));

for (const name of shellFiles) {
  const text = source(name);
  assert.match(
    text,
    /^#!\/usr\/bin\/env bash\nset -(?=[A-Za-z]*e)(?=[A-Za-z]*u)[A-Za-z]+(?: pipefail)?\n/u,
    `${name}: strict Bash entry`,
  );
  const parsed = spawnSync("/bin/bash", ["-n"], {
    input: text,
    encoding: "utf8",
    env: { LC_ALL: "C", PATH: "/usr/bin:/bin" },
    timeout: 5_000,
  });
  assert.equal(parsed.status, 0, `${name}: ${parsed.stderr}`);
}

for (const name of pythonFiles) {
  const parsed = spawnSync("python3", ["-I", "-B", "-c", "import sys; compile(sys.stdin.read(), '<source>', 'exec')"], {
    input: source(name),
    encoding: "utf8",
    env: { LC_ALL: "C", PATH: "/usr/bin:/bin" },
    timeout: 5_000,
  });
  assert.equal(parsed.status, 0, `${name}: ${parsed.stderr}`);
}

assert.ok(totalBytes <= maximumTotalBytes, "bounded aggregate source");
const versions = source("versions.tf");
const lock = source(".terraform.lock.hcl");
assert.match(versions, /required_version = "= 1\.12\.4"/u);
assert.match(versions, /source\s+= "hashicorp\/aws"[\s\S]*version\s+= "= 6\.54\.0"/u);
assert.match(lock, /provider "registry\.opentofu\.org\/hashicorp\/aws"[\s\S]*version\s+= "6\.54\.0"/u);

console.log(`Statically checked ${files.length} bounded feasibility fixture sources without infrastructure execution.`);

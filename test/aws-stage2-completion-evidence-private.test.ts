import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import test from "node:test";

const root = resolve(process.cwd());

test("fake-only Slice E private custody matrix touches no cloud or acquisition executable", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-fake-evidence-e-"));
  const log = join(temporary, "sentinel.log");
  for (const name of ["aws", "tofu", "terraform", "opentofu", "curl", "wget", "provider", "plugin"]) {
    writeFileSync(join(temporary, name), `#!/bin/sh\nprintf '%s\\n' '${name}' >> '${log}'\nexit 97\n`, { mode: 0o700 });
  }
  const result = spawnSync("python3", [resolve(root, "test/aws-stage2-completion-evidence-private.py")], {
    cwd: root,
    env: { PATH: `${temporary}${delimiter}${process.env.PATH ?? ""}`, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /fake-only completion evidence private custody hostile matrix passed/u);
  let touched = "";
  try {
    touched = readFileSync(log, "utf8");
  } catch (error) {
    assert.equal((error as NodeJS.ErrnoException).code, "ENOENT");
  }
  assert.equal(touched, "");
});

test("synthetic private model has no production driver or publication route", () => {
  const source = readFileSync(resolve(root, "deploy/aws-feasibility/completion_campaign_evidence.py"), "utf8");
  assert.doesNotMatch(source, /\b(?:subprocess|socket|boto3|requests|paramiko)\b/u);
  assert.doesNotMatch(source, /\b(?:terraform|opentofu|access_key|secret_key)\b/iu);
  assert.doesNotMatch(source, /production_publication_authorized["']?\s*:\s*True/u);
  assert.match(source, /production_publication_authorized["']?\s*:\s*False/u);
  assert.match(source, /type\(receipt\) is _ValidatedSynthetic/u);
});

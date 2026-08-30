import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import test from "node:test";

const root = resolve(process.cwd());

test("fake-only Slice C hostile receipt matrix touches no executable sentinel", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-fake-receipts-c-"));
  const log = join(temporary, "sentinel.log");
  for (const name of ["aws", "tofu", "terraform", "opentofu", "curl", "wget", "provider", "plugin"]) {
    const path = join(temporary, name);
    writeFileSync(path, `#!/bin/sh\nprintf '%s\\n' '${name}' >> '${log}'\nexit 97\n`, {
      mode: 0o700,
    });
  }
  const result = spawnSync("python3", [resolve(root, "test/aws-stage2-completion-campaign-receipts.py")], {
    cwd: root,
    env: {
      PATH: `${temporary}${delimiter}${process.env.PATH ?? ""}`,
      PYTHONDONTWRITEBYTECODE: "1",
    },
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /fake-only completion campaign Slice C exhaustive receipt matrix passed/u);
  let sentinelLog = "";
  try {
    sentinelLog = readFileSync(log, "utf8");
  } catch (error) {
    assert.equal((error as NodeJS.ErrnoException).code, "ENOENT");
  }
  assert.equal(sentinelLog, "");
});

test("Slice C receipt interfaces are pure, synthetic-only, and non-authoritative", () => {
  const source = readFileSync(resolve(root, "deploy/aws-feasibility/completion_campaign_receipts.py"), "utf8");
  assert.doesNotMatch(source, /\b(?:subprocess|socket|boto3|requests|paramiko)\b/u);
  assert.doesNotMatch(source, /\b(?:access_key|secret_key|credential_process)\b/iu);
  assert.doesNotMatch(source, /production_authorized["']?\s*:\s*True/u);
  assert.match(source, /production_authorized/u);
  assert.match(source, /bounded-synthetic-fixture/u);
  assert.doesNotMatch(source, /def\s+(?:retry|resume)\b/u);
});

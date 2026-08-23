import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import test from "node:test";

const root = resolve(process.cwd());

test("fake-only Slice B exhaustive controller matrix touches no executable sentinel", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-fake-controller-b-"));
  const log = join(temporary, "sentinel.log");
  for (const name of [
    "aws",
    "tofu",
    "terraform",
    "opentofu",
    "curl",
    "wget",
    "provider",
    "plugin",
  ]) {
    const path = join(temporary, name);
    writeFileSync(path, `#!/bin/sh\nprintf '%s\\n' '${name}' >> '${log}'\nexit 97\n`, { mode: 0o700 });
  }
  const result = spawnSync("python3", [resolve(root, "test/aws-stage2-completion-campaign-controller.py")], {
    cwd: root,
    env: {
      PATH: `${temporary}${delimiter}${process.env.PATH ?? ""}`,
      PYTHONDONTWRITEBYTECODE: "1",
    },
    encoding: "utf8",
    timeout: 180_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /fake-only completion campaign Slice B exhaustive matrix passed/u);
  let sentinelLog = "";
  try {
    sentinelLog = readFileSync(log, "utf8");
  } catch (error) {
    assert.equal((error as NodeJS.ErrnoException).code, "ENOENT");
  }
  assert.equal(sentinelLog, "");
});

test("Slice B source is fake-only and has no executable cloud or public-success surface", () => {
  const source = readFileSync(
    resolve(root, "deploy/aws-feasibility/completion_campaign_controller.py"),
    "utf8",
  );
  assert.doesNotMatch(source, /\b(?:subprocess|socket|boto3|requests|paramiko)\b/u);
  assert.doesNotMatch(source, /\b(?:terraform|opentofu|access_key|secret_key)\b/iu);
  assert.doesNotMatch(source, /production_publication_authorized["']?\s*:\s*True/u);
  assert.match(source, /production_publication_authorized["']?\s*:\s*False/u);
  assert.doesNotMatch(source, /def\s+(?:retry|resume)\b/u);
});

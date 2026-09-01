import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(".github/workflows/stage2-production-approval.yml", "utf8");

test("production approval issuance is canonical, provider-free, signed, and first-created", () => {
  const historicalV2 = execFileSync("git", ["show", "HEAD:schemas/aws-stage2-completion-production-approval-v2.json"], {
    encoding: "utf8",
  });
  assert.equal(readFileSync("schemas/aws-stage2-completion-production-approval-v2.json", "utf8"), historicalV2);
  assert.match(
    readFileSync("schemas/aws-stage2-completion-production-approval-v3.json", "utf8"),
    /production-approval\/v3/u,
  );
  const result = spawnSync("python3", ["-I", "-B", "test/stage2-production-approval.py"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "stage2 production approval issuer checks passed\n");
  assert.match(workflow, /stage2-production-approval\.yml\/runs/u);
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(workflow, /cosign\/cosign@sha256:/u);
  assert.match(workflow, /sign-blob --yes/u);
  assert.match(workflow, /verify-blob/u);
  assert.match(workflow, /approval-authentication\.bundle\.json/u);
  assert.match(workflow, /--network none/u);
  assert.match(workflow, /sigstore-trusted-root\.json/u);
  assert.doesNotMatch(workflow, /aws-actions|AWS_ACCESS_KEY_ID|opentofu|terraform|\bssm\b/u);
  assert.doesNotMatch(workflow, /actions\/(?:upload|download)-artifact@v[0-9]/u);
});

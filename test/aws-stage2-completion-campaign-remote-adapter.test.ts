import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = join(import.meta.dirname, "..");
test("provider-free adapter reaches exact fixed full and readiness wrappers", () => {
  for (const optimize of ["", "1", "2"]) {
    const result = spawnSync(
      "python3",
      ["-I", "-B", join(root, "test/aws-stage2-completion-campaign-remote-adapter.py")],
      {
        cwd: root,
        encoding: "utf8",
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          PYTHONDONTWRITEBYTECODE: "1",
          PYTHONOPTIMIZE: optimize,
        },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "stage2 provider-free remote adapter checks passed\n");
  }
});
test("remote adapter composes no command or cloud effect", () => {
  const source = readFileSync(join(root, "deploy/aws-feasibility/completion_campaign_remote_adapter.py"), "utf8");
  assert.match(source, /run-stage2-completion-full\.sh/u);
  assert.match(source, /run-stage2-completion-readiness\.sh/u);
  assert.match(source, /grant\.json/u);
  assert.doesNotMatch(source, /subprocess|Popen|system\(|boto|terraform|opentofu|requests|urllib|socket/u);
});

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = join(import.meta.dirname, "..");
const probe = join(root, "test/aws-stage2-completion-campaign-production.py");
const source = readFileSync(join(root, "deploy/aws-feasibility/completion_campaign_production.py"), "utf8");

test("provider-free production controller enforces seven independent ordered cycles", () => {
  for (const optimize of ["", "1", "2"]) {
    const result = spawnSync("python3", ["-I", probe], {
      cwd: root,
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONOPTIMIZE: optimize },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "stage2 provider-free production campaign controller checks passed\n");
  }
});

test("production controller is pure while issuing only adapter-sealed, receipt-bound effects", () => {
  assert.doesNotMatch(source, /\b(?:boto|botocore|subprocess|socket|urllib|requests|terraform|opentofu)\b/iu);
  assert.doesNotMatch(source, /\bos\.|Path\(|\bopen\(|getenv|environ|FakeCampaignPorts/u);
  assert.match(
    source,
    /CYCLE_MODES = \("full", "readiness", "readiness", "readiness", "readiness", "readiness", "readiness"\)/u,
  );
  assert.match(source, /INVENTORY_CATEGORIES =/u);
  for (const category of [
    "ec2_instances",
    "ebs_volumes",
    "network_interfaces",
    "eni_public_associations",
    "elastic_ips",
    "vpcs",
    "routes",
  ])
    assert.match(source, new RegExp(`"${category}"`, "u"));
  assert.match(source, /class CleanupReceipt/u);
  assert.match(source, /self\.ports\.recover\(/u);
  assert.doesNotMatch(
    source.slice(source.indexOf("except BaseException as primary")),
    /self\.ports\.effect\("destroy"/u,
  );
  assert.match(source, /self\.final_zero_unix_ns - self\.first_apply_unix_ns/u);
  assert.match(source, /all\(len\(set\(values\)\) == 7/u);
});

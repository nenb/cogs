import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const path = "deploy/aws-feasibility/completion_campaign_aws_adapter.py";
const source = readFileSync(path, "utf8");

test("concrete AWS adapter is import-inert and owns the sole production port issuer", () => {
  const probe = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      [
        "import os,sys",
        "p='/var/lib/cogs/stage2-aws-production-v2'; before=os.path.exists(p)",
        "sys.path.insert(0,'deploy/aws-feasibility')",
        "import completion_campaign_aws_adapter as a",
        "assert os.path.exists(p)==before",
      ].join("; "),
    ],
    { encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } },
  );
  assert.equal(probe.status, 0, probe.stderr);
  assert.match(source, /def _validate_port_authority/u);
  assert.match(source, /production\._issue_adapter_ports\(/u);
  assert.match(source, /class AwsCampaignCustodian/u);
  assert.match(source, /os\.O_EXCL/u);
  assert.match(source, /os\.fsync/u);
  assert.match(source, /def recover\(/u);
  assert.match(source, /def recover_fixed_campaign\(/u);
  assert.match(source, /LOCK = ROOT/u);
  assert.match(source, /ACTIVE = ROOT/u);
  assert.doesNotMatch(source.slice(source.indexOf("def recover(")), /self\.effect\(/u);
});

test("adapter commands and custody paths are fixed rather than caller-selected", () => {
  for (const command of [
    "run-production-effect.sh",
    "run-production-remote.sh",
    "run-production-inventory.sh",
    "recover-production-campaign.sh",
  ])
    assert.match(source, new RegExp(command.replace(".", "\\."), "u"));
  assert.doesNotMatch(source, /sys\.argv|argparse|getenv\(|environ\.get/u);
  assert.match(source, /run_fixed_campaign/u);
  assert.match(source, /issue_completion_evidence\(candidate, custody\)/u);
  assert.match(source, /approval-authentication\.json/u);
});

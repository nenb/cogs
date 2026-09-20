import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const path = "deploy/aws-feasibility/completion_campaign_aws_adapter.py";
const source = readFileSync(path, "utf8");
const launcher = readFileSync("deploy/aws-feasibility/run-production-campaign.sh", "utf8");

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
  assert.match(source, /if not ACTIVE\.exists\(\):/u);
  assert.match(source, /_journal_state\(descriptor, True\)/u);
  assert.match(source, /_retire_credentials\(\)/u);
  assert.match(source, /LOCK = ROOT/u);
  assert.match(source, /ACTIVE = ROOT/u);
  assert.doesNotMatch(source.slice(source.indexOf("def recover(")), /self\.effect\(/u);
});

test("diagnostic normal and recovery entries preserve only the clean selector environment", () => {
  const root = mkdtempSync(join(tmpdir(), "cogs-stage2-r-diagnostic-entry-"));
  try {
    for (const name of ["completion_campaign_aws_entry.py", "completion_campaign_aws_recovery_entry.py"])
      copyFileSync(`deploy/aws-feasibility/${name}`, join(root, name));
    writeFileSync(
      join(root, "completion_campaign_aws_adapter.py"),
      [
        "import os",
        "from pathlib import Path",
        "from dataclasses import dataclass",
        "@dataclass(frozen=True)",
        "class Receipt: result: str",
        "def check():",
        "    expected={'HOME':'/nonexistent','LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin','TZ':'UTC','COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC':'1'}",
        "    assert all(os.environ.get(key)==value for key,value in expected.items())",
        "    assert not any(key.startswith('AWS_') for key in os.environ)",
        "    return Receipt('pass')",
        "CONTINUATION_ADMISSION=Path('/definitely-absent')",
        "def run_fixed_diagnostic_campaign(): return check()",
        "def recover_fixed_campaign(): return check()",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    for (const name of ["completion_campaign_aws_entry.py", "completion_campaign_aws_recovery_entry.py"]) {
      const result = spawnSync(
        "/usr/bin/env",
        [
          "-i",
          "HOME=/nonexistent",
          "LANG=C",
          "LC_ALL=C",
          "PATH=/usr/bin:/bin",
          "TZ=UTC",
          "COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC=1",

          "/usr/bin/python3",
          "-I",
          "-B",
          join(root, name),
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0, `${name}: ${result.stderr}`);
      assert.equal(result.stdout, '{"result":"pass"}\n');
      assert.equal(result.stderr, "");
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("split launcher admits phase two only through the staged capability", () => {
  assert.match(launcher, /aws-stage2-production-continuation-admission-v1\.json/u);
  assert.match(launcher, /COGS_STAGE2_WORKFLOW_REVISION/u);
  assert.match(launcher, /COGS_STAGE2_APPROVAL_ARTIFACT_DIGEST/u);
  assert.match(launcher, /clean\+=\(COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC=1\)/u);
  assert.doesNotMatch(launcher, /case "\$\{COGS_STAGE2_CAMPAIGN_SEGMENT/u);
  assert.doesNotMatch(launcher, /COGS_STAGE2_CONTINUATION_SHA256=/u);
});

test("launcher executable dispatch selects only the exact adapter-custody admission path", () => {
  assert.match(
    launcher,
    /admission=\/var\/lib\/cogs\/stage2-aws-production-v2\/aws-stage2-production-continuation-admission-v1\.json/u,
  );
  const root = mkdtempSync(join(tmpdir(), "cogs-stage2-launcher-dispatch-"));
  try {
    const source = join(root, "source");
    const custody = join(root, "stage2-aws-production-v2");
    const wrong = join(root, "stage2-completion-v1");
    mkdirSync(join(source, "deploy/aws-feasibility"), { recursive: true });
    mkdirSync(custody);
    mkdirSync(wrong);
    const entry = join(source, "deploy/aws-feasibility/completion_campaign_aws_entry.py");
    copyFileSync("deploy/aws-feasibility/completion_campaign_aws_entry.py", entry);
    chmodSync(entry, 0o700);
    writeFileSync(
      join(source, "deploy/aws-feasibility/completion_campaign_aws_adapter.py"),
      [
        "from dataclasses import dataclass",
        "from pathlib import Path",
        "@dataclass(frozen=True)",
        "class Receipt: route: str",
        `CONTINUATION_ADMISSION=Path(${JSON.stringify(join(custody, "aws-stage2-production-continuation-admission-v1.json"))})`,
        "def run_fixed_second_segment(): return Receipt('phase-two')",
        "def run_fixed_first_segment(*_args): return Receipt('phase-one')",
        "def run_fixed_diagnostic_campaign(): return Receipt('diagnostic')",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    const fakeSudo = join(root, "sudo");
    writeFileSync(fakeSudo, '#!/bin/bash\ntest "$1" = -n || exit 90\nshift\nexec "$@"\n', { mode: 0o700 });
    const executable = join(root, "launcher.sh");
    writeFileSync(
      executable,
      launcher
        .replaceAll("/var/lib/cogs/stage2-completion-v1/source", source)
        .replaceAll("/var/lib/cogs/stage2-aws-production-v2", custody)
        .replaceAll("/usr/bin/sudo", fakeSudo),
    );
    chmodSync(executable, 0o700);
    const admission = "aws-stage2-production-continuation-admission-v1.json";
    writeFileSync(join(custody, admission), "{}\n");
    let result = spawnSync(executable, [], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '{"route":"phase-two"}\n');

    rmSync(join(custody, admission));
    writeFileSync(join(wrong, admission), "{}\n");
    result = spawnSync(executable, [], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
    assert.equal(result.status, 64);
    assert.equal(result.stdout, "");

    const firstEnvironment = {
      PATH: "/usr/bin:/bin",
      COGS_STAGE2_WORKFLOW_REVISION: "4".repeat(40),
      COGS_STAGE2_GITHUB_RUN_ID: "101",
      COGS_STAGE2_PRODUCER_JOB_ID: "20",
      COGS_STAGE2_APPROVAL_ARTIFACT_RUN_ID: "10",
      COGS_STAGE2_APPROVAL_ARTIFACT_ID: "11",
      COGS_STAGE2_APPROVAL_ARTIFACT_DIGEST: `sha256:${"5".repeat(64)}`,
      COGS_STAGE2_APPROVAL_ARTIFACT_NAME: `stage2-production-approval-${"4".repeat(40)}-10`,
    };
    result = spawnSync(executable, [], { encoding: "utf8", env: firstEnvironment });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '{"route":"phase-one"}\n');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("adapter commands and custody paths are fixed with one closed diagnostic identity selector", () => {
  for (const command of [
    "run-production-effect.sh",
    "run-production-remote.sh",
    "run-production-inventory.sh",
    "recover-production-campaign.sh",
  ])
    assert.match(source, new RegExp(command.replace(".", "\\."), "u"));
  assert.doesNotMatch(source, /sys\.argv|argparse|getenv\(/u);
  assert.equal(source.match(/os\.environ\.get/g)?.length, 2);
  assert.match(source, /COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC/u);
  assert.match(source, /diagnostic in \{None, "1"\}/u);
  const identityProbe = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      [
        "import os,sys",
        "sys.path.insert(0,'deploy/aws-feasibility')",
        "import completion_campaign_aws_adapter as a",
        "assert a.approval_identity()==a.PRODUCTION_APPROVAL_IDENTITY",
        "os.environ[a.DIAGNOSTIC_ENVIRONMENT]='1'",
        "assert a.approval_identity()==a.DIAGNOSTIC_APPROVAL_IDENTITY",
        "os.environ[a.DIAGNOSTIC_ENVIRONMENT]='invalid'",
        "def rejected():",
        "    try: a.approval_identity()",
        "    except a.AwsAdapterError: return True",
        "    return False",
        "assert rejected()",
      ].join("\n"),
    ],
    { encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } },
  );
  assert.equal(identityProbe.status, 0, identityProbe.stderr);
  assert.match(source, /def run_fixed_first_segment/u);
  assert.match(source, /def run_fixed_second_segment/u);
  assert.doesNotMatch(source, /def run_fixed_campaign/u);
  assert.match(source, /aws-stage2-production-continuation-v1\.json/u);
  assert.match(source, /aws-stage2-production-continuation-admission-v1\.json/u);
  assert.match(source, /continuation_from_bytes/u);
  assert.match(source, /CAMPAIGN_IDENTITY/u);
  assert.match(source, /issue_completion_evidence\(candidate, custody\)/u);
  assert.match(source, /approval-authentication\.json/u);
  assert.match(source, /approval-authentication\.bundle\.json/u);
  assert.match(source, /COSIGN_SHA256/u);
  assert.match(source, /"\/usr\/bin\/unshare", "--net"/u);
  assert.match(source, /stage2-production-approval\.yml@refs\/heads\/main/u);
  assert.match(source, /first_apply_started/u);
  assert.match(source, /maximum_cycle_duration_ns/u);
  assert.match(source, /def _provider_package\(/u);
  assert.match(source, /PROVIDER_MIRROR/u);
  assert.doesNotMatch(source, /TOFU_PROVIDER/u);
});

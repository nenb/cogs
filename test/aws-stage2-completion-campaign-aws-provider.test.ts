import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const modulePath = "deploy/aws-feasibility/completion_campaign_aws_provider.py";
const source = readFileSync(modulePath, "utf8");

test("fixed provider boundary passes its provider-free hostile fake-executor matrix", () => {
  const result = spawnSync("python3", ["test/aws-stage2-completion-campaign-aws-provider.py"], {
    encoding: "utf8",
    env: { LC_ALL: "C", PATH: process.env.PATH ?? "/usr/bin:/bin" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /provider-free concrete AWS boundary checks passed/u);
});

test("inventory owns complete pagination and explicit ENI and EIP public-address scopes", () => {
  assert.match(source, /--starting-token/u);
  assert.match(source, /"-state=" \+ str\(state\)/u);
  assert.match(source, /TF_CLI_CONFIG_FILE/u);
  assert.match(source, /inventory_observer_principal_commitment/u);
  assert.match(source, /eni_public_associations/u);
  assert.match(source, /account-region-wide-public-address/u);
  assert.match(source, /response_commitment/u);
  assert.match(source, /normal_destroy_reissued/u);
  assert.doesNotMatch(source.slice(source.indexOf("def recover(")), /self\.effect\(/u);
});

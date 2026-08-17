import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const productionPath = join(root, "deploy/aws-feasibility/remote/completion_kata_network.py");
const pythonTestPath = join(root, "test/aws-stage2-completion-kata-network.py");

test("S3 fixed network/firewall owner is closed and identity-conservative", async () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  const result = spawnSync("python3", [pythonTestPath], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion Kata network owner fixed-snapshot matrix passed/u);

  const optimized = spawnSync("python3", ["-O", pythonTestPath], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.notEqual(optimized.status, 0);

  const source = await readFile(productionPath, "utf8");
  const lines = source.split("\n").length - 1;
  assert.ok(lines <= 1100, `S3 production exceeds revised hard 1100: ${lines}`);
  assert.match(source, /Action = actions\.CommandId/u);
  assert.match(source, /TcObservation = actions\.CommandId/u);
  assert.match(source, /NFT_TRANSACTION = b'''add table inet cogs_stage2_ssh_v1/u);
  assert.match(source, /QUALIFICATION_CANDIDATE = "UNQUALIFIED_FIXED_HOST_TOOL_OUTPUT_CANDIDATE_V1"/u);
  assert.match(source, /def parse_nft_snapshot\(raw\):/u);
  assert.match(source, /def parse_netns_identity\(raw, stat\):/u);
  assert.match(source, /def parse_tc_qdiscs\(raw, endpoint\):/u);
  assert.match(source, /def parse_tc_filters\(raw, source, target\):/u);
  assert.match(source, /def runtime_difference\(before, after\):/u);
  assert.match(source, /class TeardownPrerequisite\(Enum\):/u);
  assert.match(source, /def recover_netns\(transition, observed, teardown\):/u);
  assert.match(source, /def recover_tc\(transition, observed, teardown\):/u);
  assert.match(source, /def recover_nft\(transition, observed, teardown\):/u);
  assert.match(source, /class FixedNetworkOwner/u);
  assert.match(source, /production network owner requires the sealed coordinator gate/u);
  assert.doesNotMatch(source, /def recovery_state|class Transition:|ADOPT|task_stopped/u);
  assert.doesNotMatch(source, /subprocess|os\.system|shell=True|iptables|masquerade|SNAT|DNAT/u);
  assert.doesNotMatch(source, /^def (?:run|execute|spawn|generic_command)\(/mu);
});

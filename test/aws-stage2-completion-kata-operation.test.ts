import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const operationPath = join(root, "deploy/aws-feasibility/remote/completion_kata_operation.py");
const leasePath = join(root, "deploy/aws-feasibility/remote/completion_rootfs_lease.py");
const testPath = join(root, "test/aws-stage2-completion-kata-operation.py");

test("S0 fixed operation foundation fails closed", async () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env.PYTHONOPTIMIZE;
  const result = spawnSync("python3", [testPath], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 120_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion Kata operation foundation matrix passed/u);

  const optimized = spawnSync("python3", ["-O", testPath], { cwd: root, env, encoding: "utf8" });
  assert.notEqual(optimized.status, 0);

  const operation = await readFile(operationPath, "utf8");
  const lease = await readFile(leasePath, "utf8");
  const operationLines = operation.split("\n").length - 1;
  const leaseExtension = lease.split("\n").length - 1 - 376;
  assert.ok(
    operationLines + leaseExtension <= 1500,
    `S0/S5 operation and lease extension exceeds hard 1500: ${operationLines + leaseExtension}`,
  );

  assert.match(operation, /def _make_authority\(\):[\s\S]*class _FixedJournal:/u);
  assert.match(operation, /def _make_authority\(\):[\s\S]*class OperationAuthority:/u);
  assert.doesNotMatch(operation, /^class (?:_FixedJournal|OperationAuthority):/mu);
  assert.doesNotMatch(operation, /^def _open_io\(\):/mu);
  assert.match(operation, /\) = _make_authority\(\)/u);
  assert.doesNotMatch(operation, /return \(OperationAuthority,/u);
  assert.match(operation, /__slots__ = \(\)/u);
  assert.match(operation, /O_TMPFILE/u);
  assert.match(operation, /identity_flags = fs\._O_PATH \| fs\._O_CLOEXEC/u);
  assert.match(operation, /fs\._mount_id\(identity, self\.control, fs\.FDINFO_FLAGS\)/u);
  assert.match(operation, /generation == original and generation\.key == original\.key/u);
  assert.match(operation, /def create_fixed_operation_test_local\(authority, body\):/u);
  assert.match(operation, /validate_layout\(self, records, journal_generation\)/u);
  assert.match(operation, /records\[1\]\.body\["state_parent"\]/u);
  assert.match(operation, /LOCK_EX \| fcntl\.LOCK_NB/u);
  assert.match(operation, /fs\._observe_child\(self\.state, LOCK_NAME/u);
  assert.match(operation, /fs\._revalidate_chain\(self\.chain/u);
  assert.match(operation, /def close\(self, primary=None\):/u);
  assert.match(operation, /"temporary_peer": "c42g0"/u);
  assert.match(operation, /elif kind == "FINAL_BASELINES":/u);
  assert.match(lease, /def _reopen_kata_reserved\(permit, control\):/u);
  assert.match(lease, /kata_operation\._claim_rootfs_reopen\(permit\)/u);
  assert.match(lease, /kata_operation\._invoke_rootfs_reopen_route\(grant, rootfs_route, control\)/u);
  assert.match(lease, /kata_operation\._settle_rootfs_reopen\(grant, held\.reference\)/u);
  assert.doesNotMatch(lease, /def _reopen_kata_grant|_rootfs_reopen_token|permit\._claim/u);
  assert.doesNotMatch(operation, /def recover_or_begin_fixed/u);
  assert.doesNotMatch(operation, /def _consume_permit/u);
  assert.doesNotMatch(lease, /def _(?:acquire_kata_reserved|acquire_with_token|reopen_token)\(/u);
  assert.doesNotMatch(
    operation,
    /subprocess|socket|requests|urllib|boto|docker|terraform|tofu|completion_rootfs_(?:ledger|lease|builder)/u,
  );
});

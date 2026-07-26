import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const script = join(root, "deploy/aws-feasibility/remote/completion_rootfs_fs.py");
const qualification = join(root, "test/aws-stage2-completion-rootfs-fs.py");

test("D-R2.2a rejects hostile models and remains read-only", async () => {
  const result = spawnSync("python3", [qualification], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /completion rootfs filesystem tests passed/u);

  const source = await readFile(script, "utf8");
  assert.match(source, /O_PATH/u);
  assert.match(source, /flistxattr/u);
  assert.match(source, /llistxattr/u);
  assert.match(source, /surrogateescape/u);
  assert.match(source, /PRIVILEGED_MUTATOR_EXCLUSION/u);
  assert.doesNotMatch(
    source,
    /os\.(?:mkdir|makedirs|unlink|remove|rmdir|rename|replace|link|symlink|write|pwrite|fsync|fdatasync|flock|chmod|chown)\s*\(/u,
  );
  const anonymousDefinitions = source.split("def _open_anonymous(");
  assert.equal(anonymousDefinitions.length, 2);
  const anonymousBody = anonymousDefinitions[1].split("\ndef ", 1)[0];
  assert.equal(source.match(/\bO_RDWR\b/gu)?.length, 1);
  assert.match(anonymousBody, /flags = os\.O_TMPFILE \| os\.O_RDWR \| _O_CLOEXEC/u);
  assert.match(anonymousBody, /_fail\(flags == 0o22200002\)/u);
  assert.match(anonymousBody, /os\.open\(b"\.", flags, mode, dir_fd=directory\.operation_fd\.number\)/u);
  assert.doesNotMatch(
    source,
    /O_CREAT|O_EXCL|O_TRUNC|O_WRONLY|rmtree|os\.walk|glob|subprocess|socket|boto3?|terraform/u,
  );
  assert.doesNotMatch(source, /if __name__|argparse|sys\.argv|os\.environ|os\.getenv/u);
});

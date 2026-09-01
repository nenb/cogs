import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import test from "node:test";

const root = join(import.meta.dirname, "..");
const probe = join(root, "test/aws-stage2-completion-rootfs-prebuilt.py");

test("prebuilt rootfs descriptor and canonical ustar fail closed", () => {
  for (const optimize of ["", "1", "2"]) {
    const result = spawnSync("python3", ["-I", probe], {
      cwd: root,
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONOPTIMIZE: optimize },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "stage2 prebuilt rootfs portable checks passed\n");
  }
});

test("prebuilt consumer module has no producer, tar command, selector, or fallback import", async () => {
  const source = await import("node:fs/promises").then((fs) =>
    fs.readFile(join(root, "deploy/aws-feasibility/remote/completion_rootfs_prebuilt.py"), "utf8"),
  );
  assert.doesNotMatch(source, /completion_rootfs_(?:plan|build|builder|candidate|publish)/u);
  assert.doesNotMatch(source, /extractall|subprocess|os\.system|Popen|\btar\b.*--extract/u);
  assert.doesNotMatch(source, /getenv|environ|sys\.argv|latest|fallback|mirror/u);
});

test("production lease import does not load producer or original-input modules", () => {
  const remote = join(root, "deploy/aws-feasibility/remote");
  const code = `import sys;sys.path.insert(0,${JSON.stringify(remote)});import completion_rootfs_lease,completion_runtime_closure,completion_prebuilt_runtime_contract;forbidden={'completion_rootfs_build','completion_rootfs_candidate','completion_rootfs_plan','completion_rootfs_publish','completion_rootfs_lease_legacy','completion_runtime_closure_legacy'};assert not forbidden & set(sys.modules)`;
  const result = spawnSync("python3", ["-I", "-B", "-c", code], {
    cwd: root,
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
  });
  assert.equal(result.status, 0, result.stderr);
});

test("production bridge reaches only one prebuilt import and no dual-build acquisition", async () => {
  const fs = await import("node:fs/promises");
  const bridge = await fs.readFile(
    join(root, "deploy/aws-feasibility/remote/completion_kata_preparation_bridge.py"),
    "utf8",
  );
  const lease = await fs.readFile(join(root, "deploy/aws-feasibility/remote/completion_rootfs_lease.py"), "utf8");
  const route = bridge.slice(
    bridge.indexOf("def _acquire_fixed_rootfs"),
    bridge.indexOf("def _claim_fixed_live_mapping"),
  );
  assert.match(route, /rootfs_lease\._acquire_prebuilt\(/u);
  assert.doesNotMatch(route, /rootfs_lease\._acquire\(/u);
  const importer = lease.slice(lease.indexOf("def _acquire_prebuilt"), lease.indexOf("def _abandon("));
  assert.match(importer, /"prebuilt-import-intent"/u);
  assert.ok(importer.indexOf('"prebuilt-import-intent"') < importer.indexOf("materializer._materialize_prebuilt("));
  assert.match(importer, /materializer\._materialize_prebuilt\(/u);
  assert.doesNotMatch(
    importer,
    /_build_once|_two_build_outputs|_pinned_publication|load_verified_build_inputs|_create_candidate|_load_pins/u,
  );
  assert.doesNotMatch(importer, /except[\s\S]{0,200}_acquire\(/u);
});

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";

const root = resolve(process.cwd());
const preparer = resolve(root, "scripts/prepare-stage2-fixed-source.py");

const pureChecks = String.raw`
import hashlib,importlib.util,json,os,pathlib,subprocess,sys,tempfile,time
path=sys.argv[1]
spec=importlib.util.spec_from_file_location("stage2_fixed_source",path)
module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=module
spec.loader.exec_module(module)

def rejected(call):
 try: call()
 except module.PrepareError: return
 raise AssertionError("hostile value accepted")

for hostile in (b"",b"/absolute",b"a//b",b"a/../b",b".git/config",b"a/node_modules/x",b"deploy/aws-feasibility/.state/x",bytes((97,0,98))):
 rejected(lambda hostile=hostile:module._validated_path(hostile))

oid=bytes.fromhex("11"*20)
def row(mode,name): return mode+b" "+name+b"\x00"+oid
assert module._tree_entries(row(b"100644",b"tracked.txt"))==((b"100644",b"tracked.txt","11"*20),)
for hostile_tree in (
 row(b"120000",b"link"),
 row(b"100644",b"node_modules"),
 b"100644 missing-nul",
): rejected(lambda hostile_tree=hostile_tree:module._tree_entries(hostile_tree))

plan=module._fixed_test_plan()
raw,approval=module._manifest_bytes(plan)
value=json.loads(raw)
assert tuple(value)==("version","revision","entries")
assert value["revision"]=="a"*40
assert approval.manifest_sha256==hashlib.sha256(raw).hexdigest()
paths=[item["path"] for item in value["entries"]]
assert paths==sorted(paths,key=lambda item:item.encode("utf-8"))
assert ".cogs-stage2-source-v1" in paths
assert ".cogs-stage2-source-manifest-v1.json" not in paths
assert all(".git" not in item.split("/") and "node_modules" not in item.split("/") for item in paths)
result=json.loads(module._result_bytes(module.Preparation("b"*40,"c"*64,3)))
assert result=={"version":module.RESULT_VERSION,"revision":"b"*40,"manifest_sha256":"c"*64,"entries":3,"authority":"qualification-only-fixed-source"}

process_env={"HOME":"/nonexistent","LC_ALL":"C","PATH":"/usr/bin:/bin"}
started=time.monotonic()
rejected(lambda:module._bounded_process(
 (sys.executable,"-c","import os,signal,time\nchild=os.fork()\nif child==0:\n signal.signal(signal.SIGTERM,signal.SIG_IGN)\n time.sleep(10)\nos.write(1,b'x'*65536)\ntime.sleep(10)"),
 "/tmp",process_env,64,module._deadline(0.5)))
assert time.monotonic()-started<3
started=time.monotonic()
rejected(lambda:module._bounded_process(
 (sys.executable,"-c","import time; time.sleep(10)"),
 "/tmp",process_env,64,module._deadline(0.1)))
assert time.monotonic()-started<3

with tempfile.TemporaryDirectory(prefix="cogs-fixed-source-hostile-git-") as base:
 repository=os.path.join(base,"repository")
 os.mkdir(repository)
 git=module.GIT
 env={**os.environ,"LC_ALL":"C","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null"}
 def run(*arguments,input=None):
  result=subprocess.run((git,*arguments),cwd=repository,env=env,input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
  assert result.returncode==0,result.stderr
  return result.stdout.strip()
 run("init")
 pathlib.Path(repository,"safe.txt").write_text("safe\\n",encoding="ascii")
 pathlib.Path(repository,"nested").mkdir()
 pathlib.Path(repository,"nested/tracked.txt").write_text("nested\\n",encoding="ascii")
 pathlib.Path(repository,".gitattributes").write_text("*.txt filter=hostile\\n",encoding="ascii")
 run("add","--","safe.txt","nested/tracked.txt",".gitattributes")
 run("-c","user.name=Fixed","-c","user.email=fixed@example.invalid","commit","-m","fixed")
 original=run("rev-parse","HEAD").decode()
 pathlib.Path(repository,"replacement.txt").write_text("replacement\\n",encoding="ascii")
 run("add","--","replacement.txt")
 replacement_tree=run("write-tree").decode()
 replacement=run("-c","user.name=Fixed","-c","user.email=fixed@example.invalid","commit-tree",replacement_tree,input=b"replacement\\n").decode()
 run("reset","--hard",original)
 run("replace",original,replacement)
 marker=pathlib.Path(repository,"helper-executed")
 command=f"sh -c 'echo executed > {marker}; cat'"
 run("config","filter.hostile.clean",command)
 run("config","filter.hostile.smudge",command)
 run("config","credential.helper",f"!echo executed > {marker}")
 checked=module._load_checked_plan_from(repository)
 assert checked.revision==original
 checked_paths={blob.path for blob in checked.blobs}
 assert "safe.txt" in checked_paths and ".gitattributes" in checked_paths
 assert "replacement.txt" not in checked_paths and not marker.exists()
 assert module._resolve_head(module._git_layout(repository))==original

 real_checkpoint=module._checkpoint
 def mutate_after_scan(label):
  if label=="worktree-scanned": pathlib.Path(repository,"safe.txt").write_bytes(b"changed\\n")
 module._checkpoint=mutate_after_scan
 try: rejected(lambda:module._load_checked_plan_from(repository))
 finally: module._checkpoint=real_checkpoint
 assert pathlib.Path(repository,"safe.txt").read_bytes()==b"changed\\n"
 pathlib.Path(repository,"safe.txt").write_bytes(b"safe\\n")

 preserved=pathlib.Path(base,"nested-preserved")
 def replace_after_scan(label):
  if label=="worktree-scanned":
   pathlib.Path(repository,"nested").rename(preserved)
   pathlib.Path(repository,"nested").mkdir()
   pathlib.Path(repository,"nested/tracked.txt").write_bytes(b"nested\\n")
 module._checkpoint=replace_after_scan
 try: rejected(lambda:module._load_checked_plan_from(repository))
 finally: module._checkpoint=real_checkpoint
 assert preserved.joinpath("tracked.txt").read_bytes()==b"nested\\n"
 assert pathlib.Path(repository,"nested/tracked.txt").read_bytes()==b"nested\\n"

with tempfile.TemporaryDirectory(prefix="cogs-fixed-source-shallow-") as base:
 source=pathlib.Path(base,"source");shallow=pathlib.Path(base,"checkout")
 source.mkdir()
 def git_at(cwd,*arguments):
  result=subprocess.run((module.GIT,*arguments),cwd=cwd,env={**os.environ,"LC_ALL":"C","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null"},stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
  assert result.returncode==0,result.stderr
  return result.stdout.strip()
 git_at(source,"init")
 pathlib.Path(source,"tracked.txt").write_text("first\\n",encoding="ascii")
 git_at(source,"add","--","tracked.txt")
 git_at(source,"-c","user.name=Fixed","-c","user.email=fixed@example.invalid","commit","-m","first")
 pathlib.Path(source,"tracked.txt").write_text("second\\n",encoding="ascii")
 git_at(source,"add","--","tracked.txt")
 git_at(source,"-c","user.name=Fixed","-c","user.email=fixed@example.invalid","commit","-m","second")
 git_at(base,"clone","--depth","1","file://"+str(source),str(shallow))
 git_at(shallow,"checkout","--detach","HEAD")
 assert pathlib.Path(shallow,".git/shallow").is_file()
 shallow_plan=module._load_checked_plan_from(shallow)
 assert shallow_plan.revision==git_at(shallow,"rev-parse","HEAD").decode()
 assert next(blob for blob in shallow_plan.blobs if blob.path=="tracked.txt").content==b"second\\n"
print("portable fixed-source policy, shallow checkout, and hostile Git/process matrix passed")
`;

const linuxFunctional = String.raw`
import hashlib,importlib.util,json,os,pathlib,stat,sys,tempfile
path=sys.argv[1]
spec=importlib.util.spec_from_file_location("stage2_fixed_source_linux",path)
module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=module
spec.loader.exec_module(module)

def rejected(call):
 try: call()
 except (module.PrepareError,module.fs.RootfsFsError,OSError): return
 raise AssertionError("hostile preparation accepted")

def temporary(prefix):
 return tempfile.TemporaryDirectory(prefix=prefix,dir="/work" if pathlib.Path("/work").is_dir() else "/tmp")

def open_parent(path):
 return os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)

with temporary("cogs-fixed-source-") as parent_path:
 os.chmod(parent_path,0o700)
 parent=open_parent(parent_path)
 permit=module._make_test_local_permit_for_tests(parent)
 prepared=module._prepare_test_local_for_tests(permit)
 assert prepared.revision=="a"*40 and prepared.entries==5
 rejected(lambda:module._prepare_test_local_for_tests(permit))
 source=pathlib.Path(parent_path)/"source"
 observed=source.stat(follow_symlinks=False)
 assert stat.S_ISDIR(observed.st_mode) and stat.S_IMODE(observed.st_mode)==0o700
 assert observed.st_uid==observed.st_gid==0
 manifest=(source/".cogs-stage2-source-manifest-v1.json").read_bytes()
 value=json.loads(manifest)
 assert hashlib.sha256(manifest).hexdigest()==prepared.manifest_sha256
 assert all(".git" not in row["path"].split("/") and "node_modules" not in row["path"].split("/") for row in value["entries"])
 os.close(parent)

with temporary("cogs-fixed-source-existing-") as parent_path:
 os.chmod(parent_path,0o700)
 source=pathlib.Path(parent_path)/"source"
 source.mkdir(mode=0o700)
 marker=source/"preserve"
 marker.write_bytes(b"preserve")
 parent=open_parent(parent_path)
 permit=module._make_test_local_permit_for_tests(parent)
 rejected(lambda:module._prepare_test_local_for_tests(permit))
 assert marker.read_bytes()==b"preserve"
 os.close(parent)

with temporary("cogs-fixed-source-link-") as parent_path:
 os.chmod(parent_path,0o700)
 target=pathlib.Path(parent_path)/"target"
 target.mkdir(mode=0o700)
 (target/"preserve").write_bytes(b"preserve")
 (pathlib.Path(parent_path)/"source").symlink_to(target)
 parent=open_parent(parent_path)
 permit=module._make_test_local_permit_for_tests(parent)
 rejected(lambda:module._prepare_test_local_for_tests(permit))
 assert (target/"preserve").read_bytes()==b"preserve"
 os.close(parent)

with temporary("cogs-fixed-source-file-replaced-") as parent_path:
 os.chmod(parent_path,0o700)
 parent=open_parent(parent_path)
 permit=module._make_test_local_permit_for_tests(parent)
 real_checkpoint=module._checkpoint
 def replace_file(label):
  if label=="file-published:module.py":
   target=pathlib.Path(parent_path)/"source/module.py"
   target.unlink()
   target.write_bytes(b"replacement\\n")
   target.chmod(0o400)
 module._checkpoint=replace_file
 try: rejected(lambda:module._prepare_test_local_for_tests(permit))
 finally: module._checkpoint=real_checkpoint
 assert (pathlib.Path(parent_path)/"source/module.py").read_bytes()==b"replacement\\n"
 os.close(parent)

with temporary("cogs-fixed-source-directory-replaced-") as parent_path:
 os.chmod(parent_path,0o700)
 parent=open_parent(parent_path)
 permit=module._make_test_local_permit_for_tests(parent)
 real_checkpoint=module._checkpoint
 def replace_intermediate(label):
  if label=="directory-published:deploy/aws-feasibility":
   source=pathlib.Path(parent_path)/"source"
   (source/"deploy").rename(source/"deploy-original")
   (source/"deploy/aws-feasibility").mkdir(parents=True,mode=0o700)
 module._checkpoint=replace_intermediate
 try: rejected(lambda:module._prepare_test_local_for_tests(permit))
 finally: module._checkpoint=real_checkpoint
 source=pathlib.Path(parent_path)/"source"
 assert (source/"deploy-original/aws-feasibility").is_dir()
 assert (source/"deploy/aws-feasibility").is_dir()
 os.close(parent)
with temporary("cogs-fixed-source-post-bundle-file-") as parent_path:
 os.chmod(parent_path,0o700)
 parent=open_parent(parent_path)
 permit=module._make_test_local_permit_for_tests(parent)
 real_checkpoint=module._checkpoint
 def replace_after_bundle(label):
  if label=="bundle-verified":
   target=pathlib.Path(parent_path)/"source/module.py"
   target.unlink()
   target.write_bytes(b"replacement\\n")
   target.chmod(0o400)
 module._checkpoint=replace_after_bundle
 try: rejected(lambda:module._prepare_test_local_for_tests(permit))
 finally: module._checkpoint=real_checkpoint
 assert (pathlib.Path(parent_path)/"source/module.py").read_bytes()==b"replacement\\n"
 os.close(parent)

with temporary("cogs-fixed-source-post-bundle-directory-") as parent_path:
 os.chmod(parent_path,0o700)
 parent=open_parent(parent_path)
 permit=module._make_test_local_permit_for_tests(parent)
 real_checkpoint=module._checkpoint
 def replace_directory_after_bundle(label):
  if label=="bundle-verified":
   source=pathlib.Path(parent_path)/"source"
   (source/"deploy").rename(pathlib.Path(parent_path)/"deploy-preserved")
   (source/"deploy/aws-feasibility").mkdir(parents=True,mode=0o700)
   fixture=source/"deploy/aws-feasibility/fixture.txt"
   fixture.write_bytes(b"fixed fixture\n")
   fixture.chmod(0o400)
 module._checkpoint=replace_directory_after_bundle
 try: rejected(lambda:module._prepare_test_local_for_tests(permit))
 finally: module._checkpoint=real_checkpoint
 assert (pathlib.Path(parent_path)/"deploy-preserved/aws-feasibility/fixture.txt").read_bytes()==b"fixed fixture\n"
 assert (pathlib.Path(parent_path)/"source/deploy/aws-feasibility/fixture.txt").read_bytes()==b"fixed fixture\n"
 os.close(parent)
print("NONAUTHORITATIVE fixed-source Linux functional matrix passed")
`;

test("qualification-only fixed-source preparer is closed, canonical, and bounded", async () => {
  const source = await readFile(preparer, "utf8");
  assert.match(source, /FIXED_DESTINATION = "\/var\/lib\/cogs\/stage2-completion-v1\/source"/u);
  assert.match(source, /def _prepare_fixed_source\(\):/u);
  assert.match(source, /GIT_NO_REPLACE_OBJECTS/u);
  assert.match(source, /GIT_OBJECT_DIRECTORY/u);
  assert.match(source, /hashlib\.sha1\(header \+ raw, usedforsecurity=False\)/u);
  assert.match(source, /def _bounded_process[\s\S]*start_new_session=True/u);
  assert.match(source, /os\.killpg\(process\.pid, signal\.SIGKILL\)/u);
  assert.match(source, /def _verify_created_directories/u);
  assert.match(source, /def _revalidate_checked_checkout/u);
  assert.match(source, /_checkpoint\("worktree-scanned"\)/u);
  assert.match(source, /_checkpoint\("bundle-verified"\)/u);
  assert.match(source, /fs\._verify_source_bundle/u);
  assert.match(source, /def _test_routes\(\):[\s\S]*class Permit:/u);
  assert.doesNotMatch(
    source,
    /subprocess\.run|os\.environ|os\.getenv|argparse|shutil|tarfile|os\.symlink|shell\s*=\s*True/u,
  );
  assert.doesNotMatch(source, /\bcp\b|\btar\b/u);

  const rejectedArgument = spawnSync("python3", [preparer, "unexpected"], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.notEqual(rejectedArgument.status, 0);
  assert.equal(rejectedArgument.stdout, "");

  const pure = spawnSync("python3", ["-c", pureChecks, preparer], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 60_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  assert.equal(pure.status, 0, `${pure.stdout}\n${pure.stderr}`);
  assert.match(pure.stdout, /portable fixed-source policy, shallow checkout, and hostile Git\/process matrix passed/u);
});

test("qualification-only test route is fd-relative and non-authoritative on Linux root", {
  skip: process.platform !== "linux" || process.arch !== "x64" || process.getuid?.() !== 0,
}, () => {
  const result = spawnSync("python3", ["-c", linuxFunctional, preparer], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /NONAUTHORITATIVE fixed-source Linux functional matrix passed/u);
});

test("qualification-only optional Docker route is local, pull-free, and non-authoritative", {
  skip: process.env.COGS_RUN_STAGE2_FIXED_SOURCE_DOCKER_V1 !== "1",
}, () => {
  const docker = process.env.COGS_STAGE2_FIXED_SOURCE_DOCKER_BINARY ?? "/usr/bin/docker";
  const image = process.env.COGS_STAGE2_FIXED_SOURCE_DOCKER_IMAGE ?? "";
  assert.match(docker, /^\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/u);
  assert.match(image, /^sha256:[0-9a-f]{64}$/u, "set a local Python image ID; pulls are forbidden");
  assert.ok(!root.includes(","));
  const name = `cogs-fixed-source-${randomUUID()}`;
  try {
    const result = spawnSync(
      docker,
      [
        "run",
        "--pull=never",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "DAC_OVERRIDE",
        "--cap-add",
        "FOWNER",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "512m",
        "--cpus",
        "2",
        "--tmpfs",
        "/work:rw,nosuid,nodev,noexec,mode=0700,size=134217728",
        "--mount",
        `type=bind,src=${root},dst=/repo,readonly`,
        "--workdir",
        "/repo",
        image,
        "python3",
        "-c",
        linuxFunctional,
        "/repo/scripts/prepare-stage2-fixed-source.py",
      ],
      { cwd: root, encoding: "utf8", timeout: 180_000, maxBuffer: 2 * 1024 * 1024 },
    );
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /NONAUTHORITATIVE fixed-source Linux functional matrix passed/u);
  } finally {
    spawnSync(docker, ["rm", "--force", name], { encoding: "utf8", timeout: 10_000 });
  }
});

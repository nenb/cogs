import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const remote = join(root, "deploy/aws-feasibility/remote");
const preflight = join(remote, "completion_archive_preflight.py");
const plan = join(remote, "completion_rootfs_plan.py");
const preparation = join(remote, "completion_rootfs_extractor.py");
const platformPin = join(remote, "stage2-completion-rootfs-platform-v1.json");
const bounds = {
  max_entries: 100,
  max_regular_bytes: 1024 * 1024,
  max_file_bytes: 256 * 1024,
  max_path_bytes: 4096,
  max_component_bytes: 255,
};

const pythonHelper = `
import dataclasses,hashlib,importlib.util,json,os,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
remote=Path(sys.argv[1]).parent;sys.path.insert(0,str(remote))
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
p=load("completion_archive_preflight",Path(sys.argv[2]));r=load("completion_rootfs_plan_test",Path(sys.argv[1]));e=load("completion_rootfs_preparation_test",Path(sys.argv[3]));action=sys.argv[4]
try:
 if action=="deb":
  raw=Path(sys.argv[5]).read_bytes();value=p.preflight_fixed_deb(raw,json.loads(sys.argv[6]),json.loads(sys.argv[7]));assert value.raw is raw
  print(json.dumps({"raw":hashlib.sha256(value.raw).hexdigest(),"members":[list(x) for x in value.members],"data":value.data_member,"paths":[x.path for x in value.payload.records]},sort_keys=True))
 elif action=="row":
  source=json.loads(sys.argv[5]);value=r._fixed_package_row(source);source["name"]="changed";copy=value.expected();copy["name"]="changed-again"
  assert value.name=="fixture" and value.expected()["name"]=="fixture"
  try:setattr(value,"name","changed");raise AssertionError()
  except dataclasses.FrozenInstanceError:pass
  inputs=r.RootfsBuildInputs("a"*64,(r.CacheIdentity("one",(1,2,3),"b"*64),),(r.FixedPackageInput(value,None),),r.RootfsPlan((),(),()))
  assert isinstance(inputs.cache,tuple) and isinstance(inputs.packages,tuple)
 elif action=="pin":
  value=e.parse_platform_pin(Path(sys.argv[5]).read_bytes());print(json.dumps({"image":value.image_sha256,"resolution":value.helper_resolution_sha256,"roles":[x.role for x in value.tools]}))
 elif action=="values":
  layout=e.PrivateLayout(5,6,7,8,9,10,("tar","xz"));value=e.DpkgValues(3,4,layout)
  assert value.executable()=="/proc/self/fd/3"
  assert value.argv()==("/usr/bin/dpkg-deb","-x","/proc/self/fd/4","/proc/self/fd/6")
  assert value.environment()=={"PATH":"/proc/self/fd/7","LC_ALL":"C","LANG":"C","HOME":"/proc/self/fd/8","TMPDIR":"/proc/self/fd/9"}
  assert value.inherited_fds()==(3,4,6,7,8,9,10)
 elif action=="seals":
  closed=[];calls=[];writes=[];reads=iter([b"package",b""]);observed=int(sys.argv[5]);e.os.memfd_create=lambda name,flags:41;e.os.write=lambda fd,data:(writes.append(bytes(data)) or len(data));e.os.read=lambda fd,size:next(reads);e.os.fstat=lambda fd:types.SimpleNamespace(st_size=7);e.os.lseek=lambda *args:0;e.os.close=lambda fd:closed.append(fd)
  def fixed(fd,operation,value=None):calls.append((operation,value));return observed if operation==e.F_GET_SEALS else 0
  e.fcntl.fcntl=fixed
  try:assert e.sealed_package(b"package",hashlib.sha256(b"package").hexdigest())==41 and not closed
  except Exception:assert observed!=e.ALL_SEALS and closed==[41]
  assert writes==[b"package"] and (e.F_ADD_SEALS,e.ALL_SEALS) in calls
 elif action=="copy":
  scenario=sys.argv[5];body=b"helper";digest=hashlib.sha256(body).hexdigest();pin=e.ToolPin("helper","tar","/usr/bin/tar",0o755,len(body),digest,hashlib.sha256(b"version").hexdigest());calls=[];target_bytes=bytearray();source_calls=0
  def value(size,atime):return types.SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o755,st_uid=0,st_gid=0,st_nlink=1,st_size=size,st_mtime_ns=3,st_ctime_ns=4,st_atime_ns=atime)
  def fstat(fd):
   if fd==10:
    global source_calls;source_calls+=1;return value(len(body),source_calls if scenario=="atime" else 1)
   return value(len(body)-1 if scenario=="truncate" else len(body),1)
  def opened(name,flags,mode,dir_fd):assert name=="tar" and flags&(e.os.O_RDWR|e.os.O_CREAT|e.os.O_EXCL|e.os.O_NOFOLLOW)==e.os.O_RDWR|e.os.O_CREAT|e.os.O_EXCL|e.os.O_NOFOLLOW and dir_fd==20;return 11
  def pread(fd,size,offset):
   data=body if fd==10 else bytes(target_bytes)
   if fd==11 and scenario=="corrupt":data=b"X"+data[1:]
   return data[offset:offset+size]
  def write(fd,data):
   chunk=bytes(data[:2]);target_bytes.extend(chunk);return len(chunk)
  e.os.fstat=fstat;e.os.open=opened;e.os.pread=pread;e.os.write=write;e.os.fchown=lambda *args:calls.append("chown");e.os.fchmod=lambda *args:calls.append("chmod");e.os.fsync=lambda *args:calls.append("fsync");e.os.close=lambda *args:calls.append("close")
  e.copy_helper(10,20,pin);assert calls.index("chown")<calls.index("chmod") and calls.count("fsync")==2
 elif action=="copy-real-failure":
  scenario=sys.argv[5];root=Path(sys.argv[6]);helper=root/"helpers";helper.mkdir(parents=True,exist_ok=True);source_path=root/"source";body=b"helper";source_path.write_bytes(body);source_path.chmod(0o755)
  source_fd=os.open(source_path,os.O_RDONLY);directory_fd=os.open(helper,os.O_RDONLY|os.O_DIRECTORY);real_fstat=e.os.fstat;real_fchmod=e.os.fchmod;real_fsync=e.os.fsync;target_calls=0
  def changed(value,**changes):
   fields=("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns");result={field:getattr(value,field) for field in fields};result.update(changes);return types.SimpleNamespace(**result)
  def actual_fstat(fd):
   global target_calls
   value=real_fstat(fd)
   if fd==source_fd:return changed(value,st_uid=0)
   target_calls+=1
   if target_calls==1:return value
   return changed(value,st_uid=0,st_gid=0)
  def actual_fsync(fd):
   if fd!=directory_fd:
    if scenario=="corrupt":os.pwrite(fd,b"X",0)
    if scenario=="truncate":os.ftruncate(fd,len(body)-1)
    if scenario=="fsync":raise OSError("fsync")
   return real_fsync(fd)
  e.os.fstat=actual_fstat;e.os.fchown=lambda *args:None
  e.os.fchmod=lambda *args:(_ for _ in ()).throw(OSError("chmod")) if scenario=="chmod" else real_fchmod(*args);e.os.fsync=actual_fsync
  expected=hashlib.sha256(b"wrong").hexdigest() if scenario=="hash" else hashlib.sha256(body).hexdigest();pin=e.ToolPin("helper","tar","/usr/bin/tar",0o755,len(body),expected,hashlib.sha256(b"version").hexdigest())
  try:e.copy_helper(source_fd,directory_fd,pin);raise AssertionError()
  except Exception as error:assert str(error)!="helper cleanup uncertain" and not (helper/"tar").exists()
  finally:os.close(source_fd);os.close(directory_fd)
 elif action=="cleanup-replaced":
  kind=sys.argv[5];root=Path(sys.argv[6]);helper=root/"helpers";helper.mkdir(parents=True,exist_ok=True);name=helper/"tar";name.write_bytes(b"owned");directory_fd=os.open(helper,os.O_RDONLY|os.O_DIRECTORY);descriptor=os.open(name,os.O_RDONLY);created_state=os.fstat(descriptor);created=(created_state.st_dev,created_state.st_ino,created_state.st_uid,created_state.st_nlink);os.close(descriptor);name.unlink()
  if kind=="inode":name.write_bytes(b"replacement")
  else:name.symlink_to("missing-target")
  try:
   try:raise RuntimeError("preparation")
   except Exception as original:
    try:e._remove_failed_helper(directory_fd,"tar",created);raise AssertionError()
    except e.ExtractorPreparationError as error:assert str(error)=="helper cleanup uncertain" and error.__cause__ is not None and error.__cause__.__context__ is original
   assert os.path.lexists(name) and ((kind=="inode" and name.read_bytes()==b"replacement") or (kind=="symlink" and name.is_symlink()))
  finally:os.close(directory_fd)
 elif action=="layout":
  layout=e.PrivateLayout(1,2,3,4,5,6,("tar",));states={fd:types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0,st_gid=0,st_dev=9,st_ino=fd,st_nlink=fd+1) for fd in range(1,7)}
  states.update({fd:states[1] for fd in range(12,17)});parents=iter(range(12,17));e.os.fstat=lambda fd:states[fd];e.os.open=lambda *args,**kwargs:next(parents);e.os.close=lambda fd:None;e.os.listdir=lambda fd:["tar"] if fd==3 else []
  e.validate_private_layout(layout)
 else:raise AssertionError()
except Exception:raise SystemExit(1)
`;

type TarEntry = { name: string; type?: string; body?: string; link?: string; mode?: number };
function octal(value: number, width: number) {
  return `${value.toString(8).padStart(width - 1, "0")}\0`;
}
function tar(entries: TarEntry[]) {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const body = Buffer.from(entry.body ?? "");
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100);
    header.write(octal(entry.mode ?? 0o644, 8), 100, 8, "ascii");
    header.write(octal(0, 8), 108, 8, "ascii");
    header.write(octal(0, 8), 116, 8, "ascii");
    header.write(octal(body.length, 12), 124, 12, "ascii");
    header.write(octal(1, 12), 136, 12, "ascii");
    header.fill(0x20, 148, 156);
    header.write(entry.type ?? "0", 156, 1);
    header.write(entry.link ?? "", 157, 100);
    header.write("ustar\0", 257, 6, "binary");
    header.write("00", 263, 2);
    const checksum = header.reduce((total, byte) => total + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    chunks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}
function arMember(name: string, body: Buffer) {
  const fields = [`${name}/`, "0", "0", "0", "100644", String(body.length)];
  const widths = [16, 12, 6, 6, 8, 10];
  const header = `${fields.map((field, index) => field.padEnd(widths[index] ?? 0)).join("")}\x60\n`;
  return Buffer.concat([Buffer.from(header, "binary"), body, body.length % 2 ? Buffer.from("\n") : Buffer.alloc(0)]);
}
function deb() {
  const control = tar([
    { name: "./", type: "5", mode: 0o755 },
    { name: "./control", body: "Package: fixture\nVersion: 1.0\nArchitecture: amd64\nDescription: fixed\n" },
    { name: "./postinst", body: "#!/bin/sh\nexit 99\n", mode: 0o755 },
  ]);
  const data = tar([
    { name: "./", type: "5", mode: 0o755 },
    { name: "./usr/", type: "5", mode: 0o755 },
    { name: "./usr/tool", body: "fixed\n", mode: 0o755 },
    { name: "./usr/link", type: "2", link: "tool", mode: 0o777 },
  ]);
  return Buffer.concat([
    Buffer.from("!<arch>\n"),
    arMember("debian-binary", Buffer.from("2.0\n")),
    arMember("control.tar", control),
    arMember("data.tar", data),
  ]);
}
function run(action: string, ...args: string[]) {
  return spawnSync("python3", ["-c", pythonHelper, plan, preflight, preparation, action, ...args], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 10_000,
  });
}
function digest(label: string) {
  return createHash("sha256").update(label).digest("hex");
}
function pin() {
  const tool = (role: string, name: string, path: string) => ({
    role,
    name,
    path,
    mode: 0o755,
    size: 1,
    sha256: digest(`${name}-binary`),
    version_sha256: digest(`${name}-version`),
  });
  return {
    version: "cogs.stage2-completion-rootfs-platform/v1",
    image_sha256: digest("offline-image"),
    helper_resolution_sha256: digest("reviewed-helper-resolution"),
    tools: [
      tool("python3", "python3", "/usr/bin/python3.13"),
      tool("dpkg-deb", "dpkg-deb", "/usr/bin/dpkg-deb"),
      tool("helper", "tar", "/usr/bin/tar"),
      tool("helper", "xz", "/usr/bin/xz"),
    ],
  };
}
function pinBytes(value = pin()) {
  return `${JSON.stringify(value)}\n`;
}

test("PreflightedDeb owns full bytes, all ar member identities, and payload without package execution", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-r21a-deb-"));
  try {
    const raw = deb();
    const path = join(dir, "fixture.deb");
    await writeFile(path, raw);
    const result = run(
      "deb",
      path,
      JSON.stringify({ name: "fixture", version: "1.0", architecture: "amd64" }),
      JSON.stringify(bounds),
    );
    assert.equal(result.status, 0, result.stderr);
    const value = JSON.parse(result.stdout) as {
      raw: string;
      members: Array<[string, number, string]>;
      data: string;
      paths: string[];
    };
    assert.equal(value.raw, createHash("sha256").update(raw).digest("hex"));
    assert.deepEqual(
      value.members.map(([name]) => name),
      ["debian-binary", "control.tar", "data.tar"],
    );
    assert.equal(value.data, "data.tar");
    assert.deepEqual(value.paths, ["usr", "usr/tool", "usr/link"]);
    await assert.rejects(readFile(join(dir, "SHOULD-NOT-EXIST")));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("fixed package rows and independent cache input models retain no mutable mapping", () => {
  const row = {
    name: "fixture",
    version: "1.0",
    architecture: "amd64",
    path: "pool/main/f/fixture.deb",
    filename: "fixture.deb",
    cache_name: "fixture.deb",
    url: "https://snapshot.debian.org/fixed",
    size: 1,
    sha256: "a".repeat(64),
  };
  const result = run("row", JSON.stringify(row));
  assert.equal(result.status, 0, result.stderr);
});

test("platform pin requires canonical bytes and exact image, helper-resolution, tool, path, and digest authority", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-r21a-pin-"));
  try {
    const path = join(dir, "pin.json");
    await writeFile(path, pinBytes());
    const accepted = run("pin", path);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.deepEqual(JSON.parse(accepted.stdout).roles, ["python3", "dpkg-deb", "helper", "helper"]);
    for (const raw of [
      JSON.stringify(pin()),
      ` ${pinBytes()}`,
      `${pinBytes()}\n`,
      `${JSON.stringify(pin(), null, 2)}\n`,
    ]) {
      await writeFile(path, raw);
      assert.notEqual(run("pin", path).status, 0);
    }
    const mutations: Array<(value: ReturnType<typeof pin>) => void> = [
      (value) => Object.assign(value, { image_sha256: "a".repeat(64) }),
      (value) => Object.assign(value, { image_sha256: "0".repeat(64) }),
      (value) => Object.assign(value, { image_sha256: digest("") }),
      (value) => Object.assign(value, { helper_resolution_sha256: digest("UNRESOLVED") }),
      (value) => Object.assign(value.tools[2] ?? {}, { path: "/usr/./bin/tar" }),
      (value) => Object.assign(value.tools[2] ?? {}, { path: "/usr//bin/tar" }),
      (value) => Object.assign(value.tools[2] ?? {}, { path: "/usr/bin/.." }),
      (value) => Object.assign(value.tools[2] ?? {}, { path: "/usr/bin/ta\\r" }),
      (value) => Object.assign(value.tools[2] ?? {}, { path: "/usr/bin/ta\u0001r" }),
      (value) => Object.assign(value.tools[0] ?? {}, { path: "/usr/bin/python3.123" }),
      (value) => Object.assign(value.tools[0] ?? {}, { path: "/usr/bin/pytho\u006e\u0303.13" }),
      (value) => Object.assign(value.tools[0] ?? {}, { name: "python" }),
      (value) => Object.assign(value.tools[2] ?? {}, { role: "dpkg-deb" }),
      (value) => value.tools.reverse(),
      (value) => void value.tools.pop(),
      (value) => {
        const duplicate = value.tools.at(-1);
        if (duplicate) value.tools.push(structuredClone(duplicate));
      },
      (value) => Object.assign(value.tools[2] ?? {}, { size: 0 }),
      (value) => Object.assign(value.tools[2] ?? {}, { size: 134_217_729 }),
      (value) => Object.assign(value.tools[2] ?? {}, { sha256: "f".repeat(64) }),
      (value) => Object.assign(value.tools[2] ?? {}, { extra: "hostile" }),
    ];
    for (const mutate of mutations) {
      const hostile = pin();
      mutate(hostile);
      await writeFile(path, pinBytes(hostile));
      assert.notEqual(run("pin", path).status, 0);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("procfd executable, argv, inherited descriptors, and environment values are exact", () => {
  const result = run("values");
  assert.equal(result.status, 0, result.stderr);
});

test("sealed package preparation requires all four seals and closes failure", () => {
  assert.equal(run("seals", String(0x0f)).status, 0);
  assert.equal(run("seals", String(0x07)).status, 0);
});

test("helper preparation verifies actual target bytes and ignores source atime-only drift", () => {
  for (const scenario of ["ok", "atime"]) {
    const result = run("copy", scenario);
    assert.equal(result.status, 0, `${scenario}: ${result.stderr}`);
  }
});

test("failed helper preparation removes only its exact created inode", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-r21a-helper-cleanup-"));
  try {
    for (const scenario of ["corrupt", "truncate", "chmod", "fsync", "hash"]) {
      const result = run("copy-real-failure", scenario, dir);
      assert.equal(result.status, 0, `${scenario}: ${result.stderr}`);
    }
    for (const replacement of ["inode", "symlink"]) {
      const result = run("cleanup-replaced", replacement, join(dir, replacement));
      assert.equal(result.status, 0, `${replacement}: ${result.stderr}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("private directories are direct distinct children without invalid directory link-count assumptions", () => {
  const result = run("layout");
  assert.equal(result.status, 0, result.stderr);
});

test("R2.1a production is fixed, nonexecuting, nonextracting, and closed without an approved pin", async () => {
  const text = await readFile(preparation, "utf8");
  await assert.rejects(readFile(platformPin));
  assert.match(text, /MFD_ALLOW_SEALING/u);
  assert.match(text, /F_SEAL_WRITE/u);
  assert.match(text, /O_RDWR \| os\.O_CREAT \| os\.O_EXCL \| os\.O_NOFOLLOW/u);
  assert.match(await readFile(plan, "utf8"), /"debian-binary", "control\.tar\.xz", "data\.tar\.xz"/u);
  assert.doesNotMatch(text, /\bfork\b|execv|subprocess|pidfd|killpg|PDEATH|extractall|tarfile|renameat|rmtree/u);
  assert.doesNotMatch(
    text,
    /shell=True|os\.environ|os\.getenv|putenv|socket|requests|docker|boto3?|\baws\b|tofu|terraform|ctr/u,
  );
  assert.doesNotMatch(text, /def main|if __name__/u);
});

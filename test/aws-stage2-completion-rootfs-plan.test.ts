import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const planPath = join(root, "deploy/aws-feasibility/remote/completion_rootfs_plan.py");
const preflightPath = join(root, "deploy/aws-feasibility/remote/completion_archive_preflight.py");
const bounds = {
  max_entries: 100,
  max_regular_bytes: 1024 * 1024,
  max_file_bytes: 256 * 1024,
  max_path_bytes: 4096,
  max_component_bytes: 255,
};

const helper = String.raw`
import dataclasses,hashlib,importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
remote=Path(sys.argv[1]).parent
sys.path.insert(0,str(remote))
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path); mod=importlib.util.module_from_spec(spec); sys.modules[name]=mod; spec.loader.exec_module(mod); return mod
m=load("completion_archive_preflight",Path(sys.argv[2])); p=load("completion_rootfs_plan_test",Path(sys.argv[1]))
bounds=json.loads(sys.argv[4]); action=sys.argv[3]
def archive(path,profile): return m._preflight_material_tar(Path(path).read_bytes(),bounds,profile)
def generated(path,content=b"generated\n",mode=0o644):
 record=m.MaterialRecord(path,"file",mode,0,0,1,len(content),None,None,None,hashlib.sha256(content).hexdigest(),-1)
 return p.PlannedEntry("generated",None,record,content)
try:
 if action=="inspect":
  value=archive(sys.argv[5],sys.argv[6]); selected=value.records[-1]
  assert bytes(value.content(next(r for r in value.records if r.kind=="file")))
  print(json.dumps({"raw":len(value.raw),"archive_records":all(type(r) is m.ArchiveRecord for r in value.archive_records),"kind":selected.kind,"archive_size":selected.archive_size,"link_text":selected.link_text,"resolved":selected.resolved_link_path,"hardlink":selected.hardlink_target,"hash":selected.content_sha256},sort_keys=True))
 elif action=="accept": archive(sys.argv[5],sys.argv[6])
 elif action=="plan":
  base=archive(sys.argv[5],"oci"); packages=tuple((f"package-{i}",archive(path,"package")) for i,path in enumerate(sys.argv[6:])); value=p.plan_sources(base,packages)
  print(json.dumps({"sources":value.source_order,"entries":[(e.record.path,e.record.kind,e.source) for e in value.entries]},sort_keys=True))
 elif action=="transition":
  source=p.plan_sources(archive(sys.argv[5],"oci"),())
  entries={e.record.path:e for e in source.entries}; scenario=sys.argv[6]
  if scenario=="valid":
   transitions=(p.Transition("etc/item","replace",p.identity(entries["etc/item"].record),generated("etc/item")),p.Transition("etc/remove","delete",p.identity(entries["etc/remove"].record),None),p.Transition("etc/new","create",None,generated("etc/new")))
  elif scenario=="drift":
   expected=dataclasses.replace(p.identity(entries["etc/item"].record),mode=0o600); transitions=(p.Transition("etc/item","replace",expected,generated("etc/item")),)
  elif scenario=="create-existing": transitions=(p.Transition("etc/item","create",None,generated("etc/item")),)
  elif scenario=="duplicate": transitions=(p.Transition("etc/item","replace",p.identity(entries["etc/item"].record),generated("etc/item")),p.Transition("etc/item","delete",p.identity(entries["etc/item"].record),None))
  else: raise RuntimeError()
  value=p.apply_transitions(source,transitions); print(json.dumps([e.record.path for e in value.entries]))
 else: raise RuntimeError()
except Exception: raise SystemExit(1)
`;

type TarEntry = {
  name: string;
  type?: string;
  body?: Buffer | string;
  link?: string;
  mode?: number;
  uid?: number;
  gid?: number;
  mtime?: number;
};

function octal(value: number, width: number) {
  const digits = value.toString(8);
  assert.ok(digits.length < width);
  return `${digits.padStart(width - 1, "0")}\0`;
}

function tarHeader(entry: TarEntry) {
  const body = Buffer.from(entry.body ?? "");
  const header = Buffer.alloc(512);
  header.write(entry.name, 0, 100, "utf8");
  header.write(octal(entry.mode ?? 0o644, 8), 100, 8, "ascii");
  header.write(octal(entry.uid ?? 0, 8), 108, 8, "ascii");
  header.write(octal(entry.gid ?? 0, 8), 116, 8, "ascii");
  header.write(octal(body.length, 12), 124, 12, "ascii");
  header.write(octal(entry.mtime ?? 1, 12), 136, 12, "ascii");
  header.fill(0x20, 148, 156);
  header.write(entry.type ?? "0", 156, 1, "ascii");
  header.write(entry.link ?? "", 157, 100, "utf8");
  header.write("ustar\0", 257, 6, "binary");
  header.write("00", 263, 2, "ascii");
  const checksum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  return header;
}

function tar(entries: TarEntry[]) {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const body = Buffer.from(entry.body ?? "");
    chunks.push(tarHeader(entry), body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

async function put(dir: string, name: string, entries: TarEntry[]) {
  const path = join(dir, name);
  await writeFile(path, tar(entries));
  return path;
}

function run(action: string, ...args: string[]) {
  return spawnSync("python3", ["-c", helper, planPath, preflightPath, action, JSON.stringify(bounds), ...args], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 10_000,
  });
}

const rootDir: TarEntry = { name: "./", type: "5", mode: 0o755 };

test("immutable OCI result owns bytes and separates literal, resolved, hardlink, and archive-size semantics", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-rootfs-records-"));
  try {
    const relative = await put(dir, "relative.tar", [
      rootDir,
      { name: "usr/", type: "5", mode: 0o755 },
      { name: "usr/bin/", type: "5", mode: 0o755 },
      { name: "usr/bin/tool", body: "tool\n", mode: 0o755 },
      { name: "usr/bin/link", type: "2", link: "../bin/tool", mode: 0o777 },
    ]);
    const inspected = run("inspect", relative, "oci");
    assert.equal(inspected.status, 0, inspected.stderr);
    assert.deepEqual(JSON.parse(inspected.stdout), {
      archive_records: true,
      archive_size: 0,
      hardlink: null,
      hash: null,
      kind: "symlink",
      link_text: "../bin/tool",
      raw: (await readFile(relative)).length,
      resolved: "usr/bin/tool",
    });

    const absolute = await put(dir, "absolute.tar", [
      rootDir,
      { name: "target", body: "x", mode: 0o644 },
      { name: "link", type: "2", link: "/target", mode: 0o777 },
    ]);
    const absoluteResult = run("inspect", absolute, "oci");
    assert.equal(absoluteResult.status, 0, absoluteResult.stderr);
    assert.equal(JSON.parse(absoluteResult.stdout).link_text, "/target");
    assert.equal(JSON.parse(absoluteResult.stdout).resolved, "target");
    assert.notEqual(run("accept", absolute, "package").status, 0);

    const hardlink = await put(dir, "hardlink.tar", [
      rootDir,
      { name: "target", body: "x", mode: 0o640 },
      { name: "copy", type: "1", link: "target", mode: 0o640 },
    ]);
    const hardlinkResult = run("inspect", hardlink, "oci");
    assert.equal(hardlinkResult.status, 0, hardlinkResult.stderr);
    assert.equal(JSON.parse(hardlinkResult.stdout).archive_size, 0);
    assert.equal(JSON.parse(hardlinkResult.stdout).hardlink, "target");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("OCI profile rejects hostile links, whiteouts, devices, duplicates, descendants, and hardlinks", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-rootfs-hostile-"));
  const cases: TarEntry[][] = [
    [rootDir, { name: ".wh.hidden", body: "x" }],
    [rootDir, { name: "device", type: "3" }],
    [rootDir, { name: "link", type: "2", link: "/a/../b", mode: 0o777 }],
    [rootDir, { name: "link", type: "2", link: "//a", mode: 0o777 }],
    [rootDir, { name: "link", type: "2", link: "../escape", mode: 0o777 }],
    [rootDir, { name: "same", body: "a" }, { name: "./same", body: "b" }],
    [rootDir, { name: "link", type: "2", link: "target", mode: 0o777 }, { name: "link/child", body: "x" }],
    [rootDir, { name: "copy", type: "1", link: "missing" }],
    [rootDir, { name: "target", body: "x", mode: 0o644 }, { name: "copy", type: "1", link: "target", mode: 0o600 }],
    [
      rootDir,
      { name: "target", body: "x" },
      { name: "middle", type: "1", link: "target" },
      { name: "copy", type: "1", link: "middle" },
    ],
  ];
  try {
    for (const [index, entries] of cases.entries()) {
      assert.notEqual(run("accept", await put(dir, `case-${index}.tar`, entries), "oci").status, 0, `case ${index}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("combined planner permits only directory overlays and rejects every cross-source conflict or symlink descendant", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-rootfs-graph-"));
  try {
    const base = await put(dir, "base.tar", [
      rootDir,
      { name: "etc/", type: "5", mode: 0o755 },
      { name: "etc/base", body: "base" },
    ]);
    const valid = await put(dir, "valid.tar", [
      rootDir,
      { name: "etc/", type: "5", mode: 0o700 },
      { name: "etc/package", body: "package" },
    ]);
    const accepted = run("plan", base, valid);
    assert.equal(accepted.status, 0, accepted.stderr);
    const value = JSON.parse(accepted.stdout) as { sources: string[]; entries: Array<[string, string, string]> };
    assert.deepEqual(value.sources, ["oci-layer", "package-0"]);
    assert.deepEqual(
      value.entries.find(([path]) => path === "etc"),
      ["etc", "directory", "package-0"],
    );

    const sameFile = await put(dir, "same-file.tar", [
      rootDir,
      { name: "etc/", type: "5", mode: 0o755 },
      { name: "etc/base", body: "base" },
    ]);
    assert.notEqual(run("plan", base, sameFile).status, 0);
    const changedType = await put(dir, "changed-type.tar", [rootDir, { name: "etc", body: "not-directory" }]);
    assert.notEqual(run("plan", base, changedType).status, 0);

    const symlinkPackage = await put(dir, "symlink.tar", [
      rootDir,
      { name: "etc/", type: "5", mode: 0o755 },
      { name: "etc/link", type: "2", link: "base", mode: 0o777 },
    ]);
    const descendantPackage = await put(dir, "descendant.tar", [
      rootDir,
      { name: "etc/", type: "5", mode: 0o755 },
      { name: "etc/link/", type: "5", mode: 0o755 },
      { name: "etc/link/child", body: "x" },
    ]);
    assert.notEqual(run("plan", base, symlinkPackage, descendantPackage).status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("exact transitions default-retain and reject drift, broad replacement, and duplicate paths", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-rootfs-transition-"));
  try {
    const source = await put(dir, "source.tar", [
      rootDir,
      { name: "etc/", type: "5", mode: 0o755 },
      { name: "etc/item", body: "item\n" },
      { name: "etc/remove", body: "remove\n" },
      { name: "etc/retained", body: "retained\n" },
    ]);
    const valid = run("transition", source, "valid");
    assert.equal(valid.status, 0, valid.stderr);
    assert.deepEqual(JSON.parse(valid.stdout), ["etc", "etc/item", "etc/new", "etc/retained"]);
    for (const scenario of ["drift", "create-existing", "duplicate"]) {
      assert.notEqual(run("transition", source, scenario).status, 0, scenario);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("R1 production planner is fixed, read-only, local, and has no R2/R3 mechanism", async () => {
  const text = await readFile(planPath, "utf8");
  assert.match(text, /argv != \["verify-plan"\]/u);
  assert.match(text, /fixed_transitions/u);
  assert.doesNotMatch(
    text,
    /subprocess|Popen|dpkg-deb|extractall|\.extract\(|memfd|renameat|mkdir|unlink|rmtree|socket|requests|urllib\.request/u,
  );
  assert.doesNotMatch(text, /os\.environ|os\.getenv|putenv|boto3?|\baws\b|tofu|terraform|ctr|shell=True/u);
  assert.notEqual(spawnSync("python3", [planPath, "verify-plan", "extra"], { cwd: root }).status, 0);
});

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, link, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

const root = process.cwd();
const verifier = join(root, "deploy/aws-feasibility/remote/verify-completion-artifacts.py");
const helperPath = join(root, "deploy/aws-feasibility/remote/completion_archive_preflight.py");
const pythonHelper = `
import importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location("archive_preflight",sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
try:
 action=sys.argv[2]
 if action=="deb": m.preflight_deb_bytes(Path(sys.argv[3]).read_bytes(),json.loads(sys.argv[4]),json.loads(sys.argv[5]))
 elif action=="tar": m._preflight_tar(Path(sys.argv[3]).read_bytes(),json.loads(sys.argv[4]),sys.argv[5]=="control")
 elif action=="file": m._read_fixed_package(Path(sys.argv[3]),json.loads(sys.argv[4]))
 elif action=="decompress": m._decompress_tar(sys.argv[3],Path(sys.argv[4]).read_bytes(),int(sys.argv[5]))
 else: raise RuntimeError()
except Exception: raise SystemExit(1)
`;

const expected = { name: "fixture", version: "1.0", architecture: "amd64" };
const bounds = {
  max_entries: 100,
  max_regular_bytes: 1024 * 1024,
  max_file_bytes: 256 * 1024,
  max_path_bytes: 4096,
  max_component_bytes: 255,
};

type TarEntry = {
  name: string;
  type?: string;
  body?: Buffer | string;
  link?: string;
  mode?: number;
  uid?: number;
  gid?: number;
  mtime?: number;
  prefix?: string;
};

function run(action: string, ...args: string[]) {
  return spawnSync("python3", ["-c", pythonHelper, helperPath, action, ...args], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 10_000,
  });
}

async function put(dir: string, name: string, bytes: Buffer, mode = 0o600) {
  const path = join(dir, name);
  await writeFile(path, bytes, { mode });
  await chmod(path, mode);
  return path;
}

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
  header.write(entry.prefix ?? "", 345, 155, "utf8");
  const checksum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  return header;
}

function writeTarChecksum(bytes: Buffer, terminated = true) {
  bytes.fill(0x20, 148, 156);
  const checksum = bytes
    .subarray(0, 512)
    .reduce((total, byte) => total + byte, 0)
    .toString(8);
  const field = terminated ? `${checksum.padStart(6, "0")}\0 ` : checksum.padStart(8, "0");
  bytes.write(field, 148, 8, "ascii");
}

function tar(entries: TarEntry[], terminalBlocks = 2) {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const body = Buffer.from(entry.body ?? "");
    chunks.push(tarHeader(entry), body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  chunks.push(Buffer.alloc(terminalBlocks * 512));
  return Buffer.concat(chunks);
}

function paxRecord(key: string, value: string) {
  let length = Buffer.byteLength(` ${key}=${value}\n`) + 1;
  while (true) {
    const record = `${length} ${key}=${value}\n`;
    const actual = Buffer.byteLength(record);
    if (actual === length) return record;
    length = actual;
  }
}

function arMember(name: string, body: Buffer) {
  const fields = [name.endsWith("/") ? name : `${name}/`, "0", "0", "0", "100644", String(body.length)];
  const widths = [16, 12, 6, 6, 8, 10];
  const header = `${fields.map((field, index) => field.padEnd(widths[index] ?? 0, " ")).join("")}\x60\n`;
  assert.equal(Buffer.byteLength(header), 60);
  return Buffer.concat([Buffer.from(header, "binary"), body, body.length % 2 ? Buffer.from("\n") : Buffer.alloc(0)]);
}

function ar(members: Array<[string, Buffer]>) {
  return Buffer.concat([Buffer.from("!<arch>\n"), ...members.map(([name, body]) => arMember(name, body))]);
}

function xz(bytes: Buffer) {
  const result = spawnSync(
    "python3",
    ["-c", "import lzma,sys;sys.stdout.buffer.write(lzma.compress(sys.stdin.buffer.read(),format=lzma.FORMAT_XZ))"],
    { input: bytes, maxBuffer: 4 * 1024 * 1024 },
  );
  assert.equal(result.status, 0, result.stderr.toString());
  return result.stdout;
}

function compress(kind: "raw" | "gz" | "xz", bytes: Buffer) {
  if (kind === "gz") return gzipSync(bytes);
  if (kind === "xz") return xz(bytes);
  return bytes;
}

function controlTar(packageName = expected.name, includeScript = false) {
  const control = `Package: ${packageName}\nVersion: ${expected.version}\nArchitecture: ${expected.architecture}\nDescription: fixture\n`;
  const entries: TarEntry[] = [
    { name: "./", type: "5", mode: 0o755 },
    { name: "./control", body: control },
  ];
  if (includeScript) entries.push({ name: "./postinst", body: "#!/bin/sh\ntouch SHOULD-NOT-EXIST\n", mode: 0o755 });
  return tar(entries, 20);
}

function dataTar(extra: TarEntry[] = []) {
  return tar([
    { name: "./", type: "5", mode: 0o755 },
    { name: "./usr/", type: "5", mode: 0o755 },
    { name: "./usr/bin/", type: "5", mode: 0o755 },
    { name: "./usr/bin/tool-copy", type: "1", link: "usr/bin/tool", mode: 0o755 },
    { name: "./usr/bin/tool", body: "tool\n", mode: 0o755 },
    { name: "./usr/bin/tool-link", type: "2", link: "tool" },
    ...extra,
  ]);
}

function deb(
  controlKind: "raw" | "gz" | "xz" = "gz",
  dataKind: "raw" | "gz" | "xz" = "xz",
  control = controlTar(),
  data = dataTar(),
) {
  const suffix = (kind: "raw" | "gz" | "xz") => (kind === "raw" ? "" : `.${kind}`);
  return ar([
    ["debian-binary", Buffer.from("2.0\n")],
    [`control.tar${suffix(controlKind)}`, compress(controlKind, control)],
    [`data.tar${suffix(dataKind)}`, compress(dataKind, data)],
  ]);
}

async function runDeb(dir: string, bytes: Buffer, customBounds = bounds) {
  const path = await put(dir, `fixture-${Math.random()}.deb`, bytes);
  return run("deb", path, JSON.stringify(expected), JSON.stringify(customBounds));
}

function replaceTarInDeb(control: Buffer, data: Buffer) {
  return ar([
    ["debian-binary", Buffer.from("2.0\n")],
    ["control.tar", control],
    ["data.tar", data],
  ]);
}

test("package preflight accepts strict raw, gzip, and xz archives and leaves scripts inert", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-package-valid-"));
  try {
    for (const [controlKind, dataKind] of [
      ["raw", "raw"],
      ["gz", "xz"],
      ["xz", "gz"],
    ] as const) {
      const result = await runDeb(dir, deb(controlKind, dataKind, controlTar(expected.name, true)));
      assert.equal(result.status, 0, result.stderr);
    }
    await assert.rejects(readFile(join(dir, "SHOULD-NOT-EXIST")));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("strict ar framing rejects hostile magic, headers, names, order, padding, members, and version", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-package-ar-"));
  const valid = deb("raw", "raw");
  const cases: Buffer[] = [];
  cases.push(Buffer.concat([Buffer.from("?<arch>\n"), valid.subarray(8)]));
  const badTrailer = Buffer.from(valid);
  badTrailer[8 + 58] = 0;
  cases.push(badTrailer);
  const badNumeric = Buffer.from(valid);
  badNumeric.write("x", 8 + 48, "ascii");
  cases.push(badNumeric);
  for (const [offset, width, digit] of [
    [8 + 16, 12, "1"],
    [8 + 40, 8, "1"],
    [8 + 48, 10, "0"],
  ] as const) {
    const unterminated = Buffer.from(valid);
    unterminated.write(digit.repeat(width), offset, width, "ascii");
    cases.push(unterminated);
  }
  cases.push(Buffer.concat([valid, Buffer.from("x")]));
  cases.push(
    ar([
      ["debian-binary", Buffer.from("2.1\n")],
      ["control.tar", controlTar()],
      ["data.tar", dataTar()],
    ]),
  );
  cases.push(
    ar([
      ["debian-binary", Buffer.from("2.0\n")],
      ["data.tar", dataTar()],
      ["control.tar", controlTar()],
    ]),
  );
  cases.push(
    ar([
      ["debian-binary", Buffer.from("2.0\n")],
      ["control.tar", controlTar()],
      ["data.tar", dataTar()],
      ["extra", Buffer.alloc(0)],
    ]),
  );
  const badPad = ar([
    ["debian-binary", Buffer.from("2.0\n")],
    ["control.tar", Buffer.from("x")],
    ["data.tar", dataTar()],
  ]);
  badPad[8 + 60 + 4 + 60 + 1] = 0;
  cases.push(badPad);
  try {
    for (const [index, bytes] of cases.entries()) {
      assert.notEqual((await runDeb(dir, bytes)).status, 0, `case ${index}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("compression is one bounded raw, gzip, or xz stream with exact suffix and magic", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-package-compression-"));
  const archive = dataTar();
  const gz = gzipSync(archive);
  const xzBytes = xz(archive);
  try {
    const files = [
      ["data.tar.gz", Buffer.concat([gz, Buffer.from("x")])],
      ["data.tar.gz", Buffer.concat([gz, gz])],
      ["data.tar.gz", gz.subarray(0, -1)],
      ["data.tar.xz", Buffer.concat([xzBytes, Buffer.from("x")])],
      ["data.tar.xz", Buffer.concat([xzBytes, xzBytes])],
      ["data.tar.xz", xzBytes.subarray(0, -1)],
      ["data.tar", gz],
      ["data.tar.zst", Buffer.from("28b52ffd", "hex")],
    ] as const;
    for (const [index, [name, bytes]] of files.entries()) {
      const path = await put(dir, `compressed-${index}`, bytes);
      assert.notEqual(run("decompress", name, path, String(bounds.max_regular_bytes)).status, 0, `case ${index}`);
    }
    const path = await put(dir, "bounded", gz);
    assert.notEqual(run("decompress", "data.tar.gz", path, String(archive.length - 1)).status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("raw tar framing rejects checksum, numeric, padding, body, and terminal ambiguity", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-package-tar-frame-"));
  const validControl = controlTar();
  const validData = dataTar();
  const badChecksum = Buffer.from(validData);
  badChecksum.writeUInt8(badChecksum.readUInt8(0) ^ 1, 0);
  const badBase256 = Buffer.from(validData);
  badBase256.writeUInt8(0x80, 124);
  const unterminatedChecksum = Buffer.from(validData);
  writeTarChecksum(unterminatedChecksum, false);
  const unterminatedSize = Buffer.from(validData);
  unterminatedSize.write("0".repeat(12), 124, 12, "ascii");
  writeTarChecksum(unterminatedSize);
  const badPayloadPad = tar([{ name: "./odd", body: "x" }]);
  badPayloadPad.writeUInt8(1, 513);
  const oneThenMember = Buffer.concat([
    validData.subarray(0, -1024),
    Buffer.alloc(512),
    tarHeader({ name: "late", body: "" }),
    Buffer.alloc(1024),
  ]);
  const secondArchive = Buffer.concat([validData, tar([{ name: "late", body: "" }])]);
  const rolloverData = tar([{ name: "ok", body: Buffer.alloc(18 * 512) }], 21);
  const cases = [
    badChecksum,
    badBase256,
    unterminatedChecksum,
    unterminatedSize,
    badPayloadPad,
    validData.subarray(0, -1),
    oneThenMember,
    secondArchive,
    tar([{ name: "ok", body: Buffer.alloc(18 * 512) }], 22),
  ];
  try {
    assert.equal((await runDeb(dir, replaceTarInDeb(validControl, rolloverData))).status, 0);
    for (const [index, data] of cases.entries()) {
      const bytes = replaceTarInDeb(validControl, data);
      assert.notEqual((await runDeb(dir, bytes)).status, 0, `case ${index}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("PAX and GNU names are bounded overrides while pseudo-members remain outside the path graph", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-package-extensions-"));
  const paxPath = "usr/share/pax-name";
  const pax = tar([
    { name: "./PaxHeaders/item", type: "x", body: paxRecord("path", paxPath) },
    { name: "placeholder", body: "pax\n" },
  ]);
  const longPath = `usr/share/${"long-".repeat(20)}name`;
  const gnu = tar([
    { name: "././@LongLink", type: "L", body: Buffer.from(`${longPath}\0`) },
    { name: "placeholder", body: "gnu\n" },
  ]);
  const paxLink = tar([
    { name: "./PaxHeaders/link", type: "x", body: paxRecord("linkpath", "target") },
    { name: "usr/bin/link", type: "2", link: "placeholder" },
  ]);
  const gnuLink = tar([
    { name: "././@LongLink", type: "L", body: Buffer.from(`${longPath}\0`) },
    { name: "././@LongLink", type: "K", body: Buffer.from("target\0") },
    { name: "placeholder", type: "2", link: "placeholder" },
  ]);
  const hostile = [
    tar([
      { name: "item", prefix: "../hostile", type: "x", body: paxRecord("path", paxPath) },
      { name: "x", body: "x" },
    ]),
    tar([
      { name: "./PaxHeaders/item", type: "g", body: paxRecord("path", paxPath) },
      { name: "x", body: "x" },
    ]),
    tar([
      { name: "./PaxHeaders/item", type: "x", body: paxRecord("mtime", "1") },
      { name: "x", body: "x" },
    ]),
    tar([
      { name: "./PaxHeaders/item", type: "x", body: `${paxRecord("path", "a")}${paxRecord("path", "b")}` },
      { name: "x", body: "x" },
    ]),
    tar([
      { name: "./PaxHeaders/item", type: "x", body: "99 path=a\n" },
      { name: "x", body: "x" },
    ]),
    tar([
      { name: "./PaxHeaders/item", type: "x", body: paxRecord("path", "x".repeat(256)) },
      { name: "x", body: "x" },
    ]),
    tar([{ name: "././@LongLink", type: "L", body: Buffer.from("dangling\0") }]),
    tar([
      { name: "././@LongLink", type: "K", body: Buffer.from("target\0") },
      { name: "././@LongLink", type: "L", body: Buffer.from("name\0") },
      { name: "x", body: "x" },
    ]),
    tar([
      { name: "././@LongLink", type: "L", body: Buffer.from("bad\0junk\0") },
      { name: "x", body: "x" },
    ]),
  ];
  try {
    const paxResult = await runDeb(dir, replaceTarInDeb(controlTar(), pax));
    assert.equal(paxResult.status, 0, paxResult.stderr);
    const gnuResult = await runDeb(dir, replaceTarInDeb(controlTar(), gnu));
    assert.equal(gnuResult.status, 0, gnuResult.stderr);
    assert.equal((await runDeb(dir, replaceTarInDeb(controlTar(), paxLink))).status, 0);
    assert.equal((await runDeb(dir, replaceTarInDeb(controlTar(), gnuLink))).status, 0);
    for (const [index, data] of hostile.entries()) {
      assert.notEqual((await runDeb(dir, replaceTarInDeb(controlTar(), data))).status, 0, `case ${index}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("member paths, types, links, whiteouts, duplicates, and resource bounds fail closed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-package-members-"));
  const cases: TarEntry[][] = [
    [{ name: "/absolute", body: "x" }],
    [{ name: "../escape", body: "x" }],
    [{ name: "././repeated", body: "x" }],
    [{ name: "a//b", body: "x" }],
    [{ name: "back\\slash", body: "x" }],
    [{ name: "cafe\u0301", body: "x" }],
    [{ name: ".wh.hidden", body: "x" }],
    [
      { name: "same", body: "x" },
      { name: "./same", body: "x" },
    ],
    [{ name: "device", type: "3" }],
    [{ name: "escape-link", type: "2", link: "../outside" }],
    [{ name: "absolute-link", type: "2", link: "/outside" }],
    [{ name: "missing-link", type: "1", link: "missing" }],
    [
      { name: "chain-a", type: "1", link: "chain-b" },
      { name: "chain-b", type: "1", link: "target" },
      { name: "target", body: "x" },
    ],
  ];
  try {
    for (const [index, entries] of cases.entries()) {
      const data = tar([{ name: "./", type: "5" }, ...entries]);
      assert.notEqual((await runDeb(dir, replaceTarInDeb(controlTar(), data))).status, 0, `case ${index}`);
    }
    const small = { ...bounds, max_entries: 2 };
    assert.notEqual((await runDeb(dir, deb("raw", "raw"), small)).status, 0);
    const tiny = { ...bounds, max_file_bytes: 2 };
    assert.notEqual((await runDeb(dir, deb("raw", "raw"), tiny)).status, 0);
    const aggregate = { ...bounds, max_regular_bytes: 1024 };
    assert.notEqual((await runDeb(dir, deb("raw", "raw"), aggregate)).status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control metadata is exact and stable same-read package identity rejects filesystem drift", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-package-identity-"));
  const bytes = deb("raw", "raw");
  try {
    assert.notEqual((await runDeb(dir, deb("raw", "raw", controlTar("wrong")))).status, 0);
    const path = await put(dir, "package.deb", bytes, 0o400);
    const row = { size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
    assert.equal(run("file", path, JSON.stringify(row)).status, 0);
    await chmod(path, 0o600);
    assert.notEqual(run("file", path, JSON.stringify(row)).status, 0);
    await chmod(path, 0o400);
    await link(path, join(dir, "second-link"));
    assert.notEqual(run("file", path, JSON.stringify(row)).status, 0);
    await rm(join(dir, "second-link"));
    const outside = await put(dir, "outside", bytes, 0o400);
    const linked = join(dir, "linked.deb");
    await symlink(outside, linked);
    assert.notEqual(run("file", linked, JSON.stringify(row)).status, 0);
    assert.notEqual(run("file", path, JSON.stringify({ ...row, sha256: "f".repeat(64) })).status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("fixed archive CLI composes metadata and production helper remains read-only and local", async () => {
  const verifierText = await readFile(verifier, "utf8");
  const helperText = await readFile(helperPath, "utf8");
  assert.match(verifierText, /argv == \["verify-package-archives"\]/u);
  assert.doesNotMatch(
    helperText,
    /extractall|extractfile|\.extract\(|tempfile|subprocess|socket|requests|urllib|os\.environ|os\.getenv/u,
  );
  assert.doesNotMatch(helperText, /unlink|rmtree|mkdir|chmod|chown|os\.symlink|open\([^\n]*["']w/u);
  assert.doesNotMatch(helperText, /\b(?:boto3?|aws|tofu|terraform|ctr)\b|["']docker["']|shell=True/u);
  assert.notEqual(spawnSync("python3", [verifier, "verify-package-archives", "extra"], { cwd: root }).status, 0);
});

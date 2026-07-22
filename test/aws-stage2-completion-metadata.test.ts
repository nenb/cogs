import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

const root = process.cwd();
const script = join(root, "deploy/aws-feasibility/remote/verify-completion-artifacts.py");
const contractPath = join(root, "deploy/aws-feasibility/remote/stage2-completion-artifacts-v1.json");
const helper = `
import importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location("metadata",sys.argv[1])
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
try:
 c=m.verify_contract(Path(sys.argv[3])); action=sys.argv[2]
 if action=="oci": m.verify_oci_documents(c,*[Path(p).read_bytes() for p in sys.argv[4:7]])
 elif action=="layer": m.verify_gzip_layer(Path(sys.argv[4]),json.loads(sys.argv[5]),int(sys.argv[6]))
 elif action=="inrelease": m.verify_inrelease(c,Path(sys.argv[4]).read_bytes())
 elif action=="packages": m.verify_packages_index(c,Path(sys.argv[4]).read_bytes())
 elif action=="xz": m.decompress_xz(Path(sys.argv[4]).read_bytes(),int(sys.argv[5]))
 else: raise RuntimeError()
except Exception: raise SystemExit(1)
`;

type Artifact = { media_type: string; sha256: string; size: number; diff_id?: string };
type PackageRow = {
  name: string;
  version: string;
  architecture: string;
  path: string;
  size: number;
  sha256: string;
};
type Contract = {
  oci: Record<"index" | "manifest" | "config" | "layer", Artifact>;
  snapshot: { packages_index: { path: string; size: number; sha256: string } };
  packages: PackageRow[];
  bounds: { max_file_bytes: number; max_regular_bytes: number; max_entries: number };
  package_total_bytes: number;
};

function run(action: string, ...args: string[]) {
  return spawnSync("python3", ["-c", helper, script, action, contractPath, ...args], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 10_000,
  });
}

async function put(dir: string, name: string, value: string | Buffer, mode = 0o600) {
  const path = join(dir, name);
  await writeFile(path, value, { mode });
  await chmod(path, mode);
  return path;
}

function sha256(value: Buffer) {
  return createHash("sha256").update(value).digest("hex");
}

function descriptor(row: Artifact) {
  return { mediaType: row.media_type, digest: `sha256:${row.sha256}`, size: row.size };
}

function configDocument() {
  return {
    config: {
      Env: ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
      Entrypoint: [],
      Cmd: ["bash"],
    },
    rootfs: { type: "layers", diff_ids: ["sha256:3edb2192497af6e965b9b7e57dc6dbdce1f3ea721d14a98110419d4ded523298"] },
    os: "linux",
    architecture: "amd64",
  };
}

function ociDocuments(contract: Contract) {
  const config = `${JSON.stringify(configDocument())}\n`;
  const manifest = {
    schemaVersion: 2,
    mediaType: contract.oci.manifest.media_type,
    config: { ...descriptor(contract.oci.config), data: Buffer.from(config).toString("base64") },
    layers: [descriptor(contract.oci.layer)],
  };
  const index = {
    schemaVersion: 2,
    mediaType: contract.oci.index.media_type,
    manifests: [
      { ...descriptor(contract.oci.manifest), platform: { architecture: "amd64", os: "linux" } },
      {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: `sha256:${"a".repeat(64)}`,
        size: 1,
        platform: { architecture: "unknown", os: "unknown" },
      },
    ],
  };
  return { index, manifest, config };
}

async function runOci(dir: string, documents: ReturnType<typeof ociDocuments>, configRaw?: string) {
  const paths = await Promise.all([
    put(dir, "index.json", `${JSON.stringify(documents.index)}\n`),
    put(dir, "manifest.json", `${JSON.stringify(documents.manifest)}\n`),
    put(dir, "config.json", configRaw ?? documents.config),
  ]);
  return run("oci", ...paths);
}

function inrelease(contract: Contract, row?: string) {
  const index = contract.snapshot.packages_index;
  const releasePath = index.path.replace("dists/trixie/", "");
  const selected = row ?? ` ${index.sha256} ${index.size} ${releasePath}`;
  return `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\nSHA256:\n${selected}\n ${"a".repeat(64)} 1 other\n-----BEGIN PGP SIGNATURE-----\n\nYWJj\n=YWJj\n-----END PGP SIGNATURE-----\n`;
}

function packageIndex(contract: Contract) {
  return contract.packages
    .map(
      (row) =>
        `Package: ${row.name}\nVersion: ${row.version}\nArchitecture: ${row.architecture}\nFilename: ${row.path}\nSize: ${row.size}\nSHA256: ${row.sha256}\nDescription: selected package\n`,
    )
    .join("\n");
}

function xz(value: string | Buffer) {
  const result = spawnSync(
    "python3",
    ["-c", "import lzma,sys;sys.stdout.buffer.write(lzma.compress(sys.stdin.buffer.read(),format=lzma.FORMAT_XZ))"],
    {
      input: value,
      maxBuffer: 150 * 1024 * 1024,
    },
  );
  assert.equal(result.status, 0, result.stderr.toString());
  return result.stdout;
}

test("metadata preflight accepts exact-shaped OCI documents and rejects hostile graph/config forms", async () => {
  const contract = JSON.parse(await readFile(contractPath, "utf8")) as Contract;
  const dir = await mkdtemp(join(tmpdir(), "cogs-metadata-oci-"));
  try {
    assert.equal((await runOci(dir, ociDocuments(contract))).status, 0);
    const hostile: Array<(docs: ReturnType<typeof ociDocuments>) => string | undefined> = [
      (docs) => {
        const selected = docs.index.manifests[0];
        assert.ok(selected);
        docs.index.manifests.push(structuredClone(selected));
        return undefined;
      },
      (docs) => {
        const selected = docs.index.manifests[0];
        assert.ok(selected);
        const ambiguous = structuredClone(selected);
        Object.assign(ambiguous.platform, { variant: "hostile" });
        docs.index.manifests.push(ambiguous);
        return undefined;
      },
      (docs) => {
        const selected = docs.index.manifests[0];
        assert.ok(selected);
        Object.assign(selected.platform, { variant: "hostile" });
        return undefined;
      },
      (docs) => {
        const selected = docs.index.manifests[0];
        assert.ok(selected);
        selected.digest = `sha256:${"f".repeat(64)}`;
        return undefined;
      },
      (docs) => {
        const selected = docs.index.manifests[0];
        assert.ok(selected);
        selected.platform.architecture = "arm64";
        return undefined;
      },
      (docs) => {
        docs.manifest.layers.push(descriptor(contract.oci.layer));
        return undefined;
      },
      (docs) => {
        docs.manifest.config.data = Buffer.from("wrong\n").toString("base64");
        return undefined;
      },
      (docs) => {
        const changed = configDocument();
        changed.config.Cmd = ["sh"];
        const raw = `${JSON.stringify(changed)}\n`;
        docs.manifest.config.data = Buffer.from(raw).toString("base64");
        return raw;
      },
    ];
    for (const mutate of hostile) {
      const docs = ociDocuments(contract);
      const raw = mutate(docs);
      assert.notEqual((await runOci(dir, docs, raw)).status, 0);
    }
    const docs = ociDocuments(contract);
    const duplicate = docs.config.replace(/^\{/u, '{"os":"linux",');
    docs.manifest.config.data = Buffer.from(duplicate).toString("base64");
    assert.notEqual((await runOci(dir, docs, duplicate)).status, 0);
    const nonfinite = docs.config.replace('"architecture":"amd64"', '"extra":NaN,"architecture":"amd64"');
    docs.manifest.config.data = Buffer.from(nonfinite).toString("base64");
    assert.notEqual((await runOci(dir, docs, nonfinite)).status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("metadata preflight verifies one bounded gzip stream and exact compressed and diff identities", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-metadata-gzip-"));
  const payload = Buffer.from("rootfs-tar-like-content\n".repeat(64));
  const valid = gzipSync(payload);
  const cases: Array<{ raw: Buffer; maximum?: number; diff?: string; rawHash?: string; valid?: boolean }> = [
    { raw: valid, valid: true },
    { raw: valid.subarray(0, -1) },
    { raw: Buffer.concat([valid, Buffer.from("x")]) },
    { raw: Buffer.concat([valid, valid]) },
    { raw: Buffer.from(valid).fill(0, valid.length - 8, valid.length - 4) },
    { raw: valid, maximum: payload.length - 1 },
    { raw: valid, diff: "f".repeat(64) },
    { raw: valid, rawHash: "f".repeat(64) },
  ];
  try {
    for (const [index, item] of cases.entries()) {
      const path = await put(dir, `layer-${index}.gz`, item.raw, 0o400);
      const row = {
        size: item.raw.length,
        sha256: item.rawHash ?? sha256(item.raw),
        diff_id: item.diff ?? sha256(payload),
      };
      const result = run("layer", path, JSON.stringify(row), String(item.maximum ?? payload.length));
      assert.equal(result.status === 0, item.valid === true, `case ${index}: ${result.stderr}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("metadata preflight binds the strict clear-signed InRelease SHA256 row", async () => {
  const contract = JSON.parse(await readFile(contractPath, "utf8")) as Contract;
  const dir = await mkdtemp(join(tmpdir(), "cogs-metadata-inrelease-"));
  const expected = contract.snapshot.packages_index;
  const releasePath = expected.path.replace("dists/trixie/", "");
  const valid = inrelease(contract);
  const cases = [
    valid,
    valid.replace("Hash: SHA256", "Hash: SHA512"),
    valid.replace("Origin: Debian", "Hash: SHA256\nOrigin: Debian"),
    valid.replace("SHA256:\n", "SHA256:\nSHA256:\n"),
    valid.replace(
      "-----BEGIN PGP SIGNATURE-----",
      ` ${expected.sha256} ${expected.size} ${releasePath}\n-----BEGIN PGP SIGNATURE-----`,
    ),
    inrelease(contract, ` ${"f".repeat(64)} ${expected.size} ${releasePath}`),
    inrelease(contract, ` ${expected.sha256} ${expected.size + 1} ${releasePath}`),
    valid.replace("Origin: Debian", "-bad-cleartext"),
    valid.replace("Origin: Debian", "Origin:\u0000Debian"),
    `${valid}trailing\n`,
  ];
  try {
    for (const [index, value] of cases.entries()) {
      const path = await put(dir, `inrelease-${index}`, value);
      assert.equal(run("inrelease", path).status === 0, index === 0, `case ${index}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("metadata preflight parses one bounded xz package index and exact ten package stanzas", async () => {
  const contract = JSON.parse(await readFile(contractPath, "utf8")) as Contract;
  const dir = await mkdtemp(join(tmpdir(), "cogs-metadata-packages-"));
  const validText = packageIndex(contract);
  const valid = xz(validText);
  const first = contract.packages[0];
  assert.ok(first);
  const firstStanza = validText.split("\n\n")[0];
  assert.ok(firstStanza);
  const textCases = [
    validText,
    validText.replace(`${firstStanza}\n\n`, ""),
    `${validText}\n${firstStanza}\n`,
    validText.replace(`Version: ${first.version}`, "Version: wrong"),
    validText.replace(`Architecture: ${first.architecture}`, "Architecture: arm64"),
    validText.replace(`Filename: ${first.path}`, "Filename: ../wrong.deb"),
    validText.replace(`Size: ${first.size}`, `Size: ${first.size + 1}`),
    validText.replace(`SHA256: ${first.sha256}`, `SHA256: ${"f".repeat(64)}`),
    validText.replace(`Version: ${first.version}`, `Version: ${first.version}\nVersion: duplicate`),
    validText.replace(`Package: ${first.name}`, ` continuation-without-field\nPackage: ${first.name}`),
  ];
  try {
    for (const [index, text] of textCases.entries()) {
      const path = await put(dir, `packages-${index}.xz`, xz(text));
      assert.equal(run("packages", path).status === 0, index === 0, `case ${index}`);
    }
    const compressedCases = [
      valid.subarray(0, -1),
      Buffer.concat([valid, Buffer.from("x")]),
      Buffer.concat([valid, valid]),
    ];
    for (const [index, raw] of compressedCases.entries()) {
      const path = await put(dir, `hostile-${index}.xz`, raw);
      assert.notEqual(run("packages", path).status, 0);
    }
    const bounded = await put(dir, "bounded.xz", valid);
    assert.notEqual(run("xz", bounded, String(Buffer.byteLength(validText) - 1)).status, 0);
    const longLine = `${"x".repeat(131_073)}\n`;
    assert.notEqual(run("packages", await put(dir, "long.xz", xz(longLine))).status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("metadata CLI is fixed and production metadata verification remains read-only and local", async () => {
  const text = await readFile(script, "utf8");
  assert.match(text, /argv == \["verify-metadata"\]/u);
  assert.doesNotMatch(
    text,
    /\b(?:tarfile|binascii|subprocess|socket|requests|urllib\.request)\b|extractall|\.extract\(/u,
  );
  assert.doesNotMatch(text, /os\.environ|os\.getenv|putenv|unlink|rmtree|mkdir|chmod|chown|open\([^\n]*["']w/u);
  assert.doesNotMatch(text, /\b(?:boto3?|aws|tofu|terraform|ctr)\b|["']docker["']|shell=True/u);
  assert.notEqual(spawnSync("python3", [script, "verify-metadata", "/tmp/hostile"], { cwd: root }).status, 0);
  assert.notEqual(spawnSync("python3", [script, "verify-metadata", "extra"], { cwd: root }).status, 0);
});

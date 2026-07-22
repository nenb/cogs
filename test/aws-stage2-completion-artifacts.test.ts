import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const script = join(root, "deploy/aws-feasibility/remote/verify-completion-artifacts.py");
const contractPath = join(root, "deploy/aws-feasibility/remote/stage2-completion-artifacts-v1.json");
const pythonHelper = `
import importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location("completion_artifacts", sys.argv[1])
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    if sys.argv[2] == "contract": module.verify_contract(Path(sys.argv[3]))
    elif sys.argv[2] == "cache": module.verify_cache_root(Path(sys.argv[3]), json.loads(sys.argv[4]))
    else: raise RuntimeError()
except Exception:
    raise SystemExit(1)
`;

type PackageRow = {
  name: string;
  version: string;
  architecture: string;
  path: string;
  filename: string;
  cache_name: string;
  url: string;
  size: number;
  sha256: string;
};
type Contract = {
  version: string;
  platform: Record<string, unknown>;
  source_date_epoch: number;
  oci: Record<string, Record<string, unknown> | string>;
  snapshot: Record<string, Record<string, unknown> | string>;
  packages: PackageRow[];
  package_total_bytes: number;
  bounds: Record<string, unknown>;
  fixtures: Record<string, unknown>;
  tools: Record<string, unknown>;
  timeouts_seconds: Record<string, unknown>;
  [key: string]: unknown;
};
type CacheEntry = { cache_name: string; size: number; sha256: string };

function runPython(mode: "contract" | "cache", path: string, entries: CacheEntry[] = []) {
  return spawnSync("python3", ["-c", pythonHelper, script, mode, path, JSON.stringify(entries)], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 10_000,
  });
}

function cloneContract(value: Contract): Contract {
  return structuredClone(value);
}

function packageAt(value: Contract, index: number): PackageRow {
  const row = value.packages[index];
  assert.ok(row);
  return row;
}

async function writeContract(dir: string, value: unknown, raw?: string): Promise<string> {
  const path = join(dir, "contract.json");
  await writeFile(path, raw ?? `${JSON.stringify(value, null, 2)}\n`, { mode: 0o644 });
  await chmod(path, 0o644);
  return path;
}

function digest(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

async function makeCache(dir: string, content = "abc") {
  const state = join(dir, ".state");
  const completion = join(state, "completion-v1");
  const artifactRoot = join(completion, "artifacts");
  const cache = join(artifactRoot, "cache");
  await mkdir(cache, { recursive: true, mode: 0o700 });
  for (const path of [state, completion, artifactRoot, cache]) await chmod(path, 0o700);
  await writeFile(join(artifactRoot, ".cogs-stage2-completion-artifacts-v1"), "cogs-stage2-completion-artifacts-v1\n", {
    mode: 0o600,
  });
  const file = join(cache, "artifact.bin");
  await writeFile(file, content, { mode: 0o400 });
  await chmod(file, 0o400);
  return {
    state,
    completion,
    artifactRoot,
    cache,
    file,
    entries: [{ cache_name: "artifact.bin", size: 3, sha256: digest("abc") }],
  };
}

test("Stage 2 completion artifact contract is exact, ordered, and fully pinned", async () => {
  const contract = JSON.parse(await readFile(contractPath, "utf8")) as Contract;
  const result = spawnSync("python3", [script, "verify-contract"], { cwd: root, encoding: "utf8", timeout: 10_000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(contract.packages.length, 10);
  assert.deepEqual(
    contract.packages.map((row) => row.name),
    [
      "git",
      "openssh-server",
      "libcom-err2",
      "libgssapi-krb5-2",
      "libk5crypto3",
      "libkeyutils1",
      "libkrb5-3",
      "libkrb5support0",
      "libwrap0",
      "libwtmpdb0",
    ],
  );
  assert.equal(
    contract.packages.reduce((total, row) => total + row.size, 0),
    10_145_436,
  );
  assert.equal(contract.bounds.artifact_count, 16);
  for (const row of contract.packages) {
    assert.equal(row.architecture, "amd64");
    assert.equal(row.filename, row.cache_name);
    assert.equal(row.url, `https://snapshot.debian.org/archive/debian/20260713T000000Z/${row.path}`);
    assert.match(row.sha256, /^[a-f0-9]{64}$/u);
  }
  assert.doesNotMatch(await readFile(contractPath, "utf8"), /UNRESOLVED|stage2-completion-sshd_config/u);
});

test("contract verification rejects hostile shape, types, order, duplicates, totals, URLs, paths, and hashes", async () => {
  const valid = JSON.parse(await readFile(contractPath, "utf8")) as Contract;
  const dir = await mkdtemp(join(tmpdir(), "cogs-stage2-contract-"));
  const cases: Array<(value: Contract) => void> = [
    (value) => delete (value as Record<string, unknown>).platform,
    (value) => {
      value.extra = "bad";
    },
    (value) => {
      value.bounds.artifact_count = true;
    },
    (value) => value.packages.reverse(),
    (value) => {
      packageAt(value, 1).name = packageAt(value, 0).name;
    },
    (value) => {
      packageAt(value, 1).filename = packageAt(value, 0).filename;
      packageAt(value, 1).cache_name = packageAt(value, 0).cache_name;
    },
    (value) => {
      packageAt(value, 1).url = packageAt(value, 0).url;
    },
    (value) => {
      packageAt(value, 1).sha256 = packageAt(value, 0).sha256;
    },
    (value) => {
      value.package_total_bytes += 1;
    },
    (value) => {
      packageAt(value, 0).path = "../git.deb";
    },
    (value) => {
      packageAt(value, 0).sha256 = "f".repeat(63);
    },
  ];
  try {
    for (const mutate of cases) {
      const value = cloneContract(valid);
      mutate(value);
      assert.notEqual(runPython("contract", await writeContract(dir, value)).status, 0);
    }
    for (const url of [
      "http://snapshot.debian.org/archive/debian/20260713T000000Z/pool/main/g/git/a.deb",
      "https://user@snapshot.debian.org/archive/debian/20260713T000000Z/pool/main/g/git/a.deb",
      "https://snapshot.debian.org:443/archive/debian/20260713T000000Z/pool/main/g/git/a.deb",
      "https://example.invalid/archive/debian/20260713T000000Z/pool/main/g/git/a.deb",
      "https://snapshot.debian.org/wrong/a.deb",
      "https://snapshot.debian.org/archive/debian/20260713T000000Z/pool/main/g/git/a.deb?q=1",
      "https://snapshot.debian.org/archive/debian/20260713T000000Z/pool/main/g/git/a.deb#fragment",
    ]) {
      const value = cloneContract(valid);
      packageAt(value, 0).url = url;
      assert.notEqual(runPython("contract", await writeContract(dir, value)).status, 0);
    }
    const { platform, version, ...rest } = valid;
    const reordered = { platform, version, ...rest } as Contract;
    assert.notEqual(runPython("contract", await writeContract(dir, reordered)).status, 0);
    const raw = (await readFile(contractPath, "utf8")).replace(
      /^\{/u,
      '{\n  "version": "cogs.stage2-completion-artifacts/v1",',
    );
    assert.notEqual(runPython("contract", await writeContract(dir, valid, raw)).status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("cache verifier accepts exact private state and preserves invalid artifacts", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-stage2-cache-"));
  try {
    const fixture = await makeCache(dir);
    assert.equal(runPython("cache", fixture.artifactRoot, fixture.entries).status, 0);
    const before = await lstat(fixture.file);
    await chmod(fixture.file, 0o600);
    const rejected = runPython("cache", fixture.artifactRoot, fixture.entries);
    assert.notEqual(rejected.status, 0);
    const after = await lstat(fixture.file);
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.equal(await readFile(fixture.file, "utf8"), "abc");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("cache verifier rejects symlink, directory, FIFO, hardlink, mode, extra, size, and hash drift", async () => {
  const mutations: Array<(fixture: Awaited<ReturnType<typeof makeCache>>, dir: string) => Promise<void>> = [
    async (fixture, dir) => {
      await rm(fixture.file);
      const outside = join(dir, "outside");
      await writeFile(outside, "abc");
      await symlink(outside, fixture.file);
    },
    async (fixture) => {
      await rm(fixture.file);
      await mkdir(fixture.file);
    },
    async (fixture) => {
      await rm(fixture.file);
      const made = spawnSync("python3", ["-c", "import os,sys; os.mkfifo(sys.argv[1], 0o400)", fixture.file]);
      assert.equal(made.status, 0);
    },
    async (fixture, dir) => {
      await link(fixture.file, join(dir, "second-link"));
    },
    async (fixture) => chmod(fixture.file, 0o600),
    async (fixture) => writeFile(join(fixture.cache, "extra"), "x", { mode: 0o400 }),
    async (fixture) => {
      await chmod(fixture.file, 0o600);
      await writeFile(fixture.file, "ab");
      await chmod(fixture.file, 0o400);
    },
    async (fixture) => {
      await chmod(fixture.file, 0o600);
      await writeFile(fixture.file, "abcd");
      await chmod(fixture.file, 0o400);
    },
    async (fixture) => {
      await chmod(fixture.file, 0o600);
      await writeFile(fixture.file, "xyz");
      await chmod(fixture.file, 0o400);
    },
  ];
  for (const mutate of mutations) {
    const dir = await mkdtemp(join(tmpdir(), "cogs-stage2-cache-hostile-"));
    try {
      const fixture = await makeCache(dir);
      await mutate(fixture, dir);
      assert.notEqual(runPython("cache", fixture.artifactRoot, fixture.entries).status, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("cache verifier rejects sentinel and directory boundary drift", async () => {
  for (const mutate of [
    async (fixture: Awaited<ReturnType<typeof makeCache>>) =>
      chmod(join(fixture.artifactRoot, ".cogs-stage2-completion-artifacts-v1"), 0o644),
    async (fixture: Awaited<ReturnType<typeof makeCache>>) => chmod(fixture.cache, 0o755),
    async (fixture: Awaited<ReturnType<typeof makeCache>>) => {
      const sentinel = join(fixture.artifactRoot, ".cogs-stage2-completion-artifacts-v1");
      await rm(sentinel);
      await symlink(fixture.file, sentinel);
    },
    async (fixture: Awaited<ReturnType<typeof makeCache>>) => {
      const real = `${fixture.state}-real`;
      await rename(fixture.state, real);
      await symlink(real, fixture.state);
    },
    async (fixture: Awaited<ReturnType<typeof makeCache>>) => {
      const real = `${fixture.completion}-real`;
      await rename(fixture.completion, real);
      await symlink(real, fixture.completion);
    },
  ]) {
    const dir = await mkdtemp(join(tmpdir(), "cogs-stage2-boundary-"));
    try {
      const fixture = await makeCache(dir);
      await mutate(fixture);
      assert.notEqual(runPython("cache", fixture.artifactRoot, fixture.entries).status, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

test("artifact verifier has fixed read-only CLI and no network, environment, deletion, or dependency seam", async () => {
  const text = await readFile(script, "utf8");
  assert.match(text, /argv == \["verify-contract"\]/u);
  assert.match(text, /argv == \["verify-cache"\]/u);
  assert.doesNotMatch(text, /["']fetch["']|urllib\.request|\bsocket\b|requests|subprocess|curl|wget/u);
  assert.doesNotMatch(text, /os\.environ|os\.getenv|putenv|unlink|rmtree|\.write_|open\([^\n]*["']w/u);
  assert.doesNotMatch(text, /\b(?:boto3?|aws|tofu|terraform|ctr)\b|["']docker["']|eval|shell=True/u);
  const imports = [...text.matchAll(/^(?:from\s+(\S+)|import\s+(\S+))/gmu)].map((match) => match[1] ?? match[2]);
  assert.deepEqual(imports, ["hashlib", "json", "os", "re", "stat", "sys", "pathlib", "urllib.parse"]);
  assert.notEqual(spawnSync("python3", [script, "verify-cache", "/tmp/hostile"]).status, 0);
  assert.notEqual(spawnSync("python3", [script, "fetch"]).status, 0);
});

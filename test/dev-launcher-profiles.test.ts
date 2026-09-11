import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { access, lstat, mkdir, mkdtemp, readdir, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { promisify } from "node:util";
import { normalizeDriverResult } from "../dev/launcher/contract.ts";
import { createProfileAdapter, descriptor, driverPath } from "../dev/launcher/profiles.ts";
import type { RunnerSeams } from "../dev/launcher/runner.ts";
import { resolveLauncherState } from "../dev/launcher/state.ts";

const sourceRevision = "1".repeat(40);
const generation = "a".repeat(32);
const execFileAsync = promisify(execFile);

function fakeSeams(output: string, code = 0, calls: unknown[] = [], truncated?: "stdout" | "stderr"): RunnerSeams {
  const value = JSON.parse(output);
  output = `${JSON.stringify({ ...value, generation, ...(value.status === "ready" ? { command: "verify" } : {}) })}\n`;
  return Object.freeze({
    spawn: Object.freeze(((executable: string, args: readonly string[], options: unknown) => {
      calls.push({ executable, args, options });
      const child = new EventEmitter() as never as EventEmitter & {
        pid: number;
        stdout: PassThrough;
        stderr: PassThrough;
      };
      child.pid = 12345;
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      queueMicrotask(() => {
        child.stdout.end(output);
        child.stderr.end("");
        if (truncated) child[truncated].emit("data", {}); // dropped chunk, exact valid stdout remains
        child.emit("close", code, null);
      });
      return child;
    }) as never),
    setTimer: Object.freeze((ms: number, cb: () => void) => setTimeout(cb, ms)),
    clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    kill: Object.freeze(() => true),
    identity: Object.freeze((pid: number) => String(pid)),
  });
}

async function state() {
  const root = join(process.cwd(), ".cogs-dev", "launcher");
  const name = `p${Math.random().toString(16).slice(2)}`;
  return { root, state: await resolveLauncherState({ root, name, sourceRevision }) };
}

async function cleanup(launcherState: Awaited<ReturnType<typeof resolveLauncherState>>) {
  await rm(launcherState.dir, { recursive: true, force: true });
  await rm(launcherState.lockDir, { recursive: true, force: true });
  await rm(launcherState.driverStateDir, { recursive: true, force: true });
}

test("profile adapters build exact driver argv and fixed non-secret environment", async () => {
  const { state: launcherState } = await state();
  const calls: unknown[] = [];
  try {
    const adapter = createProfileAdapter(
      "insecure-container",
      fakeSeams(
        '{"version":"cogs.dev-driver/v1alpha1","profile":"insecure-container","authority":"functional-only","command":"create","result":"pass"}\n',
        0,
        calls,
      ),
    );
    const result = await adapter.create(launcherState, generation);
    assert.equal(result.profile, "insecure-container");
    assert.equal(result.authority, "functional-only");
    assert.equal(calls.length, 1);
    const call = calls[0] as {
      executable: string;
      args: string[];
      options: { shell: boolean; env: Record<string, string> };
    };
    assert.equal(call.executable, driverPath("insecure-container"));
    assert.deepEqual(call.args, ["create"]);
    assert.equal(call.options.shell, false);
    assert.equal(call.options.env.COGS_INSECURE_STATE_DIR, launcherState.driverStateDir);
    assert.equal(call.options.env.COGS_INSECURE_GENERATION, generation);
    assert.equal(result.generation, generation);
    assert.equal(call.options.env.SECRET_TOKEN, undefined);
  } finally {
    await cleanup(launcherState);
  }
});

test("profiles normalize linux authority and reject hostile output/profile mismatch", async () => {
  const { state: launcherState } = await state();
  try {
    const linux = createProfileAdapter(
      "linux-kvm",
      fakeSeams(
        `{"status":"ready","profile":"linux-kvm","guest_root":true,"kvm_enabled":true,"distinct_boot_ids":true,"guest_kernel":"6.12.95+deb13-amd64","guest_image_sha512":"${"a".repeat(128)}","host_ip":"192.0.2.1","guest_ip":"192.0.2.2","proxy_port":18080}\n`,
      ),
    );
    assert.equal((await linux.verify(launcherState, generation)).authority, "authoritative-local");
    const hostile = createProfileAdapter("linux-kvm", fakeSeams('{"status":"ready","profile":"insecure-container"}\n'));
    await assert.rejects(() => hostile.verify(launcherState, generation));
  } finally {
    await cleanup(launcherState);
  }
});

test("driver receipts require exact full response, operation and independent nonce", () => {
  const receipt = {
    version: "cogs.dev-driver/v1alpha1",
    profile: "insecure-container",
    authority: "functional-only",
    command: "create",
    result: "pass",
    generation,
  };
  const text = `${JSON.stringify(receipt)}\n`;
  assert.equal(normalizeDriverResult(text, "insecure-container", "create", generation).generation, generation);
  for (const bad of [
    text.trimEnd(),
    `log\n${text}`,
    `${text}${text}`,
    `${text}\n`,
    text.replace(/\n$/, "\r\n"),
    text.replace('"generation":', `"generation":"${generation}","generation":`),
    `${JSON.stringify({ ...receipt, generation: "b".repeat(32) })}\n`,
    `${JSON.stringify({ ...receipt, extra: true })}\n`,
    `${JSON.stringify({ ...receipt, command: "reset" })}\n`,
  ]) {
    assert.throws(() => normalizeDriverResult(bad, "insecure-container", "create", generation));
  }
  assert.throws(() => normalizeDriverResult(text, "insecure-container", "create", ""));
});

test("profiles reject linux generic pass schema before core", () => {
  assert.throws(() =>
    normalizeDriverResult(
      '{"version":"cogs.dev-driver/v1alpha1","profile":"linux-kvm","authority":"authoritative-local","command":"verify","result":"pass"}\n',
      "linux-kvm",
      "verify",
      generation,
    ),
  );
});

test("profiles reject insecure destroyed status schema", () => {
  assert.throws(() =>
    normalizeDriverResult(
      '{"status":"destroyed","profile":"insecure-container"}\n',
      "insecure-container",
      "destroy",
      generation,
    ),
  );
});

test("profiles reject runner cleanup uncertainty even when status is ok", async () => {
  const { state: launcherState } = await state();
  try {
    const output =
      '{"version":"cogs.dev-driver/v1alpha1","profile":"insecure-container","authority":"functional-only","command":"create","result":"pass"}\n';
    const uncertainSeams: RunnerSeams = Object.freeze({
      ...fakeSeams(output),
      clearTimer: Object.freeze(() => {
        throw new Error("SECRET clear");
      }),
    });
    const adapter = createProfileAdapter("insecure-container", uncertainSeams);
    await assert.rejects(() => adapter.create(launcherState, generation), /operation failed/);
  } finally {
    await cleanup(launcherState);
  }
});

test("profiles reject either truncation flag with otherwise exact successful receipts", async () => {
  const { state: launcherState } = await state();
  try {
    for (const stream of ["stdout", "stderr"] as const) {
      const adapter = createProfileAdapter(
        "insecure-container",
        fakeSeams(
          '{"version":"cogs.dev-driver/v1alpha1","profile":"insecure-container","authority":"functional-only","command":"create","result":"pass"}\n',
          0,
          [],
          stream,
        ),
      );
      await assert.rejects(() => adapter.create(launcherState, generation), /operation failed/);
    }
  } finally {
    await cleanup(launcherState);
  }
});

test("profiles reject action mismatch and do not accept create output for reset", async () => {
  const { state: launcherState } = await state();
  try {
    const bad = createProfileAdapter(
      "insecure-container",
      fakeSeams(
        '{"version":"cogs.dev-driver/v1alpha1","profile":"insecure-container","authority":"functional-only","command":"create","result":"pass"}\n',
      ),
    );
    await assert.rejects(() => bad.reset(launcherState, generation));
  } finally {
    await cleanup(launcherState);
  }
});

test("macos-vm fixed absent driver fails prerequisite with no fallback", async () => {
  const { state: launcherState } = await state();
  try {
    const adapter = createProfileAdapter("macos-vm", fakeSeams('{"status":"ready","profile":"macos-vm"}\n'));
    await assert.rejects(() => adapter.verify(launcherState, generation), /prerequisite/);
  } finally {
    await cleanup(launcherState);
  }
});

test("real profile descriptor uses driver-compatible direct .cogs-dev state and cache", async () => {
  const root = join(process.cwd(), ".cogs-dev", "launcher");
  const launcherState = await resolveLauncherState({
    root,
    name: `realpaths${Math.random().toString(16).slice(2)}`,
    sourceRevision,
  });
  try {
    assert.equal((await lstat(join(process.cwd(), ".cogs-dev"))).mode & 0o777, 0o700);
    assert.equal((await lstat(root)).mode & 0o777, 0o700);
    const linux = descriptor("linux-kvm", driverPath("linux-kvm"), launcherState, "create", generation);
    assert.equal(linux.env.COGS_KVM_GENERATION, generation);
    assert.equal(linux.timeoutMs, 900_000);
    assert.equal(linux.killGraceMs, 120_000);
    assert.equal(linux.env.COGS_KVM_STATE_DIR, join(process.cwd(), ".cogs-dev", launcherState.driverStateName));
    assert.equal(linux.env.COGS_KVM_CACHE_DIR, join(process.cwd(), ".cogs-dev", "cache"));
    const insecure = descriptor(
      "insecure-container",
      driverPath("insecure-container"),
      launcherState,
      "create",
      generation,
    );
    assert.equal(insecure.env.COGS_INSECURE_STATE_DIR, join(process.cwd(), ".cogs-dev", launcherState.driverStateName));
  } finally {
    await cleanup(launcherState);
  }
});

test("profile drivers use exact launcher-compatible local controls", async () => {
  const insecureEntrypoint = await readFile(join(process.cwd(), "dev/insecure-sandbox/entrypoint.sh"), "utf8");
  const insecure = await readFile(join(process.cwd(), "dev/insecure-sandbox/driver.sh"), "utf8");
  assert(!/\bnpx\b|\bnpm\b/.test(insecure));
  assert.match(insecure, /tsx_bin="\$repo\/node_modules\/\.bin\/tsx"/);
  assert.match(insecure, /tsx_real=\$\(realpath "\$tsx_bin"\)/);
  assert.match(insecure, /"\$tsx_bin" "\$repo\/dev\/insecure-sandbox\/ssh-adapter-smoke\.ts"/);
  for (const flag of [
    "--read-only",
    "--tmpfs /run:rw,nosuid,nodev,noexec,size=32m,mode=0700",
    "--tmpfs /tmp:rw,nosuid,nodev,size=256m",
    "--tmpfs /shared:rw,nosuid,nodev,noexec,size=8m,mode=0700",
    "--tmpfs /user:rw,nosuid,nodev,noexec,size=8m,mode=0700",
  ])
    assert(insecure.includes(flag));
  for (const text of [insecureEntrypoint, insecure]) {
    assert.match(text, /\/shared \/user/);
    assert.match(text, /\/shared\/skills \/user\/skills/);
    assert.match(text, /realpath -e "\$skill_parent"/);
    assert.match(text, /realpath -e "\$skill_root"/);
    assert.match(text, /0:0:700:directory/);
  }

  const kvm = await readFile(join(process.cwd(), "dev/linux-kvm/driver.sh"), "utf8");
  assert.match(kvm, /read -r host_key_type host_key_data ignored/);
  assert.match(kvm, /printf '%s %s %s\\n' "\$guest_ip" "\$host_key_type" "\$host_key_data"/);
  assert.match(kvm, /\/shared\/skills, \/user\/skills/);
  assert.match(kvm, /realpath -e "\\\$skill_root"/);
  assert.match(kvm, /0:0:700:directory/);
  assert(!kvm.includes('"$(<"$state/control/host_ed25519_key.pub")"'));
});

test("launcher smoke scripts quote driver paths and document aggregate failures", async () => {
  const kvmSmoke = await readFile(join(process.cwd(), "dev/linux-kvm/ci-smoke.sh"), "utf8");
  assert.doesNotMatch(kvmSmoke, /\$driver ssh/u);
  assert.doesNotMatch(kvmSmoke, /\$\(\$driver ssh/u);
  assert.match(kvmSmoke, /"\$driver" probe boot-id >"\$boot_records\/first"/u);
  assert.match(kvmSmoke, /"\$driver" probe deny-public-https/u);
  assert.match(kvmSmoke, /"\$driver" probe boot-id >"\$boot_records\/second"/u);
  assert.doesNotMatch(kvmSmoke, /! "\$driver" probe|"\$driver" ssh/u);

  const insecureSmoke = await readFile(join(process.cwd(), "dev/insecure-sandbox/ci-smoke.sh"), "utf8");
  assert.match(insecureSmoke, /set -uo pipefail/u);
  assert.match(insecureSmoke, /Keep -e disabled: this smoke accumulates guarded step failures/u);
});

test("insecure driver rejects non-root before acquisition or Docker effects", async () => {
  const source = await readFile("dev/insecure-sandbox/driver.sh", "utf8");
  const temp = await mkdtemp(join(tmpdir(), "insecure-nonroot-"));
  try {
    for (const operation of ["create", "verify", "reset", "destroy"]) {
      const result = spawnSync("/bin/bash", ["-c", source, "driver", operation], {
        input: "",
        encoding: "utf8",
        timeout: 3000,
        ...(process.geteuid?.() === 0 ? { uid: 65534, gid: 65534 } : {}),
        env: {
          PATH: "",
          COGS_INSECURE_STATE_DIR: join(temp, "state"),
          COGS_INSECURE_GENERATION: generation,
          COGS_INSECURE_ORIGINAL_REVISION: sourceRevision,
        },
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, "insecure-container requires root-held private custody\n");
      assert.deepEqual(await readdir(temp), []);
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("insecure driver isolates docker tool state outside launcher controls", {
  skip: process.geteuid?.() !== 0,
}, async () => {
  const temp = await mkdtemp(join(tmpdir(), "cogs-insecure-docker-"));
  const stateName = `fake-docker-${Math.random().toString(16).slice(2)}`;
  const stateDir = join(process.cwd(), ".cogs-dev", stateName);
  const hostileState = join(process.cwd(), ".cogs-dev", `${stateName}-hostile`);
  const launcherControl = join(temp, "launcher-control");
  const bin = join(temp, "bin");
  const log = join(temp, "docker.log");
  await rm(stateDir, { recursive: true, force: true });
  await rm(hostileState, { recursive: true, force: true });
  await mkdir(join(launcherControl, "sandbox"), { recursive: true, mode: 0o700 });
  await mkdir(bin, { mode: 0o700 });
  await writeFile(
    join(bin, "docker"),
    `#!/usr/bin/env bash
set -euo pipefail
printf 'home=%s\\nconfig=%s\\nbuildx=%s\\nargs=%s\\n' "\${HOME:-}" "\${DOCKER_CONFIG:-}" "\${BUILDX_CONFIG:-}" "$*" >> ${JSON.stringify(log)}
mkdir -p "\${HOME:?}" "\${DOCKER_CONFIG:?}" "\${BUILDX_CONFIG:?}"
touch "$HOME/home-write" "$DOCKER_CONFIG/config-write" "$BUILDX_CONFIG/buildx-write"
if [[ "$1 $2" == 'container ls' || "$1 $2" == 'volume ls' ]]; then exit 0; fi
if [[ "$1" == build ]]; then
  if compgen -G ${JSON.stringify(`${stateDir}/input/ssh_*`)} >/dev/null; then printf 'keys-present\\n' >> ${JSON.stringify(log)}; fi
  exit 37
fi
exit 38
`,
    { mode: 0o700 },
  );
  try {
    await assert.rejects(() =>
      execFileAsync("bash", ["dev/insecure-sandbox/driver.sh", "create"], {
        cwd: process.cwd(),
        timeout: 60_000,
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH ?? ""}`,
          HOME: launcherControl,
          COGS_INSECURE_STATE_DIR: stateDir,
          COGS_INSECURE_GENERATION: generation,
          COGS_SOURCE_REVISION: sourceRevision,
          COGS_INSECURE_IMAGE: "cogs-insecure-fake:dev",
        },
      }),
    );
    const text = await readFile(log, "utf8");
    assert(text.includes(`home=${stateDir}.lock/docker-tool/home\n`));
    assert(text.includes(`config=${stateDir}.lock/docker-tool/config\n`));
    assert(text.includes(`buildx=${stateDir}.lock/docker-tool/buildx\n`));
    assert.doesNotMatch(text, /keys-present|args=container rm|args=volume rm/u);
    assert.match(await readFile(join(stateDir, "intents"), "utf8"), /cleanup-required/);
    await access(`${stateDir}.lock`); // tool/lock retirement uncertainty is retained
    assert.deepEqual((await readFile(join(process.cwd(), ".dockerignore"), "utf8")).split(/\n/u).filter(Boolean), [
      "**",
      "!.dockerignore",
      "!LICENSE",
      "!package.json",
      "!package-lock.json",
      "!tsconfig.json",
      "!tsconfig.build.json",
      "!src/",
      "!src/**",
      "!schemas/",
      "!schemas/integration-v1alpha1.json",
      "!schemas/launch-v1alpha1.json",
      "!schemas/runtime-v1alpha1.json",
      "!third_party/",
      "!third_party/envoy-ext-authz-v1.38.3/",
      "!third_party/envoy-ext-authz-v1.38.3/ext_authz.descriptor.pb",
      "!third_party/envoy-ext-authz-v1.38.3/manifest.json",
      "!third_party/envoy-ext-authz-v1.38.3/LICENSES/",
      "!third_party/envoy-ext-authz-v1.38.3/LICENSES/**",
      "!images/",
      "!images/worker/",
      "!images/worker/Dockerfile",
      "!images/sandbox/",
      "!images/sandbox/Dockerfile",
      "!images/sandbox/entrypoint.sh",
      "!images/sandbox/capture-inputs.py",
      "!images/sandbox/sshd_config",
      "!dev/",
      "!dev/insecure-sandbox/",
      "!dev/insecure-sandbox/Dockerfile",
      "!dev/insecure-sandbox/entrypoint.sh",
      "!dev/insecure-sandbox/sshd_config",
    ]);
    assert.deepEqual(await readdir(launcherControl), ["sandbox"]);
    const hostileId = createHash("sha256").update(hostileState).digest("hex").slice(0, 12);
    await mkdir(join(hostileState, "control"), { recursive: true, mode: 0o700 });
    await writeFile(join(hostileState, ".cogs-insecure-owner"), `${hostileId}\n`, { mode: 0o600 });
    await writeFile(join(hostileState, "container"), `cogs-insecure-${hostileId}\n`, { mode: 0o600 });
    await writeFile(join(hostileState, "volume"), `cogs-insecure-workspace-${hostileId}\n`, { mode: 0o600 });
    await writeFile(join(hostileState, "control", "client_ed25519_key"), "k\n", { mode: 0o600 });
    await writeFile(join(hostileState, "control", "client_ed25519_key.pub"), "p\n", { mode: 0o600 });
    await symlink("/tmp", join(hostileState, "docker-tool"));
    await assert.rejects(() =>
      execFileAsync("bash", ["dev/insecure-sandbox/driver.sh", "destroy"], {
        cwd: process.cwd(),
        timeout: 60_000,
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH ?? ""}`,
          COGS_INSECURE_STATE_DIR: hostileState,
          COGS_INSECURE_GENERATION: generation,
          COGS_SOURCE_REVISION: sourceRevision,
        },
      }),
    );
    assert.deepEqual((await readdir(join(hostileState, "control"))).sort(), [
      "client_ed25519_key",
      "client_ed25519_key.pub",
    ]);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
    await rm(hostileState, { recursive: true, force: true });
    await rm(`${stateDir}.lock`, { recursive: true, force: true });
    await rm(`${hostileState}.lock`, { recursive: true, force: true });
    await rm(temp, { recursive: true, force: true });
  }
});

// Portable syscall model of a root-owned parent; real unprivileged retirement must refuse.
const rootCustodyModel = `
import os,types
from unittest.mock import patch
def root_stat(fn):
 def call(*a,**kw):
  s=fn(*a,**kw); return types.SimpleNamespace(**{k:0 if k=='st_uid' else getattr(s,k) for k in dir(s) if k.startswith('st_')})
 return call
`;

test("insecure Docker tool metadata is inventoried and only exact custody is retired", async () => {
  const temp = await mkdtemp(join(tmpdir(), "insecure-tool-custody-"));
  const source = await readFile("dev/insecure-sandbox/driver.sh", "utf8");
  const functions = ["docker_tool_custody", "bounded_docker", "release_lock"]
    .map((name) => shellFunction(source, name))
    .join("\n");
  const result = spawnSync(
    "bash",
    [
      "-c",
      `set -euo pipefail; umask 077
${functions}
python3() {
  if [[ "$2" != - ]]; then command python3 "$@"; return; fi
  command python3 -I -c ${JSON.stringify(
    `exec(${JSON.stringify(`${rootCustodyModel}
with patch.object(os,'getuid',return_value=0),patch.object(os,'geteuid',return_value=0),patch.object(os,'fstat',side_effect=root_stat(os.fstat)),patch.object(os,'stat',side_effect=root_stat(os.stat)):
 exec(__import__('sys').stdin.read())`)})`,
  )} "\${@:3}"
}
prepare() {
  lock="$1"; lock_owner=owner; lock_held=true
  mkdir -m 700 "$lock" "$lock/docker-tool" "$lock/docker-tool/home" "$lock/docker-tool/config" "$lock/docker-tool/buildx"
  printf 'owner\\n' > "$lock/owner"; chmod 600 "$lock/owner"
  lock_identity=$(python3 -I -c 'import os,sys; s=os.stat(sys.argv[1]); print(f"{s.st_dev}:{s.st_ino}")' "$lock")
  docker_tool_custody capture
}
prepare ${JSON.stringify(join(temp, "success.lock"))}
bounded() { shift; "$@"; }
fake_docker() {
  mkdir -m 700 "$lock/docker-tool/buildx/instances"
  printf '{"Name":"owned"}\\n' > "$lock/docker-tool/buildx/instances/owned"; chmod 644 "$lock/docker-tool/buildx/instances/owned"
  printf config > "$lock/docker-tool/config/config.json"; chmod 600 "$lock/docker-tool/config/config.json"
  printf home > "$lock/docker-tool/home/metadata"; chmod 600 "$lock/docker-tool/home/metadata"
}
docker_command=(fake_docker)
bounded_docker 1s build
release_lock
[[ ! -e "$lock" ]]
prepare ${JSON.stringify(join(temp, "failed.lock"))}
failed_docker() { printf partial > "$lock/docker-tool/buildx/partial"; return 7; }
docker_command=(failed_docker)
if bounded_docker 1s build; then exit 33; fi
failed_docker() { echo executed > "$lock/forbidden"; }
if bounded_docker 1s inspect; then exit 34; fi
if release_lock; then exit 35; fi
[[ -f "$lock/owner" && -f "$lock/docker-tool/buildx/partial" && ! -e "$lock/forbidden" ]]
prepare ${JSON.stringify(join(temp, "replaced.lock"))}
mv "$lock/docker-tool/buildx" ${JSON.stringify(join(temp, "original-buildx"))}
mkdir -m 700 "$lock/docker-tool/buildx"
if docker_tool_custody capture; then exit 36; fi
if release_lock; then exit 37; fi
[[ -d "$lock/docker-tool/buildx" && -d ${JSON.stringify(join(temp, "original-buildx"))} ]]
prepare ${JSON.stringify(join(temp, "unknown.lock"))}
printf owned > "$lock/docker-tool/buildx/owned"; chmod 600 "$lock/docker-tool/buildx/owned"
docker_tool_custody capture
printf hostile > "$lock/docker-tool/buildx/unknown"; chmod 600 "$lock/docker-tool/buildx/unknown"
if release_lock; then exit 31; fi
[[ -f "$lock/docker-tool/buildx/owned" && -f "$lock/docker-tool/buildx/unknown" ]]
prepare ${JSON.stringify(join(temp, "symlink.lock"))}
printf owned > "$lock/docker-tool/buildx/owned"; chmod 600 "$lock/docker-tool/buildx/owned"
docker_tool_custody capture
rm "$lock/docker-tool/buildx/owned"
printf retained > ${JSON.stringify(join(temp, "retained"))}
ln -s ${JSON.stringify(join(temp, "retained"))} "$lock/docker-tool/buildx/owned"
if release_lock; then exit 32; fi
[[ -L "$lock/docker-tool/buildx/owned" ]]
[[ "$(cat ${JSON.stringify(join(temp, "retained"))})" = retained ]]`,
    ],
    { encoding: "utf8", timeout: 10_000 },
  );
  try {
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.error, undefined);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("Buildx final unlink/rmdir and rename replacements preserve foreign custody", async () => {
  const source = await readFile("dev/insecure-sandbox/driver.sh", "utf8");
  const program = shellFunction(source, "docker_tool_custody").split("<<'PY'\n")[1]?.split("\nPY")[0];
  assert(program);
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-c",
      String.raw`
import json,sys,tempfile,pathlib
${rootCustodyModel}
program=json.load(sys.stdin)
real_stat,real_rename,real_unlink,real_rmdir=os.stat,os.rename,os.unlink,os.rmdir
for race in ('none','unprivileged','rename-file','rename-dir','unlink','rmdir','unlink-manifest','unlink-owner','rmdir-tool','rmdir-lock','manifest','owner','lock'):
 with tempfile.TemporaryDirectory() as tmp:
  root=pathlib.Path(tmp); lock=root/'lock'; lock.mkdir(mode=0o700)
  for name in ('docker-tool','docker-tool/home','docker-tool/config','docker-tool/buildx','docker-tool/buildx/instances'): (lock/name).mkdir(mode=0o700)
  (lock/'owner').write_text('owner\n'); (lock/'owner').chmod(0o600)
  target=lock/'docker-tool/buildx/instances/owned'; target.write_text('owned'); target.chmod(0o600)
  s=lock.stat(); identity=f'{s.st_dev}:{s.st_ino}'
  def run(action):
   with patch.object(sys,'argv',['custody',str(lock),identity,'owner',action]): exec(program,{})
  fired=[]; retained=[]
  def replace(fd,name,directory):
   saved='saved-'+str(len(retained)); real_rename(name,str(root/saved),src_dir_fd=fd)
   if directory: os.mkdir(name,0o700,dir_fd=fd)
   else:
    h=os.open(name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=fd);os.write(h,b'FOREIGN');os.close(h)
   retained.append((os.dup(fd),name,real_stat(name,dir_fd=fd,follow_symlinks=False).st_ino,directory))
  def rename(name,destination,*,src_dir_fd,dst_dir_fd):
   match=(race=='rename-file' and name=='owned') or (race=='rename-dir' and name=='instances') or (race==name and name in ('owner','docker-tool.inventory','lock')) or (race=='manifest' and name=='docker-tool.inventory')
   if match and not fired: fired.append(True);replace(src_dir_fd,name,name in ('instances','lock'))
   return real_rename(name,destination,src_dir_fd=src_dir_fd,dst_dir_fd=dst_dir_fd)
  def final(name,*,dir_fd,directory):
   # Race on the *old* validated parent at the final deletion syscall. The actual
   # syscall must only touch the moved inode in the private deletion namespace.
   key='rmdir' if directory else 'unlink'
   if race.startswith(key) and not fired:
    moved=real_stat(name,dir_fd=dir_fd,follow_symlinks=False)
    old=next(((fd,n,d) for fd,n,d,ino in moves if ino==moved.st_ino),None)
    target={'unlink':'owned','rmdir':'instances','unlink-manifest':'docker-tool.inventory','unlink-owner':'owner','rmdir-tool':'docker-tool','rmdir-lock':'lock'}[race]
    if old and old[1]==target:
     fd,n,d=old;fired.append(True)
     if d: os.mkdir(n,0o700,dir_fd=fd)
     else:
      h=os.open(n,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=fd);os.write(h,b'FOREIGN');os.close(h)
     retained.append((os.dup(fd),n,real_stat(n,dir_fd=fd,follow_symlinks=False).st_ino,d))
   return (real_rmdir if directory else real_unlink)(name,dir_fd=dir_fd)
  moves=[]
  def move(name,destination,*,src_dir_fd,dst_dir_fd):
   s=real_stat(name,dir_fd=src_dir_fd,follow_symlinks=False);moves.append((os.dup(src_dir_fd),name,__import__('stat').S_ISDIR(s.st_mode),s.st_ino))
   return rename(name,destination,src_dir_fd=src_dir_fd,dst_dir_fd=dst_dir_fd)
  with patch.object(os,'getuid',return_value=0),patch.object(os,'geteuid',return_value=1 if race=='unprivileged' else 0),patch.object(os,'fstat',side_effect=root_stat(os.fstat)),patch.object(os,'stat',side_effect=root_stat(os.stat)):
   run('capture')
   try:
    with patch.object(os,'rename',side_effect=move),patch.object(os,'unlink',side_effect=lambda n,*,dir_fd:final(n,dir_fd=dir_fd,directory=False)),patch.object(os,'rmdir',side_effect=lambda n,*,dir_fd:final(n,dir_fd=dir_fd,directory=True)): run('remove')
   except SystemExit: assert race!='none'
   else: assert race=='none',race
  if race=='none': assert list(root.iterdir())==[]
  elif race=='unprivileged': assert target.read_text()=='owned' and len(list(root.iterdir()))==1
  else:
   assert fired and retained,race
   # Rename races retain the foreign inode in quarantine, not necessarily its old name.
   inodes={real_stat(p).st_ino for p in root.rglob('*') if p.is_file() or p.is_dir()}
   for fd,name,ino,d in retained:
    assert ino in inodes,(race,ino)
    if not d: assert any(p.is_file() and real_stat(p).st_ino==ino and p.read_bytes()==b'FOREIGN' for p in root.rglob('*'))
    os.close(fd)
  for fd,*_ in moves: os.close(fd)
`,
    ],
    { input: JSON.stringify(program), encoding: "utf8", timeout: 10000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("insecure authority retirement quarantines final-boundary replacements without adoption", async () => {
  const source = await readFile("dev/insecure-sandbox/driver.sh", "utf8");
  const program = shellFunction(source, "file_custody").split("<<'PY'\n")[1]?.split("\nPY")[0];
  assert(program);
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-c",
      String.raw`
import json,sys,tempfile,pathlib,stat
${rootCustodyModel}
spec=json.load(sys.stdin); program=spec['program']; preflight=spec['preflight']
real_stat,real_rename,real_unlink,real_rmdir=os.stat,os.rename,os.unlink,os.rmdir
files=['.cogs-insecure-owner','authority','intents','inventory','container','volume','port','known_hosts',
 'input/ssh_host_ed25519_key','input/ssh_host_ed25519_key.pub','input/client_ed25519_key.pub','input/egress-ca.crt',
 'control/client_ed25519_key','control/client_ed25519_key.pub']
for boundary,target in [('none',''),('unprivileged','')]+[(b,n) for b in ('rename','delete') for n in files+['files.owner','input','control','state']]:
 with tempfile.TemporaryDirectory() as tmp:
  parent=pathlib.Path(tmp); root=parent/'state'; root.mkdir(mode=0o700)
  for name in ('input','control'): (root/name).mkdir(mode=0o700)
  for name in files: (root/name).write_text('owned\n'); (root/name).chmod(0o600)
  s=root.stat(); identity=f'{s.st_dev}:{s.st_ino}'
  moves={}; fired=[]; retained=[]
  def run(action):
   # Production runs each helper in its own process. Reclaim its descriptors on
   # modeled SystemExit too, rather than depending on the host's fd limit.
   opened=set(); real_open,real_dup=os.open,os.dup
   def track(fn,*a,**kw):
    fd=fn(*a,**kw); opened.add(fd); return fd
   try:
    with patch.object(sys,'argv',['custody',str(root),action,identity]),patch.object(os,'open',side_effect=lambda *a,**kw:track(real_open,*a,**kw)),patch.object(os,'dup',side_effect=lambda fd:track(real_dup,fd)): exec(program,{})
   finally:
    for fd in opened:
     try: os.close(fd)
     except OSError: pass
  def replace(fd,name,directory,save):
   if save: real_rename(name,str(parent/'saved'),src_dir_fd=fd)
   if directory: os.mkdir(name,0o700,dir_fd=fd)
   else:
    h=os.open(name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=fd);os.write(h,b'FOREIGN');os.close(h)
   retained.append(real_stat(name,dir_fd=fd,follow_symlinks=False).st_ino);fired.append(True)
  def move(name,destination,*,src_dir_fd,dst_dir_fd):
   s=real_stat(name,dir_fd=src_dir_fd,follow_symlinks=False); directory=stat.S_ISDIR(s.st_mode)
   # Match nested keys by the retained directory inode, not ambiguous basenames.
   expected=root/target if target!='state' else root
   matches=name==expected.name and real_stat(expected.parent).st_ino==os.fstat(src_dir_fd).st_ino
   if boundary=='rename' and matches and not fired: replace(src_dir_fd,name,directory,True)
   moves[destination]=(os.dup(src_dir_fd),name,directory,matches)
   return real_rename(name,destination,src_dir_fd=src_dir_fd,dst_dir_fd=dst_dir_fd)
  def final(name,*,dir_fd,directory):
   old=moves.get(name)
   if boundary=='delete' and old and old[3] and not fired: replace(old[0],old[1],directory,False)
   return (real_rmdir if directory else real_unlink)(name,dir_fd=dir_fd)
  with patch.object(os,'getuid',return_value=0),patch.object(os,'geteuid',return_value=1 if boundary=='unprivileged' else 0),patch.object(os,'fstat',side_effect=root_stat(os.fstat)),patch.object(os,'stat',side_effect=root_stat(os.stat)):
   run('capture')
   try:
    with patch.object(os,'rename',side_effect=move),patch.object(os,'unlink',side_effect=lambda n,*,dir_fd:final(n,dir_fd=dir_fd,directory=False)),patch.object(os,'rmdir',side_effect=lambda n,*,dir_fd:final(n,dir_fd=dir_fd,directory=True)): run('remove')
   except SystemExit: assert boundary!='none',(boundary,target)
   else: assert boundary=='none',(boundary,target)
   if boundary not in ('none','unprivileged'):
    try: run('check')
    except (SystemExit,OSError): pass
    else: raise AssertionError('uncertain retirement became usable')
  if boundary=='none': assert list(parent.iterdir())==[]
  elif boundary=='unprivileged': assert (root/'authority').read_text()=='owned\n' and len(list(parent.iterdir()))==1
  else:
   assert fired and retained,(boundary,target)
   paths=list(parent.rglob('*'))
   for ino in retained:
    p=next(p for p in paths if real_stat(p).st_ino==ino)
    if p.is_file(): assert p.read_bytes()==b'FOREIGN'
   assert any(p.name.startswith('.cogs-retire-state-') for p in parent.iterdir())
   denied=__import__('subprocess').run(['/bin/bash','-c','state_root=$1; state_name=state;'+preflight+'\necho FORBIDDEN','preflight',tmp],capture_output=True)
   assert denied.returncode==1 and not denied.stdout and b'custody is uncertain' in denied.stderr
`,
    ],
    {
      input: JSON.stringify({
        program,
        preflight: `set -e;\n${shellFunction(source, "fail")}\n${source.slice(source.indexOf("# A failed retirement"), source.indexOf("trap on_error ERR"))}`,
      }),
      encoding: "utf8",
      timeout: 10000,
    },
  );
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
});

test("insecure expected lifecycle files reject FIFOs without blocking", async () => {
  const temp = await mkdtemp(join(tmpdir(), "insecure-fifo-custody-"));
  const owned = join(temp, "owned");
  const lock = join(temp, "owned.lock");
  const source = await readFile("dev/insecure-sandbox/driver.sh", "utf8");
  const functions = [
    "durable_file",
    "initialize_authority",
    "validate_custody",
    "read_owned_member",
    "file_custody",
    "docker_tool_custody",
    "release_lock",
  ]
    .map((name) => shellFunction(source, name))
    .join("\n");
  const started = Date.now();
  const result = spawnSync(
    "bash",
    [
      "-c",
      `set -euo pipefail; umask 077
state=${JSON.stringify(owned)}; generation=${generation}; profile=insecure-container
original_revision=${sourceRevision}; locator=$state; authority=$state/authority
sentinel=$state/.cogs-insecure-owner; intents=$state/intents; inventory=$state/inventory
custody_identity=''; custody_bound=false
persist_new() { durable_file new "$1" "$2"; }
${functions}
initialize_authority
for journal in intents inventory; do
  saved=$(<"$state/$journal"); rm "$state/$journal"; mkfifo -m 600 "$state/$journal"
  custody_identity=''; if validate_custody; then exit 41; fi
  rm "$state/$journal"; printf '%s\\n' "$saved" > "$state/$journal"; chmod 600 "$state/$journal"
done
validate_custody
printf locator > "$state/container"; chmod 600 "$state/container"; rm "$state/container"; mkfifo -m 600 "$state/container"
if read_owned_member container; then exit 45; fi
rm "$state/container"
mkdir "$state/input" "$state/control"
for name in container volume port known_hosts input/ssh_host_ed25519_key input/ssh_host_ed25519_key.pub input/client_ed25519_key.pub input/egress-ca.crt control/client_ed25519_key control/client_ed25519_key.pub; do
  printf fixture > "$state/$name"
done
validate_custody; file_custody capture
for name in port known_hosts container volume input/ssh_host_ed25519_key control/client_ed25519_key files.owner; do
  mv "$state/$name" ${JSON.stringify(join(temp, "held"))}; mkfifo -m 600 "$state/$name"
  if file_custody check || file_custody remove; then exit 42; fi
  [[ -f "$state/authority" ]]
  rm "$state/$name"; mv ${JSON.stringify(join(temp, "held"))} "$state/$name"
done
fifo=${JSON.stringify(join(temp, "append-fifo"))}; mkfifo -m 600 "$fifo"
if durable_file append "$fifo" x; then exit 43; fi
lock=${JSON.stringify(lock)}; lock_owner=owner; lock_held=true
mkdir -m 700 "$lock" "$lock/docker-tool" "$lock/docker-tool/home" "$lock/docker-tool/config" "$lock/docker-tool/buildx"
printf 'owner\\n' > "$lock/owner"; chmod 600 "$lock/owner"
lock_identity=$(python3 -I -c 'import os,sys; s=os.stat(sys.argv[1]); print(f"{s.st_dev}:{s.st_ino}")' "$lock")
docker_tool_custody capture
rm "$lock/owner"; mkfifo -m 600 "$lock/owner"
if release_lock; then exit 44; fi
[[ -d "$lock/docker-tool" ]]`,
    ],
    { encoding: "utf8", timeout: 10_000 },
  );
  try {
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.error, undefined);
    assert(Date.now() - started < 10_000);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("insecure driver never adopts or removes pre-existing docker competitors", {
  skip: process.geteuid?.() !== 0,
}, async () => {
  const temp = await mkdtemp(join(tmpdir(), "cogs-insecure-preflight-"));
  const stateName = `fake-stale-${Math.random().toString(16).slice(2)}`;
  const stateDir = join(process.cwd(), ".cogs-dev", stateName);
  const launcherControl = join(temp, "launcher-control");
  const bin = join(temp, "bin");
  const log = join(temp, "docker.log");
  await rm(stateDir, { recursive: true, force: true });
  await rm(`${stateDir}.lock`, { recursive: true, force: true });
  await mkdir(join(launcherControl, "sandbox"), { recursive: true, mode: 0o700 });
  await mkdir(bin, { mode: 0o700 });
  await writeFile(
    join(bin, "docker"),
    `#!/usr/bin/env bash
set -euo pipefail
printf 'home=%s\\nconfig=%s\\nbuildx=%s\\nargs=%s\\n' "\${HOME:-}" "\${DOCKER_CONFIG:-}" "\${BUILDX_CONFIG:-}" "$*" >> ${JSON.stringify(log)}
mkdir -p "\${HOME:?}" "\${DOCKER_CONFIG:?}" "\${BUILDX_CONFIG:?}"
if [[ "$1 $2" == 'container ls' ]]; then printf 'stale-container\\n'; exit 0; fi
if [[ "$1 $2" == 'volume ls' ]]; then exit 0; fi
exit 38
`,
    { mode: 0o700 },
  );
  try {
    await assert.rejects(() =>
      execFileAsync("bash", ["dev/insecure-sandbox/driver.sh", "create"], {
        cwd: process.cwd(),
        timeout: 60_000,
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH ?? ""}`,
          HOME: launcherControl,
          COGS_INSECURE_STATE_DIR: stateDir,
          COGS_INSECURE_GENERATION: generation,
          COGS_SOURCE_REVISION: sourceRevision,
          COGS_INSECURE_IMAGE: "cogs-insecure-fake:dev",
        },
      }),
    );
    const text = await readFile(log, "utf8");
    assert(text.includes(`home=${stateDir}.lock/docker-tool/home\n`));
    assert(!text.includes(`home=${stateDir}/docker-tool/home\n`));
    assert.doesNotMatch(text, /args=container rm|args=volume rm|args=build/);
    assert.equal(await readFile(join(stateDir, ".cogs-insecure-owner"), "utf8"), `${generation}\n`);
    assert.deepEqual(await readdir(launcherControl), ["sandbox"]);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
    await rm(`${stateDir}.lock`, { recursive: true, force: true });
    await rm(temp, { recursive: true, force: true });
  }
});

function shellFunction(source: string, name: string): string {
  const start = source.indexOf(`${name}() {`);
  assert(start >= 0);
  const end = source.indexOf("\n}\n", start);
  assert(end > start);
  return source.slice(start, end + 3);
}

test("insecure local custody retains exact nonces, file identities, and foreign inventory", async () => {
  const temp = await mkdtemp(join(tmpdir(), "insecure-custody-"));
  const state = join(temp, "owned");
  const source = await readFile("dev/insecure-sandbox/driver.sh", "utf8");
  const functions = ["fail", "durable_file", "initialize_authority", "validate_custody", "file_custody"]
    .map((name) => shellFunction(source, name))
    .join("\n");
  const prefix = `set -euo pipefail; umask 077
state=${JSON.stringify(state)}; generation=${generation}; profile=insecure-container
original_revision=${sourceRevision}; locator=$state; authority=$state/authority
sentinel=$state/.cogs-insecure-owner; intents=$state/intents; inventory=$state/inventory
custody_identity=''; custody_bound=false
persist_new() { durable_file new "$1" "$2"; }
${functions}
`;
  const invoke = (action: string) => spawnSync("bash", ["-c", prefix + action], { encoding: "utf8", timeout: 20_000 });
  try {
    const init = invoke(`initialize_authority; validate_custody
mkdir "$state/input" "$state/control"
for name in container volume port known_hosts input/ssh_host_ed25519_key input/ssh_host_ed25519_key.pub input/client_ed25519_key.pub input/egress-ca.crt control/client_ed25519_key control/client_ed25519_key.pub; do
 printf fixture > "$state/$name"
done
file_custody capture; file_custody check`);
    assert.equal(init.status, 0, init.stderr);
    const before = await readFile(join(state, "authority"));
    assert.notEqual(invoke("initialize_authority").status, 0);
    assert.deepEqual(await readFile(join(state, "authority")), before);
    assert.notEqual(invoke(`generation=${"b".repeat(32)}; validate_custody`).status, 0);
    assert.deepEqual(await readFile(join(state, ".cogs-insecure-owner"), "utf8"), `${generation}\n`);
    await writeFile(join(state, "input", "foreign"), "competitor");
    assert.notEqual(invoke("validate_custody; file_custody remove").status, 0);
    assert.equal(await readFile(join(state, "input", "foreign"), "utf8"), "competitor");
    assert.deepEqual(await readFile(join(state, "authority")), before);
    await rm(join(state, "input", "foreign"));
    const key = join(state, "control", "client_ed25519_key");
    await rename(key, join(temp, "retained-key"));
    await writeFile(key, "fixture", { mode: 0o600 });
    assert.notEqual(invoke("validate_custody; file_custody check").status, 0);
    assert.equal(await readFile(key, "utf8"), "fixture");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("insecure partial rollback never retires dependencies after lost container response or uncertain stop", async () => {
  const source = await readFile("dev/insecure-sandbox/driver.sh", "utf8");
  const rollback = shellFunction(source, "rollback_partial");
  for (const pending of [true, false]) {
    const result = spawnSync(
      "bash",
      [
        "-c",
        `set -euo pipefail
container_pending=${pending}; container_acquired=true; volume_acquired=true; container_id=${"1".repeat(64)}; volume_name=owned
retire_exact() { echo "$1"; return 1; }
${rollback}
rollback_partial`,
      ],
      { encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, pending ? "" : "container\n");
  }
  const retire = ["fail", "exact_line", "validate_container_ownership", "retire_exact"]
    .map((name) => shellFunction(source, name))
    .join("\n");
  const stale = spawnSync(
    "bash",
    [
      "-c",
      `set -euo pipefail
custody_bound=true; container_id=${"1".repeat(64)}; container_name=owned
profile=insecure-container; state_id=locator; generation=${generation}; original_revision=${sourceRevision}; docker_command=(docker)
validate_custody() { :; }; bounded_docker() { echo foreign; }; record_inventory() { echo MUTATED; }; record_intent() { echo MUTATED; }
${retire}
retire_exact container "$container_id"`,
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(stale.status, 0);
  assert.equal(stale.stdout, "");
});

test("driver-local Docker receipts reject lost, NUL, extra LF and oversized responses before adoption", async () => {
  const source = await readFile("dev/insecure-sandbox/driver.sh", "utf8");
  const parser = shellFunction(source, "exact_line");
  for (const input of [
    `${"1".repeat(64)}\n`,
    "",
    `${"1".repeat(64)}\n\n`,
    "id\0\n",
    "id\r\n",
    `${"x".repeat(4096)}\n`,
  ]) {
    const result = spawnSync("bash", ["-c", `${parser}\nexact_line`], { input, encoding: "utf8", timeout: 5000 });
    assert.equal(result.status === 0, input === `${"1".repeat(64)}\n`);
  }
});

test("enabled insecure smoke arms only exact receipts and consumes cleanup before report failure", async () => {
  const source = await readFile("dev/insecure-sandbox/ci-smoke.sh", "utf8");
  const functions = ["run_driver", "cleanup"].map((name) => shellFunction(source, name)).join("\n");
  const temp = await mkdtemp(join(tmpdir(), "insecure-smoke-"));
  const receipt = {
    version: "cogs.dev-driver/v1alpha1",
    profile: "insecure-container",
    authority: "functional-only",
    command: "create",
    result: "pass",
    generation,
  };
  const exact = `${JSON.stringify(receipt)}\n`;
  try {
    for (const [kind, bytes, consume] of [
      ["exact", exact, false],
      ["report-failure", exact, true],
      ["lost", "", false],
      ["no-lf", exact.trimEnd(), false],
      ["duplicate", exact.replace('"generation":', `"generation":"${generation}","generation":`), false],
      ["foreign", exact.replace(generation, "b".repeat(32)), false],
      ["extra", `${exact}\n`, false],
    ] as const) {
      const log = join(temp, `${kind}.log`);
      const result = spawnSync(
        "bash",
        [
          "-c",
          `set -uo pipefail
TMPDIR=${JSON.stringify(temp)}; generation=${generation}; driver=/unused; cleanup_pending=false; receipt_file=''; tmp_report=''
bounded() { printf '%s\\n' "$3" >> ${JSON.stringify(log)}; printf '%s' "$COGS_FAKE_RESPONSE"; }
${functions}
trap cleanup EXIT
if run_driver 1s create; then cleanup_pending=true; fi
${consume ? "cleanup_pending=false; run_driver 1s destroy;" : ""}
exit 1`,
        ],
        { encoding: "utf8", timeout: 20_000, env: { ...process.env, COGS_FAKE_RESPONSE: bytes } },
      );
      assert.notEqual(result.status, 0);
      assert.equal(await readFile(log, "utf8"), kind === "exact" || consume ? "create\ndestroy\n" : "create\n");
    }
    assert.match(source, /cleanup_pending=false\n {2}if ! run_driver 2m destroy/);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("linux-kvm seed generation preserves guest skill-root checks under nounset", async () => {
  const temp = await mkdtemp(join(tmpdir(), "cogs-kvm-seed-"));
  try {
    const control = join(temp, "control");
    await writeFile(join(temp, "seed.img"), "");
    await rm(control, { recursive: true, force: true });
    await mkdir(control, { recursive: true, mode: 0o700 });
    await writeFile(
      join(control, "client_ed25519_key.pub"),
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICLIENT cogs-kvm-client\n",
    );
    await writeFile(join(control, "host_ed25519_key"), "host-private\n");
    await writeFile(join(control, "host_ed25519_key.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHOST cogs-kvm-host\n");
    const probe = `
set -euo pipefail
state=${JSON.stringify(temp)}
guest_ip=192.0.2.2
cloud-localds() { :; }
eval "$(awk '/^prepare_seed\\(\\) \\{/{flag=1} flag{print} flag && /^}/{exit}' dev/linux-kvm/driver.sh)"
prepare_seed
`;
    await execFileAsync("bash", ["-c", probe], { cwd: process.cwd(), timeout: 20_000 });
    const userData = await readFile(join(temp, "user-data"), "utf8");
    assert.match(userData, /ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICLIENT cogs-kvm-client/);
    assert.match(userData, /content: [A-Za-z0-9+/]+=*/);
    assert.match(userData, /for skill_root in \/shared\/skills \/user\/skills/);
    assert.match(userData, /test -d "\$skill_root"/);
    assert.match(userData, /test "\$\(realpath -e "\$skill_root"\)" = "\$skill_root"/);
    assert.match(userData, /test "\$\(stat -c "%u:%g:%a:%F" "\$skill_root"\)" = "0:0:700:directory"/);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("profile descriptor maps status to verify and never exposes arbitrary executable", async () => {
  const { state: launcherState } = await state();
  try {
    const item = descriptor("linux-kvm", driverPath("linux-kvm"), launcherState, "verify", generation);
    assert.equal(item.executable, driverPath("linux-kvm"));
    assert.deepEqual(item.args, ["verify"]);
    assert.equal(item.timeoutMs, 300_000);
    assert.equal(
      descriptor("linux-kvm", driverPath("linux-kvm"), launcherState, "destroy", generation).timeoutMs,
      120_000,
    );
    assert.equal(item.env.COGS_KVM_STATE_DIR, launcherState.driverStateDir);
    assert(!Object.keys(item.env).some((key) => /TOKEN|SECRET|KEY/.test(key)));
  } finally {
    await cleanup(launcherState);
  }
});

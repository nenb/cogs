import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { access, lstat, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
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
const execFileAsync = promisify(execFile);

function fakeSeams(output: string, code = 0, calls: unknown[] = []): RunnerSeams {
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
    const result = await adapter.create(launcherState);
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
    assert.equal((await linux.verify(launcherState)).authority, "authoritative-local");
    const hostile = createProfileAdapter("linux-kvm", fakeSeams('{"status":"ready","profile":"insecure-container"}\n'));
    await assert.rejects(() => hostile.verify(launcherState));
  } finally {
    await cleanup(launcherState);
  }
});

test("profiles reject linux generic pass schema before core", () => {
  assert.throws(() =>
    normalizeDriverResult(
      '{"version":"cogs.dev-driver/v1alpha1","profile":"linux-kvm","authority":"authoritative-local","command":"verify","result":"pass"}\n',
      "linux-kvm",
      "verify",
    ),
  );
});

test("profiles reject insecure destroyed status schema", () => {
  assert.throws(() =>
    normalizeDriverResult('{"status":"destroyed","profile":"insecure-container"}\n', "insecure-container", "destroy"),
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
    await assert.rejects(() => adapter.create(launcherState), /operation failed/);
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
    await assert.rejects(() => bad.reset(launcherState));
  } finally {
    await cleanup(launcherState);
  }
});

test("macos-vm fixed absent driver fails prerequisite with no fallback", async () => {
  const { state: launcherState } = await state();
  try {
    const adapter = createProfileAdapter("macos-vm", fakeSeams('{"status":"ready","profile":"macos-vm"}\n'));
    await assert.rejects(() => adapter.verify(launcherState), /prerequisite/);
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
    const linux = descriptor("linux-kvm", driverPath("linux-kvm"), launcherState, "create");
    assert.equal(linux.timeoutMs, 900_000);
    assert.equal(linux.killGraceMs, 120_000);
    assert.equal(linux.env.COGS_KVM_STATE_DIR, join(process.cwd(), ".cogs-dev", launcherState.driverStateName));
    assert.equal(linux.env.COGS_KVM_CACHE_DIR, join(process.cwd(), ".cogs-dev", "cache"));
    const insecure = descriptor("insecure-container", driverPath("insecure-container"), launcherState, "create");
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
  assert(
    insecure.includes(
      "--read-only \\\n    --tmpfs /run:rw,nosuid,nodev,noexec,size=32m,mode=0700 \\\n    --tmpfs /tmp:rw,nosuid,nodev,size=256m \\\n    --tmpfs /shared:rw,nosuid,nodev,noexec,size=8m,mode=0700 \\\n    --tmpfs /user:rw,nosuid,nodev,noexec,size=8m,mode=0700",
    ),
  );
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
  assert.match(kvmSmoke, /guest_boot=\$\("\$driver" ssh cat \/proc\/sys\/kernel\/random\/boot_id\)/u);
  assert.match(kvmSmoke, /! "\$driver" ssh 'timeout 2 bash -c "<\/dev\/tcp\/1\.1\.1\.1\/443"'/u);
  assert.match(kvmSmoke, /second_boot=\$\("\$driver" ssh cat \/proc\/sys\/kernel\/random\/boot_id\)/u);

  const insecureSmoke = await readFile(join(process.cwd(), "dev/insecure-sandbox/ci-smoke.sh"), "utf8");
  assert.match(insecureSmoke, /set -uo pipefail/u);
  assert.match(insecureSmoke, /Keep -e disabled: this smoke accumulates guarded step failures/u);
});

test("insecure driver isolates docker tool state outside launcher controls", async () => {
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
          COGS_INSECURE_IMAGE: "cogs-insecure-fake:dev",
        },
      }),
    );
    const text = await readFile(log, "utf8");
    assert(text.includes(`home=${stateDir}/docker-tool/home\n`));
    assert(text.includes(`config=${stateDir}/docker-tool/config\n`));
    assert(text.includes(`buildx=${stateDir}/docker-tool/buildx\n`));
    assert.doesNotMatch(text, /keys-present/u);
    await assert.rejects(access(stateDir));
    assert.deepEqual((await readFile(join(process.cwd(), ".dockerignore"), "utf8")).split(/\n/u).filter(Boolean), [
      ".cogs-dev/",
      ".git/",
      ".pi/",
      "node_modules/",
      "coverage/",
      "docs/security-evidence/generated/",
      "test/egress-conformance/reports/",
      "third_party/envoy-ext-authz-v1.38.3/protos/",
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
        env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, COGS_INSECURE_STATE_DIR: hostileState },
      }),
    );
    assert.deepEqual((await readdir(join(hostileState, "control"))).sort(), [
      "client_ed25519_key",
      "client_ed25519_key.pub",
    ]);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
    await rm(hostileState, { recursive: true, force: true });
    await rm(temp, { recursive: true, force: true });
  }
});

test("insecure driver preflights stale docker resources before creating launcher state", async () => {
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
          COGS_INSECURE_IMAGE: "cogs-insecure-fake:dev",
        },
      }),
    );
    const text = await readFile(log, "utf8");
    assert(text.includes(`home=${stateDir}.lock/docker-tool/home\n`));
    assert(!text.includes(`home=${stateDir}/docker-tool/home\n`));
    await assert.rejects(access(stateDir));
    assert.deepEqual(await readdir(launcherControl), ["sandbox"]);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
    await rm(`${stateDir}.lock`, { recursive: true, force: true });
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
    const item = descriptor("linux-kvm", driverPath("linux-kvm"), launcherState, "verify");
    assert.equal(item.executable, driverPath("linux-kvm"));
    assert.deepEqual(item.args, ["verify"]);
    assert.equal(item.timeoutMs, 300_000);
    assert.equal(descriptor("linux-kvm", driverPath("linux-kvm"), launcherState, "destroy").timeoutMs, 120_000);
    assert.equal(item.env.COGS_KVM_STATE_DIR, launcherState.driverStateDir);
    assert(!Object.keys(item.env).some((key) => /TOKEN|SECRET|KEY/.test(key)));
  } finally {
    await cleanup(launcherState);
  }
});

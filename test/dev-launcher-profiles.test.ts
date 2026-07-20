import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { lstat, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { normalizeDriverResult } from "../dev/launcher/contract.ts";
import { createProfileAdapter, descriptor, driverPath } from "../dev/launcher/profiles.ts";
import type { RunnerSeams } from "../dev/launcher/runner.ts";
import { resolveLauncherState } from "../dev/launcher/state.ts";

const sourceRevision = "1".repeat(40);

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
  for (const text of [insecureEntrypoint, insecure]) {
    assert.match(text, /\/shared\/skills \/user\/skills/);
    assert.match(text, /realpath -e "\$skill_root"/);
    assert.match(text, /0:0:700:directory/);
  }

  const kvm = await readFile(join(process.cwd(), "dev/linux-kvm/driver.sh"), "utf8");
  assert.match(kvm, /read -r host_key_type host_key_data ignored/);
  assert.match(kvm, /printf '%s %s %s\\n' "\$guest_ip" "\$host_key_type" "\$host_key_data"/);
  assert.match(kvm, /\/shared\/skills, \/user\/skills/);
  assert.match(kvm, /realpath -e "\$skill_root"/);
  assert.match(kvm, /0:0:700:directory/);
  assert(!kvm.includes('"$(<"$state/control/host_ed25519_key.pub")"'));
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

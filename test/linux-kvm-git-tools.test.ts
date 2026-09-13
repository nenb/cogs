import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const gitTools = join(root, "dev/linux-kvm/git-tools.sh");
const driver = join(root, "dev/linux-kvm/driver.sh");
const boundedHelper = join(root, "dev/linux-kvm/bounded-command.py");
const kvmImageSha =
  "78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667";

async function sourceGitTools(command: string, env: Record<string, string> = {}) {
  const { spawnSync } = await import("node:child_process");
  return spawnSync("bash", ["-c", `set -euo pipefail; source ${JSON.stringify(gitTools)}; ${command}`], {
    cwd: root,
    env: { ...process.env, ...env },
    encoding: "utf8",
    timeout: 10_000,
  });
}

test("shared KVM receipt gate accepts a root-owned positive fixture", async () => {
  const { spawnSync } = await import("node:child_process");
  if (process.platform !== "linux" || spawnSync("sudo", ["-n", "true"]).status !== 0) return;
  const source = "a".repeat(40);
  const run = "123";
  const attempt = "1";
  const generation = createHash("sha256").update(`${run}:${attempt}:${source}`).digest("hex").slice(0, 32);
  const receipt = join(tmpdir(), `cogs-kvm-gate-${process.pid}.json`);
  const protectedReceipt = `/run/cogs-kvm-gate-${process.pid}.json`;
  const value = {
    version: "cogs.linux-kvm-execution/v1",
    run_id: run,
    run_attempt: attempt,
    candidate: source,
    source_revision: source,
    generation,
    expires: Date.now() + 60_000,
  };
  try {
    await writeFile(receipt, `${JSON.stringify(value, Object.keys(value).sort())}\n`, { mode: 0o600 });
    assert.equal(
      spawnSync("sudo", ["-n", "install", "-o", "root", "-g", "root", "-m", "0444", receipt, protectedReceipt]).status,
      0,
    );
    const result = await sourceGitTools("cogs_kvm_execution_gate", {
      COGS_KVM_EXECUTION_RECEIPT: protectedReceipt,
      COGS_KVM_GENERATION: generation,
      COGS_SOURCE_REVISION: source,
      GITHUB_RUN_ID: run,
      GITHUB_RUN_ATTEMPT: attempt,
    });
    assert.equal(result.status, 0, result.stderr);
  } finally {
    spawnSync("sudo", ["-n", "rm", "-f", protectedReceipt]);
    await rm(receipt, { force: true });
  }
});

test("shared KVM receipt gate rejects a root-owned receipt with a mismatched source binding", async () => {
  const { spawnSync } = await import("node:child_process");
  if (process.platform !== "linux" || spawnSync("sudo", ["-n", "true"]).status !== 0) return;
  const source = "a".repeat(40);
  const run = "123";
  const attempt = "1";
  const generation = createHash("sha256").update(`${run}:${attempt}:${source}`).digest("hex").slice(0, 32);
  const receipt = join(tmpdir(), `cogs-kvm-gate-negative-${process.pid}.json`);
  const protectedReceipt = `/run/cogs-kvm-gate-negative-${process.pid}.json`;
  const value = {
    version: "cogs.linux-kvm-execution/v1",
    run_id: run,
    run_attempt: attempt,
    candidate: source,
    source_revision: source,
    generation,
    expires: Date.now() + 60_000,
  };
  try {
    await writeFile(receipt, `${JSON.stringify(value, Object.keys(value).sort())}\n`, { mode: 0o600 });
    assert.equal(
      spawnSync("sudo", ["-n", "install", "-o", "root", "-g", "root", "-m", "0444", receipt, protectedReceipt]).status,
      0,
    );
    const result = await sourceGitTools("cogs_kvm_execution_gate", {
      COGS_KVM_EXECUTION_RECEIPT: protectedReceipt,
      COGS_KVM_GENERATION: generation,
      COGS_SOURCE_REVISION: "b".repeat(40),
      GITHUB_RUN_ID: run,
      GITHUB_RUN_ATTEMPT: attempt,
    });
    assert.notEqual(result.status, 0, result.stderr);
  } finally {
    spawnSync("sudo", ["-n", "rm", "-f", protectedReceipt]);
    await rm(receipt, { force: true });
  }
});

test("ADR0037 Git tools manifest is exact, bounded, and not parameterized", async () => {
  const result = await sourceGitTools("cogs_git_tools_manifest");
  assert.equal(result.status, 0, result.stderr);
  const rows = result.stdout
    .trim()
    .split("\n")
    .map((line) => line.split("\t"));
  assert.equal(rows.length, 4);
  assert.deepEqual(
    rows.map(([name, version, arch, file, size, url, sha]) => ({ name, version, arch, file, size, url, sha })),
    [
      {
        name: "git",
        version: "1:2.47.3-0+deb13u1",
        arch: "amd64",
        file: "git_2.47.3-0+deb13u1_amd64.deb",
        size: "8861572",
        url: "https://deb.debian.org/debian/pool/main/g/git/git_2.47.3-0+deb13u1_amd64.deb",
        sha: "3e35662fd5c46add561703e54031a1d8ad9df45811927689f0a51122b13be722",
      },
      {
        name: "libcurl3t64-gnutls",
        version: "8.14.1-2+deb13u4",
        arch: "amd64",
        file: "libcurl3t64-gnutls_8.14.1-2+deb13u4_amd64.deb",
        size: "384336",
        url: "https://deb.debian.org/debian/pool/main/c/curl/libcurl3t64-gnutls_8.14.1-2+deb13u4_amd64.deb",
        sha: "351bf3bb1c816c1d88900cbfe59dc79433f20fb962947d78313028a00f97c856",
      },
      {
        name: "libngtcp2-16",
        version: "1.11.0-1+deb13u1",
        arch: "amd64",
        file: "libngtcp2-16_1.11.0-1+deb13u1_amd64.deb",
        size: "131904",
        url: "https://deb.debian.org/debian/pool/main/n/ngtcp2/libngtcp2-16_1.11.0-1+deb13u1_amd64.deb",
        sha: "627eec81ebbd48c4e6091f5cd9dc5070b792b7075000eed60ab08c7daa961caf",
      },
      {
        name: "libngtcp2-crypto-gnutls8",
        version: "1.11.0-1+deb13u1",
        arch: "amd64",
        file: "libngtcp2-crypto-gnutls8_1.11.0-1+deb13u1_amd64.deb",
        size: "29524",
        url: "https://deb.debian.org/debian/pool/main/n/ngtcp2/libngtcp2-crypto-gnutls8_1.11.0-1+deb13u1_amd64.deb",
        sha: "2a7f109c0c4db6a800e4661c5e5e34e1f1f83c8162482276183d1ada9da7c96c",
      },
    ],
  );
  for (const row of rows) {
    assert.match(row[5] ?? "", /^https:\/\/deb\.debian\.org\/debian\/pool\//u);
    assert.match(row[6] ?? "", /^[a-f0-9]{64}$/u);
  }
});

test("Git tools builder uses bounded verified cache, metadata checks, wrapper, and deterministic image ownership", async () => {
  const text = await readFile(gitTools, "utf8");
  assert.match(text, /--proto '=https' --tlsv1\.2 --max-time 120 --max-filesize "\$size" --retry 3/u);
  assert.match(text, /mktemp "\$cache\/\.\$filename\.XXXXXX\.partial"/u);
  assert.match(text, /chmod 0600 "\$tmp"/u);
  assert.match(text, /sha256sum "\$file"/u);
  assert.match(text, /wc -c < "\$file"/u);
  assert.match(text, /COGS_GIT_TOOLS_DPKG_DEB" --field "\$file" Package/u);
  assert.match(text, /COGS_GIT_TOOLS_DPKG_DEB" --field "\$file" Version/u);
  assert.match(text, /COGS_GIT_TOOLS_DPKG_DEB" --field "\$file" Architecture/u);
  assert.match(text, /COGS_GIT_TOOLS_DPKG_DEB" -x "\$package_file" "\$root"/u);
  assert.match(text, /GIT_EXEC_PATH=\/opt\/cogs-git\/usr\/lib\/git-core/u);
  assert.match(text, /GIT_TEMPLATE_DIR=\/opt\/cogs-git\/usr\/share\/git-core\/templates/u);
  assert.match(text, /LD_LIBRARY_PATH=\/opt\/cogs-git\/usr\/lib\/x86_64-linux-gnu/u);
  assert.doesNotMatch(text, /LD_LIBRARY_PATH=\/opt\/cogs-git[^\n]*\$\{LD_LIBRARY_PATH/u);
  assert.match(text, /exec \/opt\/cogs-git\/usr\/bin\/git "\$@"/u);
  assert.match(text, /set -o noclobber; : > "\$image_tmp"/u);
  assert.match(text, /ln "\$image_tmp" "\$image"/u);
  assert.match(text, /cogs_git_tools_verify_image_file "\$image"/u);
  assert.match(text, /COGS_GIT_TOOLS_MKFS" -q -F -L "\$COGS_GIT_TOOLS_LABEL" -d "\$root"/u);
  assert.ok(text.includes("paths=['/']"));
  assert.match(text, /set_inode_field \{rel\} uid 0/u);
  assert.match(text, /set_inode_field \{rel\} gid 0/u);
  assert.doesNotMatch(text, /apt-get|\bapt\b|sudo rm -rf|mv -f|eval|bash -c "\$|curl .*\$\{/u);
});

test("Git tools postwalk accepts safe package symlinks but rejects traversal, devices, world writable, and unexpected roots", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-git-tools-walk-"));
  try {
    const safe = join(dir, "safe");
    await mkdir(join(safe, "usr/bin"), { recursive: true });
    await writeFile(join(safe, "usr/bin/git"), "x", { mode: 0o755 });
    await symlink("git", join(safe, "usr/bin/git-link"));
    if (process.platform === "linux") {
      assert.equal((await lstat(join(safe, "usr/bin/git-link"))).mode & 0o777, 0o777);
    }
    await mkdir(join(safe, "bin"));
    await mkdir(join(safe, "usr/lib/git-core"), { recursive: true });
    await mkdir(join(safe, "usr/share/git-core/templates"), { recursive: true });
    await mkdir(join(safe, "usr/lib/x86_64-linux-gnu"), { recursive: true });
    await writeFile(join(safe, "bin/git"), "x", { mode: 0o755 });
    await writeFile(join(safe, "usr/lib/git-core/git-add"), "x", { mode: 0o755 });
    await writeFile(join(safe, "usr/share/git-core/templates/HEAD"), "x", { mode: 0o644 });
    await writeFile(join(safe, "usr/lib/x86_64-linux-gnu/libcurl.so.4"), "x", { mode: 0o644 });
    await writeFile(join(safe, "cogs-git-tools-manifest.tsv"), "x", { mode: 0o444 });
    assert.equal((await sourceGitTools(`cogs_git_tools_postwalk ${JSON.stringify(safe)}`)).status, 0);

    const absolute = join(dir, "absolute");
    await mkdir(join(absolute, "usr/bin"), { recursive: true });
    await symlink("/usr/bin/git", join(absolute, "usr/bin/bad"));
    assert.notEqual((await sourceGitTools(`cogs_git_tools_postwalk ${JSON.stringify(absolute)}`)).status, 0);

    const outside = join(dir, "outside");
    await mkdir(join(outside, "usr/bin"), { recursive: true });
    await symlink("../../../../etc/passwd", join(outside, "usr/bin/bad"));
    assert.notEqual((await sourceGitTools(`cogs_git_tools_postwalk ${JSON.stringify(outside)}`)).status, 0);

    const writable = join(dir, "writable");
    await mkdir(join(writable, "usr/bin"), { recursive: true });
    await writeFile(join(writable, "usr/bin/git"), "x", { mode: 0o660 });
    await chmod(join(writable, "usr/bin/git"), 0o660);
    assert.notEqual((await sourceGitTools(`cogs_git_tools_postwalk ${JSON.stringify(writable)}`)).status, 0);

    const writableDir = join(dir, "writable-dir");
    await mkdir(join(writableDir, "usr/bin"), { recursive: true });
    await chmod(join(writableDir, "usr/bin"), 0o775);
    assert.notEqual((await sourceGitTools(`cogs_git_tools_postwalk ${JSON.stringify(writableDir)}`)).status, 0);

    const unexpected = join(dir, "unexpected");
    await mkdir(join(unexpected, "home/user"), { recursive: true });
    await writeFile(join(unexpected, "home/user/file"), "x", { mode: 0o644 });
    assert.notEqual((await sourceGitTools(`cogs_git_tools_postwalk ${JSON.stringify(unexpected)}`)).status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("Git tools executable helpers preserve invalid cache and produce injection-safe root ownership commands", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-git-tools-exec-"));
  try {
    const cache = join(dir, "cache");
    await mkdir(cache, { mode: 0o700 });
    const final = join(cache, "git_2.47.3-0+deb13u1_amd64.deb");
    await writeFile(final, "invalid", { mode: 0o400 });
    const before = await lstat(final);
    const prepare = await sourceGitTools(
      `cogs_git_tools_prepare_package ${JSON.stringify(cache)} git '1:2.47.3-0+deb13u1' amd64 git_2.47.3-0+deb13u1_amd64.deb 8861572 https://deb.debian.org/debian/pool/main/g/git/git_2.47.3-0+deb13u1_amd64.deb 3e35662fd5c46add561703e54031a1d8ad9df45811927689f0a51122b13be722`,
    );
    assert.notEqual(prepare.status, 0);
    const after = await lstat(final);
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.equal(await readFile(final, "utf8"), "invalid");

    const tree = join(dir, "tree");
    await mkdir(join(tree, "usr/bin"), { recursive: true });
    await mkdir(join(tree, "usr/lib/git-core"), { recursive: true });
    await writeFile(join(tree, "usr/bin/git"), "x", { mode: 0o755 });
    await writeFile(join(tree, "usr/lib/git-core/git-add"), "x", { mode: 0o755 });
    const commands = await sourceGitTools(`cogs_git_tools_debugfs_ownership_commands ${JSON.stringify(tree)}`);
    assert.equal(commands.status, 0, commands.stderr);
    assert.match(commands.stdout, /^set_inode_field \/ uid 0\nset_inode_field \/ gid 0\n/u);
    assert.doesNotMatch(commands.stdout, /[;'"`$\\]/u);

    const buildState = join(dir, "state");
    const emptyCache = join(dir, "empty-cache");
    await mkdir(buildState, { mode: 0o700 });
    await mkdir(emptyCache, { mode: 0o700 });
    const build = await sourceGitTools(
      `cogs_git_tools_build_image ${JSON.stringify(buildState)} ${JSON.stringify(emptyCache)}`,
    );
    assert.notEqual(build.status, 0);
    assert.doesNotMatch(build.stderr, /unbound variable/u);

    const wrapperRoot = join(dir, "wrapper");
    const wrapper = await sourceGitTools(`cogs_git_tools_write_wrapper ${JSON.stringify(wrapperRoot)}`);
    assert.equal(wrapper.status, 0, wrapper.stderr);
    const wrapperText = await readFile(join(wrapperRoot, "bin/git"), "utf8");
    assert.match(wrapperText, /^export LD_LIBRARY_PATH=\/opt\/cogs-git\/usr\/lib\/x86_64-linux-gnu$/mu);
    assert.doesNotMatch(wrapperText, /LD_LIBRARY_PATH.*\$/u);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("Linux/KVM driver wires Git tools as read-only guest disk with fixed verification and no guest package install", async () => {
  const text = (await readFile(driver, "utf8")) + (await readFile(boundedHelper, "utf8"));
  assert.match(text, /source "\$repo\/dev\/linux-kvm\/git-tools\.sh"/u);
  assert.match(text, /prepare_git_tools_disk "\$state" "\$cache"/u);
  assert.match(text, /prepare-cache\)\n {4}prepare_image >&2\n {4}cogs_git_tools_prepare_cache "\$cache" >&2/u);
  assert.match(text, /-drive if=virtio,format=raw,readonly=on,file="\$state\/git-tools\.img"/u);
  assert.match(text, /\[LABEL=COGS_GITTOOLS, \/opt\/cogs-git, auto, 'ro,nosuid,nodev'/u);
  assert.match(
    text,
    /test ! -e \/usr\/bin\/git && test ! -L \/usr\/bin\/git && ln -s \/opt\/cogs-git\/bin\/git \/usr\/bin\/git/u,
  );
  assert.doesNotMatch(text, /ln, -sfn/u);
  assert.match(text, /readonly=on,file=\$state\/git-tools\.img/u);
  assert.match(text, /blkid -s LABEL -o value/u);
  assert.match(text, /blockdev --getro "\$source"/u);
  assert.match(text, /findmnt -rn -o OPTIONS \/opt\/cogs-git/u);
  assert.match(text, /! find \/opt\/cogs-git -xdev .* ! -type l -a -perm \/0022/u);
  assert.match(text, /git --version\)" = "git version 2\.47\.3"/u);
  assert.match(text, /ldd \/opt\/cogs-git\/usr\/bin\/git/u);
  assert.match(text, /git init -q/u);
  assert.match(text, /git notes --ref=cogs add/u);
  assert.match(text, /git fsck --no-progress/u);
  assert.match(text, /rm -f "\$state\/root-overlay\.qcow2" "\$state\/seed\.img"/u);
  assert.match(text, /cogs_git_tools_verify_image_file "\$state\/git-tools\.img"/u);
  assert.doesNotMatch(text, /apt-get|\bapt\b|dpkg -i|curl .*guest|wget/u);
});

test("KVM workflow artifacts remain metadata reports and do not upload Git tools cache or image", async () => {
  const workflow = await readFile(join(root, ".github/workflows/kvm-qualification.yml"), "utf8");
  assert.match(
    workflow,
    /path: \|\n {12}docs\/security-evidence\/generated\/kvm-qualification\.json\n {12}docs\/security-evidence\/generated\/kvm-driver-smoke\.json/u,
  );
  assert.doesNotMatch(workflow, /git-tools\.img|\.deb|COGS_KVM_CACHE_DIR/u);
  assert.match(workflow, /dev\/linux-kvm\/ci-smoke\.sh/u);
  assert.match(workflow, /id: smoke/u);
  assert.match(workflow, /driver\.sh prepare-cache/u);
  assert.doesNotMatch(workflow, /driver\.sh (?:create|destroy|ssh)|envoy-kvm|suite-smoke|run-kvm-black-box-case/u);
  assert.ok(workflow.indexOf("driver.sh prepare-cache") < workflow.indexOf("ip netns add"));
  assert.match(workflow, /cogs-exclusive-netns-v1/u);
  assert.match(workflow, /sudo -n ip netns exec "\$COGS_KVM_NETNS" sudo -n -u "\$USER"/u);
  assert.match(workflow, /EXECUTE_PROTECTED_KVM/u);
  assert.match(workflow, /GITHUB_TRIGGERING_ACTOR/u);
  assert.match(workflow, /cogs\.linux-kvm-execution\/v1/u);
  assert.match(
    workflow,
    /COGS_KVM_GENERATION="\$COGS_KVM_GENERATION" COGS_KVM_EXECUTION_RECEIPT="\$COGS_KVM_EXECUTION_RECEIPT"/u,
  );
  assert.match(workflow, /GITHUB_RUN_ID="\$GITHUB_RUN_ID" GITHUB_RUN_ATTEMPT="\$GITHUB_RUN_ATTEMPT"/u);
  assert.match(workflow, /if ! pids=\$\(sudo ip netns pids "\$COGS_KVM_NETNS"\); then/u);
  assert.ok(
    workflow.indexOf('sudo ip netns delete "$COGS_KVM_NETNS"') < workflow.indexOf('sudo rm -- "$COGS_KVM_LEASE"'),
  );
  assert.match(workflow, /printf 'COGS_KVM_NETNS=%s\\n' "\$ns" >>"\$GITHUB_ENV"/u);
  assert.match(workflow, /trap rollback EXIT/u);
});

function workflowRunBlock(workflow: string, name: string): string {
  const marker = `      - name: ${name}\n`;
  const start = workflow.indexOf(marker);
  assert.notEqual(start, -1, `workflow step ${name}`);
  const run = workflow.indexOf("        run: |\n", start);
  assert.notEqual(run, -1, `run block ${name}`);
  const bodyStart = run + "        run: |\n".length;
  const end = workflow.indexOf("\n      - name:", bodyStart);
  const body = workflow.slice(bodyStart, end === -1 ? undefined : end);
  return body
    .split("\n")
    .map((line) => (line.startsWith("          ") ? line.slice(10) : line))
    .join("\n");
}

test("KVM network-domain cleanup rejects uncertain or live observations and retains its lease until deletion", async () => {
  const workflow = await readFile(join(root, ".github/workflows/kvm-qualification.yml"), "utf8");
  const cleanup = workflowRunBlock(workflow, "Retire the exclusive disposable driver network domain");
  const { spawnSync } = await import("node:child_process");
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-cleanup-faults-"));
  try {
    for (const [mode, expectedStatus, expected] of [
      ["enumeration-fails", 1, { deleted: false, removed: false }],
      ["process-live", 1, { deleted: false, removed: false }],
      ["deletion-fails", 1, { deleted: true, removed: false }],
      ["success", 0, { deleted: true, removed: true }],
    ] as const) {
      const calls = join(dir, `${mode}.calls`);
      const harness = `sudo() {
  printf '%s\\n' "$*" >> "$CALLS"
  case "$*" in
    "ip netns exec fixture stat -Lc %d-%i /proc/self/ns/net") printf '4-42\\n' ;;
    "ip netns pids fixture")
      [[ "$MODE" != enumeration-fails ]] || return 7
      [[ "$MODE" != process-live ]] || printf '123\\n'
      ;;
    "ip netns delete fixture") [[ "$MODE" != deletion-fails ]] || return 8 ;;
    "rm -- "*) ;;
    *) return 9 ;;
  esac
}
${cleanup}`;
      const result = spawnSync("bash", ["-c", harness], {
        cwd: root,
        env: {
          ...process.env,
          CALLS: calls,
          MODE: mode,
          COGS_KVM_NETNS: "fixture",
          COGS_KVM_NETNS_IDENTITY: "4-42",
          COGS_KVM_LEASE: join(dir, "absent-lease"),
        },
        encoding: "utf8",
      });
      if (expectedStatus === 0) assert.equal(result.status, 0, `${mode}: ${result.stderr}`);
      else assert.notEqual(result.status, 0, `${mode}: ${result.stderr}`);
      const recorded = await readFile(calls, "utf8");
      const deleted = recorded.includes("ip netns delete fixture");
      const removed = recorded.includes("rm -- ");
      assert.deepEqual({ deleted, removed }, expected, mode);
      if (removed) assert.ok(recorded.indexOf("ip netns delete fixture") < recorded.indexOf("rm -- "), mode);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("KVM network-domain provisioning initializes complete empty dual-stack filter snapshots before driver handoff", async () => {
  const workflow = await readFile(join(root, ".github/workflows/kvm-qualification.yml"), "utf8");
  const provision = workflowRunBlock(workflow, "Provision the exclusive disposable driver network domain");
  const { spawnSync } = await import("node:child_process");
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-filter-provision-"));
  const empty = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT";
  try {
    for (const [mode, expectedStatus] of [
      ["empty", 0],
      ["unexpected-rule", 1],
      ["unexpected-chain", 1],
    ] as const) {
      const calls = join(dir, `${mode}.calls`);
      const githubEnv = join(dir, `${mode}.env`);
      await writeFile(githubEnv, "");
      const harness = `cat() {
  if [[ "$#" -eq 1 && "$1" == /proc/sys/kernel/random/boot_id ]]; then
    printf '00000000-0000-0000-0000-000000000042\\n'
  else
    command cat "$@"
  fi
}
sudo() {
  printf '%s\\n' "$*" >> "$CALLS"
  case "$*" in
    "ip netns add "*|"ip -n "*) ;;
    "ip netns exec cogs-kvm-42-1 stat -Lc %d-%i /proc/self/ns/net") printf '4-42\\n' ;;
    "ip netns exec cogs-kvm-42-1 iptables -w 5 -P "*|"ip netns exec cogs-kvm-42-1 ip6tables -w 5 -P "*) ;;
    "ip netns exec cogs-kvm-42-1 iptables-save -t filter"|"ip netns exec cogs-kvm-42-1 ip6tables-save -t filter")
      if [[ "$MODE" == unexpected-rule ]]; then
        printf '*filter\\n:INPUT ACCEPT [0:0]\\n:FORWARD ACCEPT [0:0]\\n:OUTPUT ACCEPT [0:0]\\n-A INPUT -j DROP\\nCOMMIT\\n'
      elif [[ "$MODE" == unexpected-chain ]]; then
        printf '*filter\\n:INPUT ACCEPT [0:0]\\n:FORWARD ACCEPT [0:0]\\n:OUTPUT ACCEPT [0:0]\\n:foreign - [0:0]\\nCOMMIT\\n'
      else
        printf '%s\\n' "$EMPTY_FILTER"
      fi
      ;;
    "ip netns pids cogs-kvm-42-1") ;;
    "ip netns delete cogs-kvm-42-1"|"install -d "*|"tee /run/cogs-kvm-network-domain/4-42"|"chmod 0444 /run/cogs-kvm-network-domain/4-42") ;;
    *) return 9 ;;
  esac
}
${provision}`;
      const result = spawnSync("bash", ["-c", harness], {
        cwd: root,
        env: {
          ...process.env,
          CALLS: calls,
          EMPTY_FILTER: empty,
          GITHUB_ENV: githubEnv,
          GITHUB_RUN_ID: "42",
          GITHUB_RUN_ATTEMPT: "1",
          MODE: mode,
        },
        encoding: "utf8",
      });
      if (expectedStatus === 0) assert.equal(result.status, 0, result.stderr);
      else assert.notEqual(result.status, 0, result.stderr);
      const recorded = (await readFile(calls, "utf8")).trim().split("\n");
      const policy = recorded.filter((call) => call.includes(" -w 5 -P "));
      const expectedPolicy = [
        "ip netns exec cogs-kvm-42-1 iptables -w 5 -P INPUT ACCEPT",
        "ip netns exec cogs-kvm-42-1 iptables -w 5 -P FORWARD ACCEPT",
        "ip netns exec cogs-kvm-42-1 iptables -w 5 -P OUTPUT ACCEPT",
        "ip netns exec cogs-kvm-42-1 ip6tables -w 5 -P INPUT ACCEPT",
        "ip netns exec cogs-kvm-42-1 ip6tables -w 5 -P FORWARD ACCEPT",
        "ip netns exec cogs-kvm-42-1 ip6tables -w 5 -P OUTPUT ACCEPT",
      ];
      assert.deepEqual(policy, mode === "empty" ? expectedPolicy : expectedPolicy.slice(0, 3));
      assert.ok(policy.every((call) => call.startsWith("ip netns exec cogs-kvm-42-1 ")));
      const expectedSaves = [
        "ip netns exec cogs-kvm-42-1 iptables-save -t filter",
        "ip netns exec cogs-kvm-42-1 ip6tables-save -t filter",
      ];
      assert.deepEqual(
        recorded.filter((call) => call.endsWith("-save -t filter")),
        mode === "empty" ? expectedSaves : expectedSaves.slice(0, 1),
      );
      assert.equal(recorded.includes("ip netns delete cogs-kvm-42-1"), mode !== "empty");
    }
    assert.ok(
      workflow.indexOf('"$tool"-save -t filter') < workflow.indexOf("Exercise the isolated Debian guest lifecycle"),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("KVM network-domain provisioning publishes custody and safely rolls back partial acquisition", async () => {
  const workflow = await readFile(join(root, ".github/workflows/kvm-qualification.yml"), "utf8");
  const provision = workflowRunBlock(workflow, "Provision the exclusive disposable driver network domain");
  const { spawnSync } = await import("node:child_process");
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-provision-faults-"));
  try {
    for (const [mode, expected] of [
      ["link-fails", { deleted: true, removed: false, reachedChmod: false }],
      ["identity-fails", { deleted: false, removed: false, reachedChmod: false }],
      ["chmod-fails", { deleted: true, removed: true, reachedChmod: true }],
    ] as const) {
      const calls = join(dir, `${mode}.calls`);
      const githubEnv = join(dir, `${mode}.env`);
      await writeFile(githubEnv, "");
      const harness = `cat() {
  if [[ "$#" -eq 1 && "$1" == /proc/sys/kernel/random/boot_id ]]; then
    printf '00000000-0000-0000-0000-000000000042\\n'
  else
    command cat "$@"
  fi
}
sudo() {
  printf '%s\\n' "$*" >> "$CALLS"
  case "$*" in
    "ip netns add "*) ;;
    "ip -n "*" link set lo up") [[ "$MODE" != link-fails ]] || return 6 ;;
    "ip netns exec "*" stat -Lc %d-%i /proc/self/ns/net")
      [[ "$MODE" != identity-fails ]] || return 7
      printf '4-42\\n'
      ;;
    "ip netns exec "*" iptables -w 5 -P "*|"ip netns exec "*" ip6tables -w 5 -P "*) ;;
    "ip netns exec "*" iptables-save -t filter"|"ip netns exec "*" ip6tables-save -t filter")
      printf '*filter\\n:INPUT ACCEPT [0:0]\\n:FORWARD ACCEPT [0:0]\\n:OUTPUT ACCEPT [0:0]\\nCOMMIT\\n'
      ;;
    "ip netns pids "*) ;;
    "ip netns delete "*) ;;
    "install -d "*) ;;
    "tee "*) cat >/dev/null ;;
    "chmod 0444 "*) [[ "$MODE" != chmod-fails ]] || return 8 ;;
    "rm -- "*) ;;
    *) return 9 ;;
  esac
}
${provision}`;
      const result = spawnSync("bash", ["-c", harness], {
        cwd: root,
        env: {
          ...process.env,
          CALLS: calls,
          MODE: mode,
          GITHUB_ENV: githubEnv,
          GITHUB_RUN_ID: "42",
          GITHUB_RUN_ATTEMPT: "1",
        },
        encoding: "utf8",
      });
      assert.notEqual(result.status, 0, `${mode}: ${result.stderr}`);
      assert.match(await readFile(githubEnv, "utf8"), /^COGS_KVM_NETNS=cogs-kvm-42-1$/mu);
      const recorded = await readFile(calls, "utf8");
      const deleted = recorded.includes("ip netns delete cogs-kvm-42-1");
      const removed = /rm -- .*cogs-kvm-network-domain/u.test(recorded);
      const reachedChmod = recorded.includes("chmod 0444 /run/cogs-kvm-network-domain/4-42");
      assert.deepEqual({ deleted, removed, reachedChmod }, expected, mode);
      if (removed) {
        assert.ok(recorded.indexOf("ip netns delete cogs-kvm-42-1") < recorded.indexOf("rm -- "), mode);
      }
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

function shellFunction(text: string, name: string): string {
  const matches = [...text.matchAll(new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}`, "gmu"))];
  assert.equal(matches.length, 1, `unique ${name} function`);
  return matches[0]?.[0] ?? "";
}

function serialContract(text: string) {
  const start = shellFunction(text, "start_vm");
  const command = start.match(/ {2}nohup [\s\S]*?9>&- &/u)?.[0];
  // Exact supported launch shape, not a comment/unused null token or flag blacklist.
  assert.equal(
    command,
    String.raw`  nohup qemu-system-x86_64 \
    -name cogs-stage1-linux-kvm -machine q35 -accel kvm -cpu host -smp 2 -m 2048M \
    -drive if=virtio,format=qcow2,file="$state/root-overlay.qcow2" \
    -drive if=virtio,format=raw,readonly=on,file="$state/seed.img" \
    -drive if=virtio,format=raw,readonly=on,file="$state/git-tools.img" \
    -drive if=virtio,format=raw,file="$state/workspace.img" \
    -netdev tap,id=cogsnet,ifname="$tap",script=no,downscript=no \
    -device virtio-net-pci,netdev=cogsnet,mac=52:54:00:c0:65:01 \
    -display none -serial null -monitor none \
    -qmp unix:"$state/qmp.sock",server=on,wait=off -no-reboot \
    >"$state/qemu.stdout" 2>"$state/qemu.stderr" 9>&- &`,
  );
  assert.equal(text.match(/nohup qemu-system-x86_64/gu)?.length, 1);
  assert.equal(text.match(/-serial\b/gu)?.length, 1);
  assert.equal(text.match(/serial\.log/gu)?.length ?? 0, 0);
  assert.ok(start.indexOf('rm -f "$state/qmp.sock"') < start.indexOf("  nohup "));
  assert.match(start, /qemu_owner capture[\s\S]*bounded_guest readiness/u);
  const routes = text.slice(text.indexOf('case "$operation" in'));
  assert.match(routes, /create\)[\s\S]*owner_stage seed\n {4}prepare_seed[\s\S]*owner_stage runtime\n {4}start_vm/u);
  assert.doesNotMatch(routes, /if ! owner_stage|owner_stage [^;\n]+ [a-z_]+/u);
  assert.match(routes, /reset\)[\s\S]*stop_vm >&2[\s\S]*remove_network >&2[\s\S]*prepare_seed\n {4}start_vm/u);
  assert.doesNotMatch(routes, /trap .*rm -rf|rm -rf "\$state"/u);
  assert.match(routes, /generation_owner intent removal[\s\S]*generation_owner remove/u);
}

test("driver UART is null on the shared create/reset launch; stage-zero marker capture stays separate", async () => {
  const text = await readFile(driver, "utf8");
  serialContract(text);
  const qualify = await readFile(join(root, "dev/linux-kvm/qualify.sh"), "utf8");
  assert.ok(qualify.includes('-serial file:"$guest_log"'));
  assert.ok(qualify.includes('echo "COGS_GUEST_READY=1"'));
  assert.ok(qualify.includes("grep -q '^COGS_GUEST_READY=1' \"$guest_log\""));
  for (const mutant of [
    '-serial file:"$state/serial.log"',
    "-serial file:/dev/null",
    "-serial stdio",
    "-serial mon:stdio",
    "-serial none",
    "-serial $BACKEND",
    "# -serial null",
    "-serial null -serial stdio",
    "-serial null -chardev null,id=uart,logfile=uart.log",
    "-serial null -nographic",
    "-serial null -D trace.log",
    "-serial null -debugcon file:debug.log",
  ])
    assert.throws(() => serialContract(text.replace("-serial null", mutant)), mutant);
});

// Extract only the reviewed embedded owner program. Never source the driver:
// its normal shell top level owns real state/locks. Every command/signal below
// is replaced with recording fakes before run(); only a private temp dir is used.
async function ownerTest(owner: "qemu" | "network", body: string) {
  const { spawnSync } = await import("node:child_process");
  const text = shellFunction(await readFile(driver, "utf8"), `${owner}_owner`);
  const program = text.split("<<'PY'\n")[1]?.split("\nPY\n")[0];
  assert.ok(program);
  const entry = owner === "network" ? "try:\n    domain_fd=domain_lock()" : "try:\n    run()";
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-owner-"));
  try {
    const result = spawnSync(
      "python3",
      [
        "-c",
        `
import copy,json,os,pathlib,subprocess,sys
from unittest.mock import patch
sys.argv=['owner',${JSON.stringify(dir)},'stop','cgtap','CGINPUT','CGFORWARD','18080','1000']
program=${JSON.stringify(program)}
def forbidden(*args,**kwargs): raise AssertionError('ambient effect forbidden')
with patch.object(subprocess,'check_output',forbidden), patch.object(os,'kill',forbidden):
    entry=${JSON.stringify(entry)}
    exec(program.split(entry)[0])
    if 'domain_lock' in globals():
        real_domain_lock=domain_lock
        domain_identity=[1,2,'boot']
        def domain_lock():
            fd=os.open(state/'fake-domain',os.O_CREAT|os.O_RDONLY,0o600)
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return fd
    def invoke():
        exec(entry+program.split(entry)[1],globals())
    def fails():
        try: invoke()
        except (RuntimeError,FileNotFoundError,ValueError,KeyError,ProcessLookupError): pass
        else: raise AssertionError('expected uncertainty')
    ${body.replaceAll("\n", "\n    ")}
`,
      ],
      { encoding: "utf8", timeout: 20_000 },
    );
    assert.equal(result.status, 0, result.stderr);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("QEMU custody uses a held pidfd, revalidates TERM/KILL, and never signals unknown/reused PIDs", async () => {
  await ownerTest(
    "qemu",
    `
real_identity=identity
signals=[]; closed=[]; observations=[]; polls=[]
def identity(pid): return observations.pop(0) if len(observations)>1 else observations[0]
def poll(ms): return polls.pop(0) if polls else []
class Poll:
    def register(self,fd,event): assert fd==88
    poll=staticmethod(poll)
def send(fd,sig,*args):
    assert fd==88 # numeric PID 42 is never the signal target
    signals.append(sig)
base={'phase':'live','pid':42,'identity':['boot','100','/qemu',1,2,'argv']}
def reset():
    save(copy.deepcopy(base)); signals.clear(); closed.clear()
    observations[:]=[base['identity']]; polls[:]=[]
with patch.object(os,'pidfd_open',lambda pid,flags: 88,create=True), patch.object(os,'close',closed.append), \\
     patch.object(signal,'pidfd_send_signal',send,create=True), patch.object(select,'poll',Poll):
    reset(); polls[:]=[[],[1]]; invoke()
    assert signals==[signal.SIGTERM] and closed==[88]
    assert json.loads(record.read_text())=={'phase':'retired'}
    invoke(); assert len(signals)==1 # repeated stop is effect-free
    reset(); polls[:]=[[],[],[],[1]]; invoke()
    assert signals==[signal.SIGTERM,signal.SIGKILL]
    for boundary in (1,2,3):
        reset(); observations[:]=[base['identity']]*(boundary-1)+[['replacement']]
        fails(); assert len(signals)==(1 if boundary==3 else 0)
        assert json.loads(record.read_text())['failed'] is True
        observations[:]=[base['identity']]; fails() # later observation cannot erase failure
    for pid in (0,1,-1,'42',True):
        reset(); value=copy.deepcopy(base); value['pid']=pid; save(value)
        fails(); assert not signals
    for phase in ('launching','unknown'):
        reset(); save({'phase':phase}); fails(); assert not signals
    reset(); polls[:]=[]; fails() # timeout does not mean retirement
    assert json.loads(record.read_text())['phase']=='live'
    reset()
    with patch.object(os,'pidfd_open',side_effect=ProcessLookupError): fails()
    assert not signals and json.loads(record.read_text())['failed']
    record.unlink(); fails(); assert not signals # no custody is never a clean stop
    reset(); save({'phase':'never'}); invoke(); assert not signals
`,
  );
});

test("network inverses preserve exact original tuples and unrelated resources; every failed cut is sticky", async () => {
  await ownerTest(
    "network",
    `
policy='*filter\\n:CGINPUT - [0:0]\\n:CGFORWARD - [0:0]\\n-A CGINPUT -j DROP\\n-I INPUT 1 -d 192.0.2.1 -p tcp --dport 18080 -j CGINPUT\\n-I FORWARD 1 -i cgtap -j CGFORWARD\\nCOMMIT\\n'
(state/'network.policy').write_text(policy)
world=[]; calls=[]; fail_at=None; no_effect=False
def snapshot(): return [copy.deepcopy(world),[],[]]
def command(args,expected=None):
    assert expected==snapshot()
    calls.append(args)
    if len(calls)==fail_at: raise RuntimeError('injected command failure')
    if action=='prepare': world.append(args)
    else:
        pending=json.loads(record.read_text())
        assert args==pending['steps'][-1][0]
        if not no_effect: world.pop()
    return ''
def reset():
    global action,fail_at,no_effect
    action='prepare'; fail_at=None; no_effect=False; world[:]=[['unrelated']]; calls.clear()
    save({'phase':'never','steps':[]})
reset(); invoke(); count=len(calls); assert count>8
assert all('-F' not in call for call in calls)
assert json.loads(record.read_text())['steps']
action='remove'; port='19090'; calls.clear(); invoke()
assert world==[['unrelated']]
assert any('--dport' in call and '18080' in call for call in calls)
assert not any('19090' in call for call in calls)
prior=len(calls); invoke(); assert len(calls)==prior # journaled idempotence
for cut in range(1,count+1):
    reset(); fail_at=cut; fails()
    retained=json.loads(record.read_text()); assert retained['failed'] and retained['pending']
    assert len(retained['steps'])==cut-1
    action='remove'; fail_at=None; before=len(calls); fails(); assert len(calls)==before
    reset(); invoke(); action='remove'; calls.clear(); fail_at=cut; fails()
    retained=json.loads(record.read_text()); assert retained['failed'] and retained['pending']
    fail_at=None; before=len(calls); fails(); assert len(calls)==before
reset(); invoke(); action='remove'; world.append(['foreign replacement'])
before=len(calls); fails(); assert len(calls)==before and world[-1]==['foreign replacement']
reset(); invoke(); action='remove'; no_effect=True; fails()
assert json.loads(record.read_text())['failed'] # command success without inverse is not cleanup
reset(); world.append(['cgtap']); fails(); assert not calls # colliding names are never adopted
record.unlink(); action='remove'; fails(); assert not calls
`,
  );
});

test("network observations bind link generation and complete filter tables, not counters or carrier", async () => {
  await ownerTest(
    "network",
    `
rules='*filter\\n:INPUT ACCEPT [12:34]\\n:FORWARD ACCEPT [0:0]\\n:OUTPUT ACCEPT [0:0]\\nCOMMIT\\n'
item={'ifindex':12,'ifname':tap,'ifalias':'cogs-generation','link_type':'ether','flags':['UP'],
      'linkinfo':{'info_kind':'tun','info_data':{'owner':1000,'group':1000,'vnet_hdr':False,'num_queues':0}}}
def command(args):
    if args[0].endswith('tables-save'): return rules
    if 'addr' in args: return json.dumps([{'ifname':tap,'addr_info':[]}])
    return json.dumps([item])
before=snapshot()
rules=rules.replace('[12:34]','[56:78]'); item['flags'].append('LOWER_UP')
item['linkinfo']['info_data'].update(vnet_hdr=True,num_queues=1)
assert snapshot()==before
item['linkinfo']['info_data']['owner']=1001; assert snapshot()!=before
item['linkinfo']['info_data']['owner']=1000
for field,value in (('ifindex',13),('ifalias','foreign')):
    old=item[field]; item[field]=value; assert snapshot()!=before; item[field]=old
rules='';
try: snapshot()
except RuntimeError: pass
else: raise AssertionError('empty observation accepted')
`,
  );
});

test("fake launch leaves unowned legacy serial entries untouched", async () => {
  const { spawnSync } = await import("node:child_process");
  const start = shellFunction(await readFile(driver, "utf8"), "start_vm");
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-serial-"));
  try {
    const target = join(dir, "unrelated");
    await writeFile(target, "preserve");
    const original = await lstat(target);
    for (const kind of ["regular", "symlink", "hardlink"]) {
      const state = join(dir, kind);
      await mkdir(state);
      const log = join(state, "serial.log");
      if (kind === "regular") await writeFile(log, "legacy");
      else if (kind === "symlink") await symlink(target, log);
      else await link(target, log);
      const result = spawnSync(
        "bash",
        [
          "-c",
          `set -euo pipefail
state=${JSON.stringify(state)}; tap=fake
prepare_network() { :; }
bounded_guest() { [[ "$1" == readiness ]]; }
sleep() { echo unexpected sleep >&2; return 1; }
nohup() { printf '%s\\0' "$@" > "$state/argv"; }
qemu_owner() { if [[ "$1" == capture ]]; then wait "$(<"$state/qemu.pid")"; fi; }
${start}
start_vm
`,
        ],
        { encoding: "utf8", timeout: 5_000 },
      );
      assert.equal(result.status, 0, result.stderr);
      const retained = await lstat(log);
      if (kind === "regular") assert.equal(await readFile(log, "utf8"), "legacy");
      if (kind === "hardlink") assert.equal(retained.ino, original.ino);
      const argv = (await readFile(join(state, "argv"), "utf8")).split("\0");
      assert.equal(argv[argv.indexOf("-serial") + 1], "null");
      assert.equal(await readFile(target, "utf8"), "preserve");
      assert.equal((await lstat(target)).ino, original.ino);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("owner stages propagate nested key and network failures through exact ERR rollback", async () => {
  const { spawnSync } = await import("node:child_process");
  const text = await readFile(driver, "utf8");
  const stages = ["owner_stage", "owner_stage_commit", "owner_stage_error", "arm_owner_errors", "disarm_owner_errors"]
    .map((name) => shellFunction(text, name))
    .join("\n");
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-stage-errors-"));
  try {
    for (const [mode, effect] of [
      [
        "keys",
        'prepare_keys() { ssh-keygen; printf continued >> "$CALLS"; }; ssh-keygen() { return 7; }; prepare_keys',
      ],
      [
        "network",
        'prepare_network() { network_policy > "$STATE/network.policy"; network_owner prepare; printf continued >> "$CALLS"; }; network_policy() { :; }; network_owner() { return 8; }; prepare_network',
      ],
    ] as const) {
      const calls = join(dir, `${mode}.calls`);
      await writeFile(calls, "");
      const result = spawnSync(
        "bash",
        [
          "-c",
          `set -euo pipefail
operation=create; owner_stage_key=; CALLS=${JSON.stringify(calls)}; STATE=${JSON.stringify(dir)}
generation_owner() { printf '%s %s\\n' "$1" "\${2:-}" >> "$CALLS"; }
rollback_create() { printf 'rollback\\n' >> "$CALLS"; }
${stages}
arm_owner_errors
owner_stage ${mode}
${effect}
owner_stage_commit
printf ready >> "$CALLS"`,
        ],
        { encoding: "utf8" },
      );
      assert.notEqual(result.status, 0, mode);
      assert.equal(await readFile(calls, "utf8"), `intent ${mode}\nfail ${mode}\nrollback\n`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("prepare_keys makes generated private and public keys generation-owner mode 0600", async () => {
  const { spawnSync } = await import("node:child_process");
  const source = shellFunction(await readFile(driver, "utf8"), "prepare_keys");
  const state = await mkdtemp(join(tmpdir(), "cogs-kvm-keys-"));
  try {
    const result = spawnSync(
      "bash",
      [
        "-c",
        `set -euo pipefail
state=${JSON.stringify(state)}; guest_ip=192.0.2.2
ssh-keygen() {
  local target=; while [[ $# -gt 0 ]]; do [[ $1 == -f ]] && { target=$2; shift 2; continue; }; shift; done
  printf private > "$target"; printf 'ssh-ed25519 AAAA generated\\n' > "$target.pub"; chmod 0600 "$target"; chmod 0644 "$target.pub"
}
${source}
prepare_keys`,
      ],
      { encoding: "utf8", timeout: 5_000 },
    );
    assert.equal(result.status, 0, result.stderr);
    for (const name of ["client_ed25519_key", "client_ed25519_key.pub", "host_ed25519_key", "host_ed25519_key.pub"])
      assert.equal((await lstat(join(state, "control", name))).mode & 0o777, 0o600, name);
  } finally {
    await rm(state, { recursive: true, force: true });
  }
});

test("cleanup wiring retains uncertainty, has no PID-number signaling or suppressed network failures", async () => {
  const text = await readFile(driver, "utf8");
  assert.doesNotMatch(text, /\bkill\b|remove_firewall|iptables -F/u);
  assert.match(text, /signal\.pidfd_send_signal\(fd,sig,None,0\)/u);
  assert.match(text, /fields\[19\]/u); // field 22 after removing pid and parenthesized comm
  assert.match(text, /exe\.st_dev, exe\.st_ino/u);
  assert.match(text, /\(proc\/'cmdline'\)\.read_bytes\(\)\.hex\(\)/u);
  const network = shellFunction(text, "network_owner");
  assert.doesNotMatch(network, /\|\| true|2>\/dev\/null/u);
  assert.ok(network.indexOf("value['pending']=True; save(value)") < network.indexOf("command(do,before)"));
  assert.match(text, /cleanup_partial\(\) \{\n {2}stop_vm && remove_network/u);
  assert.match(text, /no matching retained driver custody/u);
  const smoke = await readFile(join(root, "dev/linux-kvm/ci-smoke.sh"), "utf8");
  assert.doesNotMatch(smoke, /"\$driver" destroy[^\n]*\|\| true/u);
  assert.match(smoke, /smoke requires absent state/u);
  assert.doesNotMatch(smoke, /socat_pid|reuseaddr,fork|EXEC:\/bin\/true|TCP-LISTEN:18080/u);
  assert.match(smoke, /failures are diagnostic only and grant no firewall-enforcement evidence/u);
  assert.match(smoke, /'host_enforced_network':False/u);
  assert.doesNotMatch(
    smoke,
    /'host_enforced_network':result=='pass'|host TAP policy survived guest-firewall removal|denied non-proxy traffic/u,
  );
});

test("network command-boundary replacement cannot retarget ifindex deletion or an admitted writer", async () => {
  await ownerTest(
    "network",
    `
real_command=command
before=[['baseline'],[],[]]; after=[['baseline'],[{'ifindex':10}],[]]
world=copy.deepcopy(after); calls=[]
def snapshot(): return copy.deepcopy(world)
def reset(undo):
    global action,world
    action='remove'; world=copy.deepcopy(after); calls.clear()
    save({'phase':'owned','domain':domain_identity,'steps':[[undo,before,after]],'current':after})
def boundary(args,**kwargs):
    calls.append(args)
    # Supplied reproduction: replacement occurs INSIDE the actual command boundary.
    import socket,struct
    assert args[:3]==['python3','-I','-c'] and args[-1]=='10'
    assert kwargs['pass_fds']==(domain_fd,) # actual effect inherits domain exclusion
    class Netlink:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def settimeout(self,ms): pass
        def bind(self,address): pass
        def sendto(self,message,destination):
            assert destination==(0,0)
            world[1]=[{'ifindex':99}] # replacement at the kernel effect boundary
            assert struct.unpack_from('=IHH',message)==(32,17,5)
            assert struct.unpack_from('=i',message,20)[0]==10
        def recvfrom(self,size): return struct.pack('=IHHIIi',20,2,0,1,0,-19),(0,0)
    with patch.object(socket,'socket',lambda *args:Netlink()), patch.object(sys,'argv',['netlink','10']), \\
         patch.object(socket,'AF_NETLINK',16,create=True), patch.object(socket,'NETLINK_ROUTE',0,create=True):
        exec(args[3],{}) # actual packed RTM_DELLINK; kernel reports old index absent
with patch.object(subprocess,'check_output',boundary):
    reset(['ip','link','delete','dev',tap]); fails()
assert world[1]==[{'ifindex':99}] and len(calls)==1
assert json.loads(record.read_text())['pending'] and json.loads(record.read_text())['failed']
# Foreign rules arriving after outer observation but before adapter revalidation.
def command(args,expected=None):
    world[0]=['foreign rule']; return real_command(args,expected)
reset(['iptables','-w','5','-D','INPUT','-j',chain]); fails()
assert not calls and world[0]==['foreign rule']
# Every admitted network writer uses the SAME namespace-wide lock, including
# other checkouts. Attempt replacement inside subprocess, not before snapshot.
command=real_command
for undo in (['ip','link','delete','dev',tap],['iptables','-w','5','-D','INPUT','-j',chain]):
    def boundary(args,**kwargs):
        assert kwargs['pass_fds']==(domain_fd,)
        fd=os.open(state/'fake-domain',os.O_RDONLY)
        try:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: pass
            else: raise AssertionError('foreign writer admitted inside effect')
        finally: os.close(fd)
        world[:]=copy.deepcopy(before); calls.append(args); return ''
    with patch.object(subprocess,'check_output',boundary): reset(undo); invoke()
    assert len(calls)==1 and not json.loads(record.read_text())['steps']
reset(['iptables','-D','INPUT','-j',chain]); domain_identity=[1,99,'boot']; fails()
assert not calls # namespace replacement never adopts a retained journal
`,
  );
});

test("an effect's inherited domain descriptor excludes writers after its observer closes", async () => {
  await ownerTest(
    "network",
    `
fd=domain_lock()
# Local pipe-only child, not a network command or privileged operation.
with subprocess.Popen([sys.executable,'-I','-c','import sys; sys.stdin.buffer.read()'],
                      stdin=subprocess.PIPE,pass_fds=(fd,)) as child:
    os.close(fd) # observer retired; actual work still owns the same flock
    contender=os.open(state/'fake-domain',os.O_RDONLY)
    try:
        try: fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: pass
        else: raise AssertionError('released live effect exclusion')
        child.communicate(timeout=5)
        assert child.returncode==0
        fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally: os.close(contender)
`,
  );
});

test("network domain admission requires isolated namespace and trusted immutable root lease", async () => {
  await ownerTest(
    "network",
    `
from types import SimpleNamespace as S
ns=S(st_dev=1,st_ino=2); initial=S(st_dev=1,st_ino=1)
parent=S(st_mode=stat.S_IFDIR|0o755,st_uid=0)
lease=S(st_mode=stat.S_IFREG|0o444,st_uid=0,st_nlink=1,st_dev=3,st_ino=4,st_ctime_ns=5)
opened=[]; locked=[]; closed=[]
def open_lease(path,flags):
    opened.append((str(path),flags)); return 88
def stat_ns(path): return ns if path=='/proc/self/ns/net' else initial
with patch.object(os,'stat',stat_ns), patch.object(pathlib.Path,'lstat',lambda path:parent), \\
     patch.object(pathlib.Path,'read_text',lambda path:'boot'), patch.object(os,'open',open_lease), \\
     patch.object(os,'fstat',lambda fd:lease), patch.object(os,'read',lambda fd,size:b'cogs-exclusive-netns-v1 boot\\n'), \\
     patch.object(os,'close',closed.append), patch.object(fcntl,'flock',lambda fd,flags:locked.append((fd,flags))):
    assert real_domain_lock()==88 and locked==[(88,fcntl.LOCK_EX|fcntl.LOCK_NB)]
    assert domain_identity==[1,2,'boot',3,4,5]
    assert opened[0][0]=='/run/cogs-kvm-network-domain/1-2'
    assert opened[0][1] & os.O_NOFOLLOW and opened[0][1] & os.O_CLOEXEC
    for obj,field,bad in ((ns,'st_ino',1),(parent,'st_uid',1000),(parent,'st_mode',stat.S_IFLNK|0o777),
                          (lease,'st_uid',1000),(lease,'st_mode',stat.S_IFREG|0o644),(lease,'st_nlink',2)):
        old=getattr(obj,field); setattr(obj,field,bad)
        try: real_domain_lock()
        except RuntimeError: pass
        else: raise AssertionError('unsafe domain admitted')
        setattr(obj,field,old)
    assert closed==[88,88,88]
`,
  );
});

test("KVM generation owner binds exact private state and never adopts replacements", async () => {
  const { spawn, spawnSync } = await import("node:child_process");
  const source = shellFunction(await readFile(driver, "utf8"), "generation_owner");
  const program = source.split("<<'PY'\n")[1]?.split("\nPY\n")[0];
  assert.ok(program);
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-generation-"));
  const nonce = "a".repeat(32);
  const revision = "c".repeat(40);
  const invoke = (state: string, action: string, key = "", source = revision, locator = state) =>
    spawnSync("python3", ["-I", "-c", program, dir, state, action, nonce, key, source, "linux-kvm", locator], {
      encoding: "utf8",
    });
  try {
    const racing = join(dir, "racing");
    const race = (generation: string) =>
      new Promise<{ status: number | null }>((resolve) => {
        const child = spawn("python3", [
          "-I",
          "-c",
          program,
          dir,
          racing,
          "init",
          generation,
          "",
          revision,
          "linux-kvm",
          racing,
        ]);
        child.on("close", (status) => resolve({ status }));
      });
    const raceResults = await Promise.all([race(nonce), race("b".repeat(32))]);
    assert.deepEqual(raceResults.map(({ status }) => status).sort(), [0, 1]);
    assert.match(await readFile(join(racing, ".cogs-linux-kvm-v1"), "utf8"), /^(a{32}|b{32})\n$/u);

    const ambient = join(dir, "ambient");
    await writeFile(ambient, "competitor", { mode: 0o600 });
    assert.notEqual(invoke(ambient, "init").status, 0);
    assert.equal(await readFile(ambient, "utf8"), "competitor");

    const state = join(dir, "state");
    assert.equal(invoke(state, "init").status, 0);
    const sentinel = join(state, ".cogs-linux-kvm-v1");
    const sentinelInfo = await lstat(sentinel);
    assert.equal(await readFile(sentinel, "utf8"), `${nonce}\n`);
    assert.equal(sentinelInfo.mode & 0o777, 0o600);
    assert.equal(sentinelInfo.nlink, 1);
    if (process.getuid) assert.equal(sentinelInfo.uid, process.getuid());
    const owner = JSON.parse(await readFile(join(state, ".generation.owner"), "utf8"));
    const stateInfo = await lstat(state);
    assert.deepEqual(owner.directory, [stateInfo.dev, stateInfo.ino]);
    assert.equal(owner.profile, "linux-kvm");
    assert.equal(owner.sourceRevision, revision);
    assert.equal(owner.locator, state);
    assert.deepEqual(owner.keys, ["bootstrap"]);
    assert.notEqual(invoke(state, "check", "verify", "d".repeat(40)).status, 0);
    assert.notEqual(invoke(state, "check", "verify", revision, `${state}-other`).status, 0);

    assert.equal(invoke(state, "intent", "keys").status, 0);
    const owned = join(state, "control");
    await mkdir(owned, { mode: 0o700 });
    for (const name of ["client_ed25519_key", "client_ed25519_key.pub", "host_ed25519_key", "host_ed25519_key.pub"])
      await writeFile(join(owned, name), "secret", { mode: 0o600 });
    await writeFile(join(state, "known_hosts"), "host", { mode: 0o600 });
    assert.equal(invoke(state, "commit", "keys").status, 0);
    const replacement = join(state, "control/client_ed25519_key");
    const staged = join(dir, "replacement-key"); // Outside the inventoried state directory.
    await writeFile(staged, "foreign", { mode: 0o600, flag: "wx" });
    assert.notEqual((await lstat(staged)).ino, (await lstat(replacement)).ino);
    // Both inodes are live until atomic rename; inode ABA remains possible after unlink/recreate.
    await rename(staged, replacement);
    assert.notEqual(invoke(state, "intent", "retirement").status, 0);
    assert.notEqual(invoke(state, "remove").status, 0);
    assert.equal(await readFile(replacement, "utf8"), "foreign");
    assert.equal(JSON.parse(await readFile(join(state, ".generation.owner"), "utf8")).uncertain, true);

    for (const [name, mutate] of [
      ["wrong-nonce", async (path: string) => writeFile(join(path, ".cogs-linux-kvm-v1"), `${"b".repeat(32)}\n`)],
      ["extra-line", async (path: string) => writeFile(join(path, ".cogs-linux-kvm-v1"), `${nonce}\n\n`)],
      ["wrong-mode", async (path: string) => chmod(join(path, ".cogs-linux-kvm-v1"), 0o644)],
      [
        "hard-link",
        async (path: string) => {
          await link(join(path, ".cogs-linux-kvm-v1"), join(path, "sentinel-alias"));
        },
      ],
    ] as const) {
      const candidate = join(dir, name);
      assert.equal(invoke(candidate, "init").status, 0);
      await mutate(candidate);
      assert.notEqual(invoke(candidate, "check", "verify").status, 0, name);
    }

    for (const [name, mutation, finish] of [
      ["pending-extra", async (path: string) => writeFile(join(path, "foreign"), "x", { mode: 0o600 }), "fail"],
      ["commit-extra", async (path: string) => writeFile(join(path, "foreign"), "x", { mode: 0o600 }), "commit"],
      [
        "pending-replacement",
        async (path: string) => {
          const target = join(path, "qemu.owner"),
            staged = join(dir, "replacement-qemu-owner");
          await writeFile(staged, '{"phase":"never"}\n', { mode: 0o600, flag: "wx" });
          assert.notEqual((await lstat(staged)).ino, (await lstat(target)).ino);
          // Distinct live inode outside candidate; unlink/recreate inode ABA is not covered.
          await rename(staged, target);
        },
        "fail",
      ],
      ["disk-staging", async (path: string) => mkdir(join(path, "git-tools.staging"), { mode: 0o700 }), "fail"],
    ] as const) {
      const candidate = join(dir, name);
      assert.equal(invoke(candidate, "init").status, 0);
      assert.equal(invoke(candidate, "intent", name === "disk-staging" ? "disks" : "keys").status, 0);
      await mutation(candidate);
      assert.notEqual(invoke(candidate, finish, name === "disk-staging" ? "disks" : "keys").status, 0, name);
      const retained = JSON.parse(await readFile(join(candidate, ".generation.owner"), "utf8"));
      assert.equal(retained.uncertain, true);
      assert.deepEqual(retained.keys, ["bootstrap"]);
    }

    const partial = join(dir, "partial");
    assert.equal(invoke(partial, "init").status, 0);
    assert.equal(invoke(partial, "intent", "disks").status, 0);
    await writeFile(join(partial, "workspace.img"), "owned", { mode: 0o600 });
    assert.equal(invoke(partial, "fail", "disks").status, 0);
    assert.equal(invoke(partial, "intent", "retirement").status, 0);
    assert.equal(invoke(partial, "commit", "retirement").status, 0);
    assert.equal(invoke(partial, "intent", "removal").status, 0);
    assert.equal(invoke(partial, "remove").status, 0);
    await assert.rejects(lstat(partial), { code: "ENOENT" });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("KVM generation owner names missing, unexpected, wrong-kind, and wrong-mode fixed outputs", async () => {
  const { spawnSync } = await import("node:child_process");
  const source = shellFunction(await readFile(driver, "utf8"), "generation_owner");
  const program = source.split("<<'PY'\n")[1]?.split("\nPY\n")[0];
  assert.ok(program);
  const root = await mkdtemp(join(tmpdir(), "cogs-kvm-stage-output-"));
  const generation = "a".repeat(32),
    revision = "b".repeat(40);
  const invoke = (state: string, action: string, key = "") =>
    spawnSync("python3", ["-I", "-c", program, root, state, action, generation, key, revision, "linux-kvm", state], {
      encoding: "utf8",
    });
  try {
    for (const [name, mutate, diagnostic] of [
      ["missing", async (state: string) => rm(join(state, "known_hosts")), "missing stage output: known_hosts"],
      [
        "unexpected",
        async (state: string) => writeFile(join(state, "foreign"), "x", { mode: 0o600 }),
        "unexpected stage output path",
      ],
      [
        "kind",
        async (state: string) => {
          await rm(join(state, "known_hosts"));
          await mkdir(join(state, "known_hosts"), { mode: 0o700 });
        },
        "wrong stage output kind: known_hosts",
      ],
      [
        "mode",
        async (state: string) => chmod(join(state, "control", "host_ed25519_key.pub"), 0o644),
        "wrong stage output mode: control/host_ed25519_key.pub",
      ],
    ] as const) {
      const state = join(root, name);
      assert.equal(invoke(state, "init").status, 0);
      assert.equal(invoke(state, "intent", "keys").status, 0);
      await mkdir(join(state, "control"), { mode: 0o700 });
      for (const file of ["client_ed25519_key", "client_ed25519_key.pub", "host_ed25519_key", "host_ed25519_key.pub"])
        await writeFile(join(state, "control", file), "key", { mode: 0o600 });
      await writeFile(join(state, "known_hosts"), "host", { mode: 0o600 });
      await mutate(state);
      const result = invoke(state, "commit", "keys");
      assert.notEqual(result.status, 0, name);
      assert.match(result.stderr, new RegExp(diagnostic.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
      assert.equal(JSON.parse(await readFile(join(state, ".generation.owner"), "utf8")).uncertain, true);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("KVM receipts are generation-bound canonical closed schemas and smoke rejects extras or duplicates", async () => {
  const { spawnSync } = await import("node:child_process");
  const source = await readFile(driver, "utf8");
  const emitter = shellFunction(source, "emit_ready");
  assert.match(emitter, /bounded_guest "receipt-\$1"/u); // helper validates before JSON encoding
  const smoke = await readFile(join(root, "dev/linux-kvm/ci-smoke.sh"), "utf8");
  const parser = shellFunction(smoke, "exact_receipt");
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-receipt-"));
  try {
    const base = {
      status: "ready",
      profile: "linux-kvm",
      guest_root: true,
      kvm_enabled: true,
      distinct_boot_ids: true,
      guest_kernel: "6.12",
      guest_image_sha512: kvmImageSha,
      host_ip: "192.0.2.1",
      guest_ip: "192.0.2.2",
      proxy_port: 18080,
      generation: "b".repeat(32),
      command: "create",
    };
    for (const [name, raw, accepted] of [
      ["exact", `${JSON.stringify(base)}\n`, true],
      ["extra", `${JSON.stringify({ ...base, extra: true })}\n`, false],
      ["duplicate", `${JSON.stringify(base).replace("{", '{"status":"ready",')}\n`, false],
      ["two-lines", `${JSON.stringify(base)}\n\n`, false],
    ] as const) {
      const path = join(dir, name);
      await writeFile(path, raw);
      const result = spawnSync(
        "bash",
        [
          "-c",
          `set -euo pipefail; COGS_KVM_GENERATION=${"b".repeat(32)}; proxy_port=18080; ${parser}; exact_receipt ${JSON.stringify(path)} create`,
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status === 0, accepted, `${name}: ${result.stderr}`);
    }
    assert.match(smoke, /acquired=false[^\n]*\n {6}"\$driver" destroy/u);
    assert.match(smoke, /acquired=false[^\n]*\n"\$driver" destroy/u);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("smoke arms cleanup only from an exact create receipt and does not retry consumed destroy", async () => {
  const { spawnSync } = await import("node:child_process");
  const smoke = await readFile(join(root, "dev/linux-kvm/ci-smoke.sh"), "utf8");
  const exact = shellFunction(smoke, "exact_receipt");
  const ready = shellFunction(smoke, "run_ready");
  const cleanup = shellFunction(smoke, "cleanup");
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-smoke-authority-"));
  const fake = join(dir, "driver");
  await writeFile(
    fake,
    `#!/bin/bash
printf '%s\n' "$1" >> "$CALLS"
if [[ "$1" == create ]]; then
  printf competitor > "$AMBIENT"
  [[ "$MODE" != failed ]] || exit 1
  generation=$COGS_KVM_GENERATION
  [[ "$MODE" != stale ]] || generation=${"c".repeat(32)}
  printf '{"status":"ready","profile":"linux-kvm","guest_root":true,"kvm_enabled":true,"distinct_boot_ids":true,"guest_kernel":"6.12","guest_image_sha512":"${kvmImageSha}","host_ip":"192.0.2.1","guest_ip":"192.0.2.2","proxy_port":18080,"generation":"%s","command":"create"' "$generation"
  [[ "$MODE" != extra ]] || printf ',"extra":true'
  printf '}\\n'
else
  printf '{"profile":"linux-kvm","status":"destroyed","generation":"%s","command":"destroy"}\\n' "$COGS_KVM_GENERATION"
fi
`,
    { mode: 0o700 },
  );
  try {
    for (const mode of ["failed", "stale", "extra", "exact"]) {
      const calls = join(dir, `${mode}.calls`);
      const ambient = join(dir, `${mode}.ambient`);
      const result = spawnSync(
        "bash",
        [
          "-c",
          `set -uo pipefail
driver=${JSON.stringify(fake)}; proxy_port=18080; passed=false; acquired=false; helper_safe=true; boot_records=
write_report() { :; }
${exact}
${ready}
${cleanup}
trap cleanup EXIT
if run_ready create; then acquired=true; fi
exit 1`,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            MODE: mode,
            CALLS: calls,
            AMBIENT: ambient,
            COGS_KVM_GENERATION: "b".repeat(32),
          },
        },
      );
      assert.equal(result.status, 1, result.stderr);
      assert.equal(await readFile(ambient, "utf8"), "competitor");
      const operations = (await readFile(calls, "utf8")).trim().split("\n");
      assert.deepEqual(operations, mode === "exact" ? ["create", "destroy"] : ["create"]);
    }
    assert.match(smoke, /if \[\[ \$destroy_status -ne 0 \]\]; then[\s\S]*exit 1/u);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("smoke destroy failure cannot publish pass or retry after receipt/report failure", async () => {
  const { spawnSync } = await import("node:child_process");
  const smoke = await readFile(join(root, "dev/linux-kvm/ci-smoke.sh"), "utf8");
  // Execute the actual final path and EXIT owner; all external effects are fakes.
  const tail = smoke.slice(smoke.indexOf("destroy_receipt=$(mktemp)"));
  const cleanup = shellFunction(smoke, "cleanup");
  const exact = shellFunction(smoke, "exact_receipt");
  const dir = await mkdtemp(join(tmpdir(), "cogs-smoke-destroy-"));
  try {
    for (const entry of ["final", "exit"]) {
      for (const mode of ["success", "nonzero", "malformed"]) {
        for (const reportFailure of [false, true]) {
          const calls = join(dir, "calls");
          await writeFile(calls, "");
          const result = spawnSync(
            "bash",
            [
              "-c",
              `set -euo pipefail
passed=false; acquired=true; helper_safe=true; report=fake; proxy_port=18080
boot_records=$(mktemp -d); driver=fake_driver; COGS_KVM_GENERATION=${"b".repeat(32)}
fake_driver() {
  [[ "$1" == destroy && "$acquired" == false ]] || exit 99
  printf 'destroy\\n' >> "$CALLS"
  ${mode === "nonzero" ? "return 7" : mode === "malformed" ? "printf malformed" : `printf '{"profile":"linux-kvm","status":"destroyed","generation":"%s","command":"destroy"}\\n' "$COGS_KVM_GENERATION"`}
}
write_report() {
  printf '%s\\n' "$1" >> "$CALLS"
  ${reportFailure ? "return 8" : ":"}
}
${exact}
${cleanup}
trap cleanup EXIT
${entry === "final" ? tail : "exit 1"}`,
            ],
            {
              encoding: "utf8",
              timeout: 10_000,
              env: { ...process.env, CALLS: calls },
            },
          );
          const recorded = (await readFile(calls, "utf8")).trim().split("\n");
          assert.equal(recorded.filter((v) => v === "destroy").length, 1, result.stderr);
          assert.equal(result.status === 0, entry === "final" && mode === "success" && !reportFailure);
          if (mode !== "success" || entry === "exit") assert(!recorded.includes("pass"));
        }
      }
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("every KVM shell ingress denies before effects regardless of ambient workflow or nonce", async () => {
  const { spawnSync } = await import("node:child_process");
  const dir = await mkdtemp(join(tmpdir(), "cogs-kvm-denied-"));
  try {
    const calls = join(dir, "calls");
    const bin = join(dir, "bin");
    await mkdir(bin);
    // Even prerequisites, temp files and reporting are forbidden on denied paths.
    for (const tool of [
      "python3",
      "git",
      "dirname",
      "mkdir",
      "mktemp",
      "flock",
      "curl",
      "sudo",
      "ssh",
      "scp",
      "docker",
      "socat",
      "qemu-system-x86_64",
    ])
      await writeFile(join(bin, tool), '#!/bin/bash\nprintf effect >> "$CALLS"\nexit 99\n', { mode: 0o700 });
    const state = join(dir, "state");
    await mkdir(join(state, "control"), { recursive: true });
    for (const name of [".cogs-linux-kvm-v1", "known_hosts", "control/client_ed25519_key"])
      await writeFile(join(state, name), "invalid competitor", { mode: 0o600 });
    const paths: [string, string[]][] = [
      ["dev/linux-kvm/ci-smoke.sh", [join(dir, "report")]],
      ["dev/linux-kvm/qualify.sh", [join(dir, "report")]],
      ["test/egress-conformance/guest-probes/run-kvm-black-box-case.sh", []],
      ...["prepare-cache", "create", "verify", "reset", "destroy", "probe", "ssh"].map((op): [string, string[]] => [
        "dev/linux-kvm/driver.sh",
        [op, "boot-id"],
      ]),
    ];
    for (const event of ["schedule", "pull_request", "workflow_dispatch"]) {
      for (const [path, args] of paths) {
        const result = spawnSync("/bin/bash", [join(root, path), ...args], {
          encoding: "utf8",
          timeout: 5_000,
          env: {
            PATH: bin,
            CALLS: calls,
            GITHUB_EVENT_NAME: event,
            COGS_KVM_GENERATION: "a".repeat(32),
            COGS_SOURCE_REVISION: "b".repeat(40),
            COGS_KVM_STATE_DIR: state,
            COGS_KVM_EXECUTION_AUTHORIZATION: "true",
            COGS_SUITE_GUEST_PROXY: "http://192.0.2.1:18080",
            COGS_SUITE_TARGET_PORT: "443",
            COGS_SUITE_PUBLIC_CA: join(state, "known_hosts"),
            COGS_SUITE_CAPABILITY: "fake",
            COGS_SUITE_SCENARIO: "fake",
            COGS_SUITE_KIND: "https",
            COGS_SUITE_EXPECT: "deny",
          },
        });
        assert.equal(result.status, 1, `${path}: ${result.stderr}`);
        assert.match(result.stderr, /ADR0335|KVM execution receipt/u);
        assert.equal(result.stdout, "");
      }
    }
    await assert.rejects(lstat(calls), { code: "ENOENT" });
    await assert.rejects(lstat(join(dir, "report")), { code: "ENOENT" });
    assert.equal(await readFile(join(state, ".cogs-linux-kvm-v1"), "utf8"), "invalid competitor");
    const policy = spawnSync("bash", [driver, "print-network-policy"], { encoding: "utf8" });
    assert.equal(policy.status, 0, policy.stderr);
    assert.match(policy.stdout, /^\*filter\n/u);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Import the pure helper only. Portable faults run local Python children and
// Unix socket fixtures, never SSH, QEMU, Docker, network setup or the driver.
async function boundedTest(body: string) {
  const { spawnSync } = await import("node:child_process");
  const result = spawnSync(
    "python3",
    [
      "-B",
      "-I",
      "-c",
      `
import importlib.util,io,json,os,pathlib,select,signal,subprocess,sys,tempfile,threading,time
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('bounded',${JSON.stringify(boundedHelper)})
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
native_pidfd=h.Pidfd
def rejects(fn):
    try: fn()
    except (h.Rejected,UnicodeError,ValueError,OSError): pass
    else: raise AssertionError('fault accepted')
# macOS has no pidfds. A test-only kqueue observes the unreaped direct child;
# production still requires Linux pidfds before spawn, without a CLI override.
if sys.platform=='darwin':
    class PortableIdentity:
        @staticmethod
        def preflight(): pass
        def __init__(self,pid):
            self.pid=pid; self.done=False; self.queue=select.kqueue()
            try: self.queue.control([select.kevent(pid,filter=select.KQ_FILTER_PROC,flags=select.KQ_EV_ADD,fflags=select.KQ_NOTE_EXIT)],0,0)
            except ProcessLookupError: self.done=True
        def exited(self):
            self.done=self.done or bool(self.queue.control(None,1,0)); return self.done
        def kill(self):
            if not self.exited(): os.kill(self.pid,signal.SIGKILL)
        def close(self): self.queue.close()
    def portable_group_quiet(pgid):
        lines=subprocess.check_output(['/bin/ps','-axo','pgid=,stat='],timeout=1).splitlines()
        return all(int(parts[0])!=pgid or parts[1].startswith(b'Z') for line in lines if (parts:=line.split()))
    native_killpg=os.killpg
    def portable_killpg(pgid,sig):
        try: native_killpg(pgid,sig)
        except PermissionError:
            # Darwin reports EPERM for a group containing only zombies.
            if not portable_group_quiet(pgid): raise
    h.Pidfd=PortableIdentity; h.group_quiet=portable_group_quiet; h.os.killpg=portable_killpg
${body}
`,
    ],
    { encoding: "utf8", timeout: 30_000, maxBuffer: 128 * 1024 },
  );
  assert.equal(result.status, 0, result.stderr);
}

test("bounded KVM raw caps, simultaneous streams, EOF, deadlines and cancellation retire local children", async () => {
  await boundedTest(String.raw`
def run(program,cap=37,seconds=1):
    return h.bounded([sys.executable,'-I','-c',program],cap,seconds)
assert run("import os; os.write(1,b'x'*37)")== (0,b'x'*37)
assert run("import os; os.write(2,b'x'*4096)")== (0,b'')
for program in (
    "import os; os.write(1,b'x'*38)",
    "import os; os.write(2,b'x'*4097)",
    "import os; os.write(1,b'\\xff')",
    "import os; os.write(2,b'\\x00')",
    "import os; os.write(1,b'valid\\r\\n')",
    "import os; os.write(1,'é'.encode()*19)",
    "import os; os.write(1,b'x'*38); os.write(2,b'x'*4097)",
): rejects(lambda:run(program))
assert run('raise SystemExit(7)')==(7,b'')
# A single ignored TERM and silent stream cannot evade the absolute deadline.
started=time.monotonic()
rejects(lambda:run('import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(20)',seconds=.1))
assert time.monotonic()-started<4
# Leader exits, descendant inherits pipes OR closes them before sleeping.
for close in ('','os.close(1); os.close(2);'):
    program="import os,time,signal; pid=os.fork();\nif pid==0: "+close+"signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(20)\nelse: os._exit(0)"
    started=time.monotonic()
    if not close: rejects(lambda:run(program,seconds=.15))
    else: assert run(program)==(0,b'')
    assert time.monotonic()-started<4
# Cancellation latches through spawn/capture rather than losing child identity.
original=h.subprocess.Popen
children=[]
def spawn(*args,**kwargs):
    if args[0][0]=='/bin/ps': return original(*args,**kwargs) # portable census only
    assert kwargs['shell'] is False and kwargs['start_new_session'] is True
    assert kwargs['stdin']==subprocess.DEVNULL
    child=original(*args,**kwargs); children.append(child); h.cancelled=True; return child
with patch.object(h.subprocess,'Popen',spawn): rejects(lambda:run('import time; time.sleep(20)'))
assert children[0].returncode is not None
h.cancelled=False
# Admission of unsupported pidfds is effect-free.
with patch.object(h.Pidfd,'preflight',side_effect=h.Rejected), patch.object(h.subprocess,'Popen',side_effect=AssertionError):
    rejects(lambda:run('pass'))
`);
});

test("bounded KVM retirement retains pidfd/group identity through TERM/KILL, before any reap", async () => {
  await boundedTest(String.raw`
from types import SimpleNamespace as S
for fail in (False,True):
    events=[]; clock=[0.0]
    class Child:
        pid=42
        def wait(self,timeout): events.append('reap'); return 0
    class Held:
        def exited(self): return not fail
        def kill(self): events.append('pidfd-kill')
    def tick(): clock[0]+=.1; return clock[0]
    with patch.object(h.os,'killpg',lambda pid,sig:events.append((pid,sig))), \
         patch.object(h,'group_quiet',lambda pid:not fail), patch.object(h.time,'monotonic',tick), patch.object(h.time,'sleep',lambda _:None):
        if fail: rejects(lambda:h.retire(Child(),Held()))
        else: assert h.retire(Child(),Held())==0
    assert events[:2]==[(42,signal.SIGTERM),(42,signal.SIGKILL)]
    assert events[2:]==['pidfd-kill','reap']
# Held pidfd, not a potentially reused numeric PID, receives the final signal.
sent=[]
held=object.__new__(native_pidfd)
held.fd=88; held.exited=lambda:False
with patch.object(signal,'pidfd_send_signal',lambda fd,*args:sent.append(fd),create=True):
    held.kill()
assert sent==[88]
`);
});

test("bounded KVM fixed IDs validate exact identity bytes, host keys, canonical receipts and remote failures", async () => {
  await boundedTest(String.raw`
boot=b'00000000-0000-4000-8000-000000000001\n'
assert h.identity(boot,'boot-id')==boot[:-1].decode()
for raw in (boot[:-1],boot+b'\n',boot.replace(b'\n',b'\r\n'),boot+b'x',boot.replace(b'0',b'G'),b'\0'*37):
    rejects(lambda:h.identity(raw,'boot-id'))
for raw in (b'6.12\n',b'x'*64+b'\n'): assert h.identity(raw,'kernel')
for raw in (b'',b'\n',b'x'*65+b'\n',b'6.12\nextra\n',b'6.12\r\n',b'6.12\0\n',b'\xff\n'):
    rejects(lambda:h.identity(raw,'kernel'))
for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":Infinity}',b'\xff'):
    rejects(lambda:h.exact_json(raw))
state=pathlib.Path('/safe'); nonce='a'*32; calls=[]
def bounded(argv,cap=16384,seconds=15,deadline=None):
    calls.append((argv,cap,seconds,deadline)); assert argv[0]=='/usr/bin/ssh'
    assert argv[-2]=='root@192.0.2.2' and 'IdentityAgent=none' in argv
    return 0,boot if argv[-1]==h.PROBES['boot-id'] else b'6.12.95-amd64\n' if argv[-1]=='uname -r' else b''
with patch.object(h,'bounded',bounded), patch.object(h,'read_control',lambda *args:(nonce+'\n').encode()), \
     patch('builtins.open',lambda *args:io.BytesIO(boot.replace(b'001',b'002'))):
    for name in h.PROBES: h.guest(state,name,'18080')
    for command in ('create','verify','reset'):
        value=h.execute('receipt-'+command,state,nonce,'18080')
        raw=h.canonical(value)
        assert raw==json.dumps(value,separators=(',',':')).encode()+b'\n'
        assert value['generation']==nonce and value['command']==command and value['distinct_boot_ids'] is True
    before=len(calls)
    for name,token,port in (('arbitrary',nonce,'18080'),('root','b','18080'),('root',nonce,'1;id'),('root',nonce,'65536')):
        rejects(lambda:h.execute(name,state,token,port))
    assert len(calls)==before
assert any(cap==37 for _,cap,_,_ in calls) and any(cap==65 for _,cap,_,_ in calls)
for code,raw in ((255,b''),(1,b''),(-15,b''),(0,boot+b'\n')):
    with patch.object(h,'bounded',return_value=(code,raw)):
        rejects(lambda:h.guest(state,'boot-id','18080'))
# Readiness retries ONLY key exchange without a remote command, under one bound.
scans=[]; guests=[]; clock=[0.0]
def scan(state,end): scans.append(end); clock[0]+=4; return len(scans)==3
with patch.object(h,'host_key',scan), patch.object(h,'guest',lambda *args:guests.append(args)), \
     patch.object(h,'read_control',return_value=(nonce+'\n').encode()), \
     patch.object(h.time,'monotonic',lambda:clock[0]), patch.object(h.time,'sleep',lambda _:None):
    h.execute('readiness',state,nonce,'18080')
assert scans==[120,120,120] and guests==[(state,'ready','18080',120)]
key=b'192.0.2.2 ssh-ed25519 YWJj\n'
with patch.object(h,'read_control',return_value=key):
    for code,raw in ((0,key),(1,b''),(0,key+key),(0,key+b'\n'),(0,key.replace(b'YWJj',b'eA=='))):
        with patch.object(h,'bounded',return_value=(code,raw)):
            if raw==key: assert h.host_key(state)
            elif code==1: assert h.host_key(state) is False
            else: rejects(lambda:h.host_key(state))
`);
});

test("QMP bounds raw line/aggregate/message count, trickle deadlines, malformed responses and short writes", async () => {
  await boundedTest(String.raw`
# Deterministic nonblocking socket faults use the actual parser/deadline logic.
greeting=b'{"QMP":{}}\r\n'; caps=b'{"return":{},"id":"caps"}\r\n'; answer=b'{"return":{"present":true,"enabled":true},"id":"kvm"}\r\n'
for mode in ('ok','cap','total','count','duplicate','incomplete','trickle','caps-error','false','boolean-int','wrong-id','utf8'):
    clock=[0.0]; writes=[]
    event=b'{"event":"tick"}\n'
    response=greeting+caps+answer
    if mode=='cap': response=b'x'*8193
    if mode=='total': response=greeting+caps+(b'{"event":"'+b'x'*8000+b'"}\n')*5+answer
    if mode=='count': response=greeting+caps+event*31+answer
    if mode=='duplicate': response=greeting+caps+answer.replace(b'"present":true',b'"present":false,"present":true')
    if mode=='incomplete': response=greeting+caps+answer[:-2]
    if mode=='caps-error': response=greeting+b'{"error":{},"id":"caps"}\n'+answer
    if mode=='false': response=response.replace(b'"enabled":true',b'"enabled":false')
    if mode=='boolean-int': response=response.replace(b'"enabled":true',b'"enabled":1')
    if mode=='wrong-id': response=response.replace(b'"id":"kvm"',b'"id":"other"')
    if mode=='utf8': response=b'{"QMP":"\xff"}\n'
    pending=bytearray(response)
    class Socket:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def setblocking(self,value): assert value is False
        def connect_ex(self,path): return 0
        def getsockopt(self,*args): return 0
        def send(self,raw): writes.append(raw[:2]); return min(2,len(raw))
        def recv(self,size):
            if mode=='trickle': clock[0]+=.2; return b' '
            result=bytes(pending[:min(size,47)]); del pending[:len(result)]; return result
    class Selector:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def register(self,*args): pass
        def modify(self,*args): pass
        def select(self,timeout): return [True]
    with patch.object(h.socket,'socket',lambda *args:Socket()), patch.object(h.selectors,'DefaultSelector',Selector), \
         patch.object(h.time,'monotonic',lambda:clock[0]):
        if mode=='ok': h.query_kvm('/fixture')
        else: rejects(lambda:h.query_kvm('/fixture'))
    if mode=='ok': assert b''.join(writes)==b'{"execute":"qmp_capabilities","id":"caps"}\n{"execute":"query-kvm","id":"kvm"}\n'
`);
});

test("QMP portable Unix-socket observations handle fragmented actual reads and incomplete EOF", async () => {
  await boundedTest(String.raw`
import socket
for incomplete in (False,True):
    with tempfile.TemporaryDirectory(prefix='qmp-',dir='/tmp') as directory:
        path=directory+'/q'; server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(path); server.listen(1); server.settimeout(2); errors=[]
        def serve():
            try:
                with server.accept()[0] as client:
                    client.settimeout(2)
                    for part in (b'{"Q',b'MP":{}}\r',b'\n'): client.sendall(part)
                    with client.makefile('rb') as stream:
                        assert stream.readline(129)==b'{"execute":"qmp_capabilities","id":"caps"}\n'
                        client.sendall(b'{"return":{},"id":"caps"}\r\n')
                        assert stream.readline(129)==b'{"execute":"query-kvm","id":"kvm"}\n'
                        client.sendall(b'{"return":{"present":true,"enabled":true},"id":"kvm"}'+(b'' if incomplete else b'\r\n'))
            except BaseException as error: errors.append(error)
        thread=threading.Thread(target=serve); thread.start()
        try:
            if incomplete: rejects(lambda:h.query_kvm(path))
            else: h.query_kvm(path)
        finally:
            thread.join(3); server.close()
        assert not thread.is_alive() and not errors,errors
`);
});

test("helper CLI cannot discover custody from a sentinel, and uncertain local retirement is distinct", async () => {
  await boundedTest(String.raw`
# Direct CLI denial precedes even lock/custody observation, for every fixed ID.
with patch.object(h,'require_driver',side_effect=AssertionError('custody reached')), \
     patch.object(h,'execute',side_effect=AssertionError('effect reached')):
    for name in h.IDS:
        with patch.object(sys,'argv',['bounded',name,'/safe','a'*32,'18080']): assert h.main()==1
with patch.object(h.os,'fstat',side_effect=OSError), patch.object(h.subprocess,'Popen',side_effect=AssertionError), \
     patch.object(sys,'argv',['bounded','root','/safe','a'*32,'18080']):
    assert h.main()==1
# Primitive local retirement failures become exit 2, not settled guest failure.
with patch.object(h,'require_local_execution'), patch.object(h,'require_driver'), patch.object(h,'execute',side_effect=h.RetirementUncertain), \
     patch.object(sys,'argv',['bounded','root','/safe','a'*32,'18080']):
    assert h.main()==2
native_retire=h.retire
children=[]; original=h.subprocess.Popen
def spawn(*args,**kwargs):
    child=original(*args,**kwargs)
    if args[0][0]!='/bin/ps': children.append(child)
    return child
def fail_after_retirement(child,held):
    native_retire(child,held); raise OSError('lost proof')
with patch.object(h.subprocess,'Popen',spawn), patch.object(h,'retire',fail_after_retirement):
    try: h.bounded([sys.executable,'-I','-c','pass'])
    except h.RetirementUncertain: pass
    else: raise AssertionError('local uncertainty erased')
assert children[0].returncode==0
# Real control-file no-follow and raw caps; no helper mutates the sentinel.
with tempfile.TemporaryDirectory() as directory:
    target=pathlib.Path(directory)/'token'; target.write_bytes(b'a'*32+b'\n'); target.chmod(0o600)
    assert h.read_control(target,33)==b'a'*32+b'\n'
    alias=target.with_name('alias'); alias.symlink_to(target)
    rejects(lambda:h.read_control(alias,33))
    target.write_bytes(b'a'*33+b'\n'); rejects(lambda:h.read_control(target,33))
    assert target.read_bytes()==b'a'*33+b'\n'
`);
});

test("driver fixed-ID custody fails closed across helper failure, lost completion and foreign generation", async () => {
  const { spawnSync } = await import("node:child_process");
  const source = await readFile(driver, "utf8");
  const functions = ["generation_owner", "bounded_guest"].map((name) => shellFunction(source, name)).join("\n");
  const dir = await mkdtemp(join(tmpdir(), "cogs-guest-custody-"));
  try {
    await mkdir(join(dir, ".cogs-dev"), { mode: 0o700 });
    for (const mode of ["success", "failure", "uncertain", "killed", "lost", "foreign"] as const) {
      const state = join(dir, ".cogs-dev", mode);
      const program = `set -euo pipefail; umask 077
repo=${JSON.stringify(dir)}; state=${JSON.stringify(state)}; source_revision=${"c".repeat(40)}; generation=${"a".repeat(32)}; proxy_port=18080
${functions}
generation_owner init
python3() {
 if [[ "$2" == */bounded-command.py ]]; then
   [[ "$3" == root && "$4" == "$state" && "$5" == "$generation" && "$6" == 18080 ]] || exit 9
   ${mode === "failure" ? "return 1" : mode === "uncertain" ? "return 2" : mode === "killed" ? "return 137" : ":"}
 else command python3 "$@"; fi
}
${mode === "lost" ? "generation_owner guest-start root" : mode === "foreign" ? `generation=${"b".repeat(32)}; bounded_guest root` : "bounded_guest root"}
`;
      const result = spawnSync("bash", ["-c", program], { encoding: "utf8", timeout: 10_000 });
      assert.equal(result.status === 0, mode === "success" || mode === "lost", result.stderr);
      const custody = JSON.parse(await readFile(join(state, ".generation.owner"), "utf8"));
      assert.equal(custody.generation, "a".repeat(32));
      assert.equal(custody.guest, ["lost", "uncertain", "killed"].includes(mode) ? "root" : null);
      assert.equal(custody.failed, mode === "failure");
      const check = spawnSync(
        "bash",
        ["-c", `${program.slice(0, program.indexOf("generation_owner init"))}generation_owner check verify`],
        { encoding: "utf8" },
      );
      assert.equal(check.status === 0, mode === "success" || mode === "foreign");
      if (mode === "failure") {
        const cleanup = spawnSync(
          "bash",
          ["-c", `${program.slice(0, program.indexOf("generation_owner init"))}generation_owner check destroy`],
          { encoding: "utf8" },
        );
        assert.equal(cleanup.status, 0, cleanup.stderr); // cleanup-only, no adoption
      }
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  const smoke = await readFile(join(root, "dev/linux-kvm/ci-smoke.sh"), "utf8");
  const harness = await readFile(join(root, "test/egress-conformance/stage3-real-runtime/harness.ts"), "utf8");
  assert.doesNotMatch(source, /run_ssh|ssh_args|ssh-keyscan|^ {2}ssh\)/mu);
  assert.match(source, /generation_owner guest-start[\s\S]*bounded-command\.py[\s\S]*generation_owner guest-done/u);
  for (const command of ["create", "reset"]) {
    // Receipt bytes are provisional until zero exit; failed unlock never grants
    // an unlocked rollback permission to mutate the generation afterwards.
    assert.ok(source.includes(`emit_ready ${command}\n    disarm_owner_errors\n    release_lock`));
  }
  assert.doesNotMatch(smoke, /"\$driver" ssh|! "\$driver" probe|\$\("\$driver" probe/u);
  assert.doesNotMatch(harness, /run-kvm-black-box-case|execFileAsync\(driver/u);
  assert.match(harness, /unmigrated KVM conformance acquisition is not admitted/u);
});

test("socat single-child owner retains pidfd through reuse, failures and TERM/KILL retirement", async () => {
  const { spawnSync } = await import("node:child_process");
  const text = shellFunction(await readFile(join(root, "dev/linux-kvm/ci-smoke.sh"), "utf8"), "proxy_probe");
  const program = text.split("<<'PY'\n")[1]?.split("\nPY\n")[0];
  assert.ok(program);
  const result = spawnSync(
    "python3",
    [
      "-c",
      `
import contextlib,io,os,select,signal,subprocess,sys,time
from unittest.mock import patch
from types import SimpleNamespace as S
program=${JSON.stringify(program)}
sys.argv=['probe','/fake-driver','19090']
for mode in ('success','early-exit','kill','timeout','probe-fail','signal','pidfd-fail','exit-failure'):
    calls=[]; signals=[]; waits=[]; closed=[]; stdout=io.StringIO(); dead=False
    class Child:
        pid=42
        def kill(self): signals.append('unreaped-child')
        def wait(self,timeout):
            waits.append(timeout); return 1 if mode=='exit-failure' else 0
    def spawn(args,**kwargs):
        assert args==['socat','TCP-LISTEN:19090,bind=0.0.0.0,reuseaddr','OPEN:/dev/null']
        return Child()
    def pidfd(pid,flags):
        assert pid==42 and not waits
        if mode=='pidfd-fail': raise OSError('unsupported')
        return 88
    def send(fd,sig,*args):
        global dead
        assert fd==88 # fake numeric PID now reused; only held generation is targeted
        signals.append(sig)
        if mode!='timeout' and (mode!='kill' or sig==signal.SIGKILL): dead=True
    class Poll:
        def register(self,fd,event): assert fd==88
        def poll(self,ms): return [1] if dead or mode=='early-exit' else []
    def probe(args,**kwargs):
        calls.append(args); assert args==['/fake-driver','probe','proxy-connect'] and kwargs['timeout']==45
        if mode=='signal': raise RuntimeError('interrupted')
        return S(returncode=1 if mode=='probe-fail' else 0)
    with patch.object(subprocess,'Popen',spawn), patch.object(subprocess,'run',probe), \\
         patch.object(os,'pidfd_open',pidfd,create=True), patch.object(os,'close',closed.append), \\
         patch.object(signal,'pidfd_send_signal',send,create=True), patch.object(select,'poll',Poll), \\
         patch.object(signal,'signal',lambda *args:None), patch.object(signal,'pthread_sigmask',lambda *args:set()), \\
         patch.object(time,'sleep',lambda *args:None), contextlib.redirect_stdout(stdout):
        try: exec(program)
        except (RuntimeError,OSError): assert mode not in ('success','kill')
        else: assert mode in ('success','kill')
    assert stdout.getvalue()==('' if mode=='timeout' else 'retired\\n')
    assert bool(waits)==(mode!='timeout')
    if mode=='kill': assert signals==[signal.SIGTERM,signal.SIGKILL]
    if mode=='early-exit': assert not signals and not calls
    if mode!='pidfd-fail': assert closed==[88]
`,
    ],
    { encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

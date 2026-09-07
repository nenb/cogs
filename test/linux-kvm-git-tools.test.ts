import assert from "node:assert/strict";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const gitTools = join(root, "dev/linux-kvm/git-tools.sh");
const driver = join(root, "dev/linux-kvm/driver.sh");

async function sourceGitTools(command: string, env: Record<string, string> = {}) {
  const { spawnSync } = await import("node:child_process");
  return spawnSync("bash", ["-c", `set -euo pipefail; source ${JSON.stringify(gitTools)}; ${command}`], {
    cwd: root,
    env: { ...process.env, ...env },
    encoding: "utf8",
    timeout: 10_000,
  });
}

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
  const text = await readFile(driver, "utf8");
  assert.match(text, /source "\$repo\/dev\/linux-kvm\/git-tools\.sh"/u);
  assert.match(text, /prepare_git_tools_disk "\$state" "\$cache"/u);
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
  assert.match(workflow, /path: docs\/security-evidence\/generated\//u);
  assert.doesNotMatch(workflow, /git-tools\.img|\.deb|COGS_KVM_CACHE_DIR/u);
  assert.match(workflow, /dev\/linux-kvm\/ci-smoke\.sh/u);
  assert.match(workflow, /dev\/linux-kvm\/driver\.sh create/u);
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
  assert.equal(text.match(/serial\.log/gu)?.length, 1);
  assert.ok(start.indexOf('rm -f "$state/qmp.sock" "$state/serial.log"') < start.indexOf("  nohup "));
  assert.match(start, /qemu_owner capture[\s\S]*run_ssh true/u);
  const routes = text.slice(text.indexOf('case "$operation" in'));
  assert.match(routes, /create\)[\s\S]*prepare_seed; start_vm; verify/u);
  assert.match(routes, /reset\)[\s\S]*stop_vm; remove_network[\s\S]*prepare_seed; start_vm/u);
  assert.match(routes, /cleanup_partial && rm -rf "\$state"/u);
  assert.match(routes, /stop_vm; remove_network; rm -rf "\$state"/u);
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

test("fake launch unlinks legacy serial files without following symlink or hardlink targets", async () => {
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
run_ssh() { :; }
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
      await assert.rejects(lstat(log), { code: "ENOENT" });
      const argv = (await readFile(join(state, "argv"), "utf8")).split("\0");
      assert.equal(argv[argv.indexOf("-serial") + 1], "null");
      assert.equal(await readFile(target, "utf8"), "preserve");
      assert.equal((await lstat(target)).ino, original.ino);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
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
  assert.match(text, /no retained driver custody; absence is not teardown proof/u);
  const smoke = await readFile(join(root, "dev/linux-kvm/ci-smoke.sh"), "utf8");
  assert.doesNotMatch(smoke, /"\$driver" destroy[^\n]*\|\| true/u);
  assert.match(smoke, /smoke requires absent state/u);
  assert.doesNotMatch(smoke, /socat_pid|reuseaddr,fork|EXEC:\/bin\/true|TCP-LISTEN:18080/u);
  assert.match(smoke, /failures are diagnostic only and grant no firewall-enforcement evidence/u);
  assert.doesNotMatch(smoke, /host TAP policy survived guest-firewall removal|denied non-proxy traffic/u);
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

test("smoke competitor and mismatched receipt never confer cleanup; successful nonce does", async () => {
  const { spawnSync } = await import("node:child_process");
  const smoke = await readFile(join(root, "dev/linux-kvm/ci-smoke.sh"), "utf8");
  const acquisition = smoke.slice(smoke.indexOf('receipt=$("$driver" create)'), smoke.indexOf('"$driver" verify'));
  const dir = await mkdtemp(join(tmpdir(), "cogs-smoke-race-"));
  try {
    for (const mode of ["competitor", "wrong-receipt", "owned", "retired", "helper-uncertain"]) {
      const fake = join(dir, "driver");
      await writeFile(
        fake,
        `#!/bin/bash
if [[ "$1" == create ]]; then
  printf foreign > "$COGS_KVM_STATE_DIR"
  [[ "$MODE" != competitor ]] || exit 1
  nonce=$COGS_KVM_GENERATION
  [[ "$MODE" != wrong-receipt ]] || nonce=foreign
  printf '{"status":"ready","profile":"linux-kvm","generation":"%s"}\\n' "$nonce"
else
  printf '%s' "$COGS_KVM_GENERATION" > "$COGS_KVM_STATE_DIR.destroyed"
fi
`,
        { mode: 0o700 },
      );
      const state = join(dir, mode);
      const result = spawnSync(
        "bash",
        [
          "-c",
          `set -euo pipefail
state=$COGS_KVM_STATE_DIR; driver=${JSON.stringify(fake)}
passed=false; acquired=false; helper_safe=true
write_report() { :; }
${shellFunction(smoke, "cleanup")}
trap cleanup EXIT
${acquisition}
[[ "$MODE" != retired ]] || acquired=false
[[ "$MODE" != helper-uncertain ]] || helper_safe=false
exit 1
`,
        ],
        {
          encoding: "utf8",
          env: { ...process.env, MODE: mode, COGS_KVM_STATE_DIR: state, COGS_KVM_GENERATION: "a".repeat(32) },
        },
      );
      assert.equal(result.status, 1, result.stderr);
      assert.equal(await readFile(state, "utf8"), "foreign");
      if (mode === "owned") assert.equal(await readFile(`${state}.destroyed`, "utf8"), "a".repeat(32));
      else await assert.rejects(lstat(`${state}.destroyed`), { code: "ENOENT" });
    }
    const text = await readFile(driver, "utf8");
    const gate = text.slice(text.indexOf("generation=${COGS_KVM_GENERATION"), text.indexOf("ssh_args()"));
    const sentinel = join(dir, "sentinel");
    await writeFile(sentinel, "b".repeat(32));
    for (const operation of ["destroy", "reset", "verify", "ssh"]) {
      const result = spawnSync(
        "bash",
        ["-c", `set -eu; operation=${operation}; sentinel=${JSON.stringify(sentinel)}; ${gate}`],
        {
          encoding: "utf8",
          env: { ...process.env, COGS_KVM_GENERATION: "a".repeat(32) },
        },
      );
      assert.equal(result.status, 1);
      assert.match(result.stderr, /generation mismatch/u);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("KVM nonce receipts preserve the exact launcher schema when custody was not requested", async () => {
  const { spawnSync } = await import("node:child_process");
  const { normalizeDriverResult } = await import("../dev/launcher/contract.ts");
  const source = await readFile(driver, "utf8");
  const receipt = source.slice(
    source.indexOf("  # Preserve the launcher's exact legacy result schema"),
    source.indexOf('\ncase "$operation" in'),
  );
  for (const nonce of ["", "a".repeat(32)]) {
    const result = spawnSync(
      "bash",
      [
        "-c",
        `set -euo pipefail
COGS_KVM_GENERATION=${JSON.stringify(nonce)}; generation=${JSON.stringify(nonce)}
guest_kernel=6.12.95+deb13-amd64; image_sha512=${"a".repeat(128)}
host_ip=192.0.2.1; guest_ip=192.0.2.2; proxy_port=18080
receipt() {
${receipt}
receipt
`,
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    if (nonce) assert.equal(JSON.parse(result.stdout).generation, nonce);
    else assert.equal(normalizeDriverResult(result.stdout, "linux-kvm", "create").result, "ready");
  }
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
        calls.append(args); assert '/19090' in args[-1]
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

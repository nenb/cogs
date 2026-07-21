import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
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
  assert.ok(text.includes("! find /opt/cogs-git -xdev \\( ! -uid 0 -o ! -gid 0 -o -perm /0022"));
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

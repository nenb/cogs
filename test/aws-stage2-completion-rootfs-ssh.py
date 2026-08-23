#!/usr/bin/env python3
"""Portable policy checks and an opt-in no-KVM generated-rootfs SSH test."""
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_rootfs_plan as plan

BASE_SHADOW = b"""root:*:20627:0:99999:7:::
daemon:*:20627:0:99999:7:::
bin:*:20627:0:99999:7:::
sys:*:20627:0:99999:7:::
sync:*:20627:0:99999:7:::
games:*:20627:0:99999:7:::
man:*:20627:0:99999:7:::
lp:*:20627:0:99999:7:::
mail:*:20627:0:99999:7:::
news:*:20627:0:99999:7:::
uucp:*:20627:0:99999:7:::
proxy:*:20627:0:99999:7:::
www-data:*:20627:0:99999:7:::
backup:*:20627:0:99999:7:::
list:*:20627:0:99999:7:::
irc:*:20627:0:99999:7:::
_apt:*:20627:0:99999:7:::
nobody:*:20627:0:99999:7:::
"""
FINAL_ROOT = b"root:x:20627:0:99999:7:::"
FIXED_TAR = Path("/var/lib/cogs/stage2-completion-v1/accepted/rootfs.tar")


def reject(call):
    try:
        call()
    except BaseException:
        return
    raise AssertionError("hostile rootfs SSH policy accepted")


def directives(raw):
    result = {}
    for raw_line in raw.decode("ascii").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split(None, 1)
        lowered = key.lower()
        if lowered in result:
            raise AssertionError("duplicate sshd directive")
        result[lowered] = value
    return result


def portable():
    assert len(BASE_SHADOW) == plan._ACCOUNT_EXPECTED["etc/shadow"].archive_size
    assert hashlib.sha256(BASE_SHADOW).hexdigest() == plan._ACCOUNT_EXPECTED["etc/shadow"].content_sha256
    assert BASE_SHADOW.splitlines()[0] == plan._ROOT_SHADOW_SOURCE
    result = plan._account_result("etc/shadow", BASE_SHADOW)
    lines = result.splitlines()
    assert lines[0] == FINAL_ROOT == plan._ROOT_SHADOW_RESULT
    assert lines[-1] == plan._ACCOUNT_LINES["etc/shadow"].rstrip(b"\n")
    assert len(lines) == 19 and sum(line.startswith(b"root:") for line in lines) == 1
    password = lines[0].split(b":")[1]
    assert password == b"x" == plan._ROOT_SHADOW_PASSWORD
    assert password and password[:1] not in {b"!", b"*"} and not password.startswith(b"$")
    # A one-byte value cannot equal a 13-byte traditional crypt result, while
    # every supported modern crypt format is a modular `$...` string.
    assert len(password) == 1

    for hostile in (
        BASE_SHADOW.replace(b"root:*:", b"root:!:", 1),
        BASE_SHADOW.replace(b"root:*:", b"root:x:", 1),
        BASE_SHADOW.replace(plan._ROOT_SHADOW_SOURCE + b"\n", b"", 1),
        BASE_SHADOW + plan._ROOT_SHADOW_SOURCE + b"\n",
        BASE_SHADOW.rstrip(b"\n"),
    ):
        reject(lambda hostile=hostile: plan._account_result("etc/shadow", hostile))

    config = directives(plan._SSHD_CONFIG)
    required = {
        "permitrootlogin": "prohibit-password",
        "pubkeyauthentication": "yes",
        "authenticationmethods": "publickey",
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no",
        "permitemptypasswords": "no",
        "usepam": "no",
        "allowusers": "root",
        "authorizedkeysfile": "/run/cogs-stage2-ssh/authorized_keys",
    }
    assert all(config.get(key) == value for key, value in required.items())
    assert config["strictmodes"] == "yes" and config["disableforwarding"] == "yes"
    assert "challengeresponseauthentication" not in config
    assert not any(value.lower() == "yes" for key, value in config.items()
                   if key in {"passwordauthentication", "kbdinteractiveauthentication", "usepam"})
    for hostile_key, hostile_value in (
        ("passwordauthentication", "yes"),
        ("kbdinteractiveauthentication", "yes"),
        ("usepam", "yes"),
        ("permitrootlogin", "yes"),
        ("authenticationmethods", "publickey,password"),
    ):
        hostile = dict(config)
        hostile[hostile_key] = hostile_value
        assert not all(hostile.get(key) == value for key, value in required.items())
    print("completion rootfs SSH portable policy tests passed")


def tool(name, candidates):
    found = shutil.which(name)
    if found not in candidates:
        raise RuntimeError("fixed Linux SSH test tool unavailable")
    return found


def checked(command, **values):
    return subprocess.run(command, check=True, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **values)


def write_file(path, raw, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def extract_fixed_rootfs(rootfs, pins):
    raw = FIXED_TAR.read_bytes()
    assert len(raw) == pins["ustar"]["size"]
    assert hashlib.sha256(raw).hexdigest() == pins["ustar"]["sha256"]
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        assert len(members) == pins["entry_count"] + 1 and members[0].name == "."
        for member in members:
            parts = Path(member.name).parts
            assert not member.name.startswith("/") and ".." not in parts
            assert member.isdir() or member.isreg() or member.issym() or member.islnk()
        archive.extractall(rootfs, filter="fully_trusted")


def keygen(executable, path):
    checked((executable, "-q", "-t", "ed25519", "-N", "", "-f", str(path)))


def client_argv(ssh, client, known_hosts):
    return (
        ssh, "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none", "-o", "PasswordAuthentication=no", "-o",
        "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes", "-o",
        f"UserKnownHostsFile={known_hosts}", "-o", "ConnectionAttempts=1", "-o",
        "ConnectTimeout=5", "-o", "ClearAllForwardings=yes", "-i", str(client),
        "root@192.0.2.2", "/bin/true",
    )


def linux_no_kvm():
    if (os.environ.get("COGS_REQUIRE_STAGE2_ROOTFS_SSH_LINUX") != "1"
            or sys.platform != "linux" or platform.machine() != "x86_64" or os.geteuid() != 0):
        raise RuntimeError("exact no-KVM rootfs SSH admission required")
    pins = json.loads((REMOTE / "stage2-completion-rootfs-v2.json").read_bytes())
    ssh = tool("ssh", ("/usr/bin/ssh",))
    keygen_executable = tool("ssh-keygen", ("/usr/bin/ssh-keygen",))
    chroot = tool("chroot", ("/usr/sbin/chroot", "/usr/bin/chroot"))
    ip = tool("ip", ("/usr/sbin/ip", "/usr/bin/ip"))
    with tempfile.TemporaryDirectory(prefix="cogs-rootfs-ssh-") as temporary:
        temporary_path = Path(temporary)
        rootfs = temporary_path / "rootfs"
        rootfs.mkdir(mode=0o700)
        extract_fixed_rootfs(rootfs, pins)
        shadow = (rootfs / "etc/shadow").read_bytes().splitlines()
        assert shadow[0] == FINAL_ROOT and shadow[-1] == b"sshd:!:0:0:99999:7:::"
        assert (rootfs / "etc/ssh/sshd_config").read_bytes() == plan._SSHD_CONFIG

        client = temporary_path / "client"
        wrong = temporary_path / "wrong"
        server = rootfs / "run/cogs-stage2-ssh/ssh_host_ed25519_key"
        keygen(keygen_executable, client)
        keygen(keygen_executable, wrong)
        keygen(keygen_executable, server)
        public = (client.parent / (client.name + ".pub")).read_bytes().split(None, 2)[:2]
        write_file(rootfs / "run/cogs-stage2-ssh/authorized_keys", b"restrict " + b" ".join(public) + b"\n", 0o400)
        server_public = (server.parent / (server.name + ".pub")).read_bytes().split(None, 2)[:2]
        known_hosts = temporary_path / "known_hosts"
        write_file(known_hosts, b"192.0.2.2 " + b" ".join(server_public) + b"\n", 0o400)

        device_root = rootfs / "dev"
        for name, device in (("null", os.makedev(1, 3)), ("zero", os.makedev(1, 5)),
                             ("random", os.makedev(1, 8)), ("urandom", os.makedev(1, 9))):
            path = device_root / name
            if not path.exists():
                os.mknod(path, stat.S_IFCHR | 0o666, device)

        config_test = checked((chroot, str(rootfs), "/usr/sbin/sshd", "-T", "-f",
                               "/etc/ssh/sshd_config", "-C",
                               "user=root,host=192.0.2.2,addr=192.0.2.1"), text=True)
        effective = directives(config_test.stdout.encode())
        assert effective["usepam"] == "no"
        assert effective["passwordauthentication"] == "no"
        assert effective["kbdinteractiveauthentication"] == "no"
        assert effective["pubkeyauthentication"] == "yes"
        assert effective["authenticationmethods"] == "publickey"
        assert effective["permitrootlogin"] in {"prohibit-password", "without-password"}

        if ctypes.CDLL(None, use_errno=True).unshare(0x40000000) != 0:
            raise OSError(ctypes.get_errno(), "unshare(CLONE_NEWNET)")
        checked((ip, "link", "set", "lo", "up"))
        checked((ip, "address", "add", "192.0.2.2/32", "dev", "lo"))
        server_process = subprocess.Popen(
            (chroot, str(rootfs), "/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while True:
                if server_process.poll() is not None:
                    raise AssertionError("generated rootfs sshd exited before readiness")
                try:
                    with socket.create_connection(("192.0.2.2", 22), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("generated rootfs sshd readiness timeout")
                    time.sleep(0.05)
            success = subprocess.run(client_argv(ssh, client, known_hosts), stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            assert success.returncode == 0
            bad_key = subprocess.run(client_argv(ssh, wrong, known_hosts), stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            assert bad_key.returncode != 0
            disabled = subprocess.run(
                (ssh, "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o",
                 "PubkeyAuthentication=no", "-o",
                 "PreferredAuthentications=password,keyboard-interactive", "-o",
                 "NumberOfPasswordPrompts=0", "-o", "StrictHostKeyChecking=yes", "-o",
                 f"UserKnownHostsFile={known_hosts}", "root@192.0.2.2", "/bin/true"),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            assert disabled.returncode != 0
        finally:
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
                server_process.wait(timeout=5)
            if server_process.stderr is not None:
                server_process.stderr.close()
    print("completion generated rootfs no-KVM SSH authentication test passed")


if sys.argv[1:] == []:
    portable()
elif sys.argv[1:] == ["--linux"]:
    linux_no_kvm()
else:
    raise SystemExit("usage: aws-stage2-completion-rootfs-ssh.py [--linux]")

#!/usr/bin/env python3
"""Pure hostile matrix and guarded Linux fixed-input owner qualification."""
import ast
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import tempfile
import time
import zlib

if sys.flags.optimize:
    raise RuntimeError("input tests refuse Python optimization")
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
import completion_kata_inputs as inputs
import completion_rootfs_fs as fs


def rejected(function):
    try:
        function()
    except BaseException:
        return
    raise AssertionError("hostile input case accepted")


def ssh_string(raw):
    return struct.pack(">I", len(raw)) + raw


def synthetic_key(seed_hex, public_hex, comment):
    # Fixed RFC 8032 vectors: standard-library encoding, no external keygen.
    seed = bytes.fromhex(seed_hex)
    public = bytes.fromhex(public_hex)
    private = seed + public
    blob = ssh_string(b"ssh-ed25519") + ssh_string(public)
    row = b"ssh-ed25519 " + base64.b64encode(blob) + b" " + comment + b"\n"
    inner = struct.pack(">II", 0x12345678, 0x12345678)
    inner += ssh_string(b"ssh-ed25519") + ssh_string(public) + ssh_string(private) + ssh_string(comment)
    padding = 8 - len(inner) % 8
    inner += bytes(range(1, padding + 1))
    outer = b"openssh-key-v1\0" + ssh_string(b"none") + ssh_string(b"none") + ssh_string(b"")
    outer += struct.pack(">I", 1) + ssh_string(blob) + ssh_string(inner)
    encoded = base64.b64encode(outer)
    lines = [encoded[index:index + 70] for index in range(0, len(encoded), 70)]
    pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"\n".join(lines)
    pem += b"\n-----END OPENSSH PRIVATE KEY-----\n"
    return pem, row, public


client_private, client_public, client_raw = synthetic_key(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    inputs.CLIENT_COMMENT,
)
server_private, server_public, server_raw = synthetic_key(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6e2e1a72f4f",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    inputs.SERVER_COMMENT,
)
material = inputs.KeyMaterial(client_private, client_public, server_private, server_public)
assert inputs._validate_key_material(material) == material
assert client_raw != server_raw

# The test issuer accepts only these exact approved RFC vectors. A canonical
# private key with a changed seed and the old advertised public half is denied.
altered_private, altered_public, _altered_raw = synthetic_key(
    "9c61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    inputs.CLIENT_COMMENT,
)
altered = inputs.KeyMaterial(altered_private, altered_public, server_private, server_public)
assert inputs._validate_key_material(altered) == altered
old_testing = os.environ.get("COGS_KATA_INPUTS_TESTING_V1")
try:
    os.environ["COGS_KATA_INPUTS_TESTING_V1"] = "1"
    assert inputs._make_test_key_grant(material) is not None
    rejected(lambda: inputs._make_test_key_grant(altered))
finally:
    if old_testing is None:
        os.environ.pop("COGS_KATA_INPUTS_TESTING_V1", None)
    else:
        os.environ["COGS_KATA_INPUTS_TESTING_V1"] = old_testing

# Every public/private field is structurally bound, bounded, and role-specific.
for hostile in (
    inputs.KeyMaterial(client_private, client_public, client_private, client_public.replace(inputs.CLIENT_COMMENT, inputs.SERVER_COMMENT)),
    inputs.KeyMaterial(client_private, client_public.replace(b"ssh-ed25519", b"ssh-rsa", 1), server_private, server_public),
    inputs.KeyMaterial(client_private, client_public.replace(b" ", b"  ", 1), server_private, server_public),
    inputs.KeyMaterial(client_private[:-1], client_public, server_private, server_public),
    inputs.KeyMaterial(client_private.replace(b"A", b"B", 1), client_public, server_private, server_public),
    inputs.KeyMaterial(b"x" * (inputs.MAX_PRIVATE + 1), client_public, server_private, server_public),
):
    rejected(lambda hostile=hostile: inputs._validate_key_material(hostile))

# The fixture graph is deterministic and is an independently usable bare repo.
graph = inputs._expected_graph(material)
assert graph == inputs._expected_graph(material)
assert graph[0] == inputs.ExpectedEntry(".", "directory", 0o700, None)
assert len(graph) > 1_000 and len({item.path for item in graph}) == len(graph)
by_path = {item.path: item for item in graph}
assert by_path[inputs.CLIENT_KEY].mode == 0o400
assert by_path[inputs.SERVER_KEY].mode == 0o400
assert by_path[inputs.AUTHORIZED_KEYS].content == b"restrict " + client_public
assert by_path[inputs.KNOWN_HOSTS].content.startswith(inputs.SSH_ALIAS + b" ssh-ed25519 ")
assert by_path["share/fixture/git.git/HEAD"].content == b"ref: refs/heads/main\n"
assert by_path["share/fixture/git.git/config"].content == (
    b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"
)
ref = by_path["share/fixture/git.git/refs/heads/main"].content.strip().decode()
assert ref == "ca429a94b73caea0fc39164b8087cc1c63f43818"
loose = [item for item in graph if "/objects/" in item.path and item.kind == "file"]
assert len(loose) == 515
for item in loose:
    oid = item.path.rsplit("/", 2)[-2] + item.path.rsplit("/", 1)[-1]
    framed = zlib.decompress(item.content)
    assert hashlib.sha1(framed, usedforsecurity=False).hexdigest() == oid
    kind_size, payload = framed.split(b"\0", 1)
    kind, size = kind_size.split(b" ")
    assert kind in {b"blob", b"tree", b"commit"} and int(size) == len(payload)
# Independent canonical pin: this test does not call the owner's digest helper.
fixture_rows = [{
    "kind": item.kind, "mode": item.mode, "path": item.path,
    "sha256": None if item.content is None else hashlib.sha256(item.content).hexdigest(),
    "size": 0 if item.content is None else len(item.content),
} for item in inputs._FIXED_FIXTURE]
fixture_pin = hashlib.sha256(json.dumps(
    fixture_rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
).encode() + b"\n").hexdigest()
assert inputs.FIXTURE_SUBTREE_SHA256 == "33aafa9c8a0629ee4d708eb692d9231cf2713244046a00409ea45da6f6c722d7"
assert fixture_pin == inputs.FIXTURE_SUBTREE_SHA256
object_frame = bytearray()
for item in inputs._FIXED_FIXTURE:
    if "/objects/" in item.path and item.kind == "file":
        encoded_path = item.path.encode()
        object_frame += len(encoded_path).to_bytes(4, "big") + encoded_path
        object_frame += len(item.content).to_bytes(8, "big") + item.content
assert inputs.COMPRESSED_OBJECTS_SHA256 == "f5c9e0477c73c0a9099566b5a15c5b9721cb8743557b51c3acde11098611300e"
assert hashlib.sha256(object_frame).hexdigest() == inputs.COMPRESSED_OBJECTS_SHA256

package_records = [item for item in graph if item.path.startswith("share/fixture/package/")]
assert len(package_records) == 261
assert by_path["share/fixture/package/DEBIAN/control"].content.startswith(b"Package: cogs-stage2-fixture\n")
assert all(item.mode == (0o555 if item.kind == "directory" else 0o444) for item in package_records)

# Canonical operation-specific manifest excludes itself; identity is supplied separately.
identities = {
    item.path: fs.HostKey(1, 2, index + 10, item.kind)
    for index, item in enumerate(graph)
}
manifest = inputs._manifest_bytes("a" * 64, graph, identities)
parsed = inputs._parse_manifest(manifest, "a" * 64)
assert parsed["operation_token"] == "a" * 64
assert len(parsed["entries"]) == len(graph)
assert inputs.MANIFEST_NAME.text not in {row["path"] for row in parsed["entries"]}
assert manifest == json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
for hostile in (
    manifest[:-1], manifest.replace(b'"version"', b'"version" ', 1),
    manifest.replace(b'"mode":448', b'"mode":true', 1),
    manifest.replace(b'"operation_token":"' + b"a" * 64, b'"operation_token":"' + b"b" * 64, 1),
    manifest.replace(b'{', b'{"version":"duplicate",', 1),
):
    rejected(lambda hostile=hostile: inputs._parse_manifest(hostile, "a" * 64))

# Mountinfo parsing is complete and rejects the source itself or a nested mount.
mountinfo = (
    b"20 1 8:1 / / rw,relatime - ext4 /dev/root rw\n"
    b"21 20 0:5 / /proc rw,nosuid - proc proc rw\n"
)
assert inputs._parse_mountinfo(mountinfo, "/fixed/input") == 2
for hostile in (
    mountinfo + b"22 20 8:1 /x /fixed/input rw - ext4 /dev/root rw\n",
    mountinfo + b"22 20 8:1 /x /fixed/input/fixture rw - ext4 /dev/root rw\n",
    mountinfo + b"22 20 8:1 /fixed/input/key /elsewhere rw - ext4 /dev/root rw\n",
    mountinfo.replace(b"/proc", b"/bad\\777"),
    mountinfo + mountinfo.splitlines(keepends=True)[0],
    b"x" * (inputs.MAX_MOUNTINFO + 1) + b"\n",
):
    rejected(lambda hostile=hostile: inputs._parse_mountinfo(hostile, "/fixed/input"))

# Capabilities are registry identities, not duck-typed lookalikes, and there is
# no production operation or process issuer in this module.
source_path = REMOTE / "completion_kata_inputs.py"
source = source_path.read_text()
module_tree = ast.parse(source)
assert "InputPermit" in source and "KeyMaterialGrant" in source
for forbidden in ("os.walk", "rmtree", "glob", "subprocess", "socket", "ssh-keygen", "keyscan", "if __name__"):
    assert forbidden not in source
for name in ("create_fixed_inputs", "remove_fixed_inputs", "InputPermit", "KeyMaterialGrant"):
    assert not hasattr(inputs, name)
for exported in (inputs._create_fixed_inputs_test_local, inputs._verify_fixed_inputs_test_local,
                 inputs._remove_fixed_inputs_test_local):
    assert callable(exported)
rejected(lambda: inputs._create_fixed_inputs_test_local(object(), object(), object(), object()))

# The one close aggregator is leaf-to-root, non-short-circuiting, and retains
# the primary plus every per-fd close failure.
close_fds = [fs.CheckedFd(os.open(os.devnull, os.O_RDONLY), f"close-{index}") for index in range(3)]
close_numbers = [item.number for item in close_fds]
close_calls = []
real_os_close = fs.os.close
try:
    def fail_every_close(number):
        close_calls.append(number)
        raise OSError(f"close-{number}")
    fs.os.close = fail_every_close
    primary = RuntimeError("primary")
    try:
        inputs._close_owned(tuple(close_fds), primary)
    except inputs.CloseUncertainError as error:
        assert error.primary is primary and len(error.close_errors) == 3
        assert all(type(item) is fs.RootfsFsError and item.close_error is not None
                   for item in error.close_errors)
    else:
        raise AssertionError("close uncertainty was not raised")
    assert close_calls == close_numbers
    assert all(item.disposition == "uncertain" for item in close_fds)
finally:
    fs.os.close = real_os_close
    for number in close_numbers:
        real_os_close(number)


def held_directory(path, control):
    identity = fs.CheckedFd(os.open(path, fs.IDENTITY_FLAGS), "input-test-identity")
    operation = fs.CheckedFd(os.open(path, fs.DIRECTORY_FLAGS), "input-test-directory")
    return fs.HeldNode(identity, operation, fs._observe_node(identity, operation, control))


def require_docker_environment():
    if os.environ.get("COGS_KATA_INPUTS_DOCKER_V1") != "1":
        return

    def require(condition):
        if not condition:
            raise RuntimeError("unsafe Kata-input Docker functional environment")

    require(platform.system() == "Linux" and os.geteuid() == 0 and Path("/.dockerenv").is_file())
    require(ROOT == Path("/repo") and Path("/work").is_dir() and Path("/cogs-private").is_dir())
    rows = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]

    def mount(path):
        matches = [row for row in rows if row[4] == path and "-" in row]
        require(len(matches) == 1)
        return matches[0], matches[0].index("-")

    repo, _repo_separator = mount("/repo")
    work, work_separator = mount("/work")
    private, _private_separator = mount("/cogs-private")
    require("ro" in repo[5].split(",") and "ro" in private[5].split(","))
    require(work[work_separator + 1] == "tmpfs")
    require({"rw", "nosuid", "nodev", "noexec"} <= set(work[5].split(",")))
    work_stat = Path("/work").stat(follow_symlinks=False)
    require(stat.S_ISDIR(work_stat.st_mode) and stat.S_IMODE(work_stat.st_mode) == 0o700)
    require(work_stat.st_uid == work_stat.st_gid == 0 and work_stat.st_dev != Path("/").stat().st_dev)
    sentinel = Path("/cogs-private/.cogs-kata-inputs-docker-v1")
    sentinel_stat = sentinel.stat(follow_symlinks=False)
    require(stat.S_ISREG(sentinel_stat.st_mode) and stat.S_IMODE(sentinel_stat.st_mode) == 0o400)
    require(sentinel_stat.st_uid == sentinel_stat.st_gid == 0 and sentinel_stat.st_nlink == 1)
    require(sentinel.read_bytes() == b"cogs-kata-inputs-docker-v1\n")
    require(tuple(path.name for path in Path("/cogs-private").iterdir()) == (sentinel.name,))
    print("NONAUTHORITATIVE Docker filesystem functional harness constraints proved")


def linux_functional():
    required = os.environ.get("COGS_RUN_KATA_INPUTS_LINUX_V1") == "1"
    qualified = platform.system() == "Linux" and os.geteuid() == 0
    if not required:
        print("completion Kata inputs Linux functional matrix SKIPPED (guard closed)")
        return
    assert qualified, "guarded input qualification requires Linux EUID 0"
    require_docker_environment()
    os.environ["COGS_KATA_INPUTS_TESTING_V1"] = "1"
    control = fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False)
    temporary_parent = os.environ.get("COGS_KATA_INPUTS_TMPDIR", "/tmp")
    with tempfile.TemporaryDirectory(dir=temporary_parent, prefix="cogs-kata-inputs-") as temporary:
        os.chmod(temporary, 0o700)
        completion_path = Path(temporary) / "completion"
        completion_path.mkdir(mode=0o700)
        completion = held_directory(completion_path, control)
        try:
            key_grant = inputs._make_test_key_grant(material)
            operation_grant = inputs._make_test_operation_grant("a" * 64)
            inputs._bind_test_operation_grant(operation_grant, key_grant)

            def create():
                return inputs._create_fixed_inputs_test_local(
                    completion, operation_grant, key_grant, control,
                )

            # Intent with absence and a durably recorded exact key resume.
            # A fault after mkdir or parent fsync is tested below as uncertain.
            directory_targets = ["after-directory-intent:.", "after-directory-settle:."]
            real_checkpoint = inputs._checkpoint
            try:
                def directory_fault(current_control, label):
                    current_control.check()
                    if directory_targets and label == directory_targets[0]:
                        directory_targets.pop(0)
                        raise OSError("directory boundary " + label)
                inputs._checkpoint = directory_fault
                while directory_targets:
                    before = len(directory_targets)
                    rejected(create)
                    assert len(directory_targets) == before - 1
            finally:
                inputs._checkpoint = real_checkpoint

            # Fail before and after anonymous identity acquisition and while
            # observing its mount ID; the same operation/key grant resumes.
            real_open_fd, real_mount_id = fs._open_fd, fs._mount_id
            tripped = {"before": False, "mount": False}
            try:
                def open_identity_fault(path, flags, role, current_control, dir_fd=None):
                    if role == "kata-input-anonymous-identity" and not tripped["before"]:
                        tripped["before"] = True
                        raise OSError("before anonymous identity")
                    return real_open_fd(path, flags, role, current_control, dir_fd)
                fs._open_fd = open_identity_fault
                rejected(create)
                fs._open_fd = real_open_fd

                def mount_fault(descriptor, current_control, expected_flags=None):
                    if descriptor.role == "kata-input-anonymous" and not tripped["mount"]:
                        tripped["mount"] = True
                        raise OSError("anonymous mount observation")
                    return real_mount_id(descriptor, current_control, expected_flags)
                fs._mount_id = mount_fault
                rejected(create)
            finally:
                fs._open_fd, fs._mount_id = real_open_fd, real_mount_id
            assert tripped == {"before": True, "mount": True}

            first_file = inputs.CLIENT_KEY
            targets = [
                "after-anonymous-identity:" + first_file,
                "after-file-intent:" + first_file, "after-link:" + first_file,
                "after-file-parent-fsync:" + first_file,
                "after-directory-chmod:.", "after-directory-fsync:.",
                "after-directory-reobserve:.",
                "after-file-intent:@manifest", "after-link:@manifest",
                "after-file-parent-fsync:@manifest",
            ]
            real_checkpoint = inputs._checkpoint
            try:
                def create_fault(current_control, label):
                    current_control.check()
                    if targets and label == targets[0]:
                        targets.pop(0)
                        raise OSError("create boundary " + label)
                inputs._checkpoint = create_fault
                while targets:
                    before = len(targets)
                    rejected(create)
                    assert len(targets) == before - 1
            finally:
                inputs._checkpoint = real_checkpoint

            created = create()
            assert created == create()  # complete is idempotently resumable
            assert created == inputs._verify_fixed_inputs_test_local(completion, operation_grant, control)
            assert created.entry_count == len(graph)

            detach = inputs._make_test_detach_grant(operation_grant)
            ordered = sorted((item for item in graph if item.path != "."),
                             key=lambda item: (item.path.count("/"), item.path.encode()), reverse=True)
            first_path = ordered[0].path
            first_directory = next(item.path for item in ordered if item.kind == "directory")
            remove_targets = [
                "after-remove-manifest-preflight",
                "after-remove-intent:" + first_path,
                "after-unlink:" + first_path,
                "after-remove-parent-fsync:" + first_path,
                "after-remove-absence-settle:" + first_path,
                "after-rmdir:" + first_directory,
                "after-remove-intent:.", "after-rmdir:.",
                "after-remove-parent-fsync:.", "after-remove-absence-settle:.",
            ]
            real_checkpoint = inputs._checkpoint
            try:
                def remove_fault(current_control, label):
                    current_control.check()
                    if remove_targets and label == remove_targets[0]:
                        remove_targets.pop(0)
                        raise OSError("remove boundary " + label)
                inputs._checkpoint = remove_fault
                while remove_targets:
                    before = len(remove_targets)
                    try:
                        inputs._remove_fixed_inputs_test_local(
                            completion, operation_grant, detach, control,
                        )
                    except BaseException:
                        if len(remove_targets) != before - 1:
                            raise
                    else:
                        raise AssertionError("remove fault was not observed")
            finally:
                inputs._checkpoint = real_checkpoint
            removed = inputs._remove_fixed_inputs_test_local(completion, operation_grant, detach, control)
            assert removed == created and not (completion_path / inputs.INPUT_NAME.text).exists()
            assert inputs._remove_fixed_inputs_test_local(
                completion, operation_grant, detach, control,
            ) == removed

            # mkdir success without a recorded exact identity is uncertain even
            # if parent fsync completed. Retry preserves and cannot adopt it.
            for index, boundary in enumerate(("after-mkdir:.", "after-directory-parent-fsync:.")):
                uncertain_key = inputs._make_test_key_grant(material)
                uncertain_operation = inputs._make_test_operation_grant(("d" if index == 0 else "e") * 64)
                inputs._bind_test_operation_grant(uncertain_operation, uncertain_key)
                real_checkpoint = inputs._checkpoint
                tripped = False
                try:
                    def uncertain_fault(current_control, label):
                        nonlocal tripped
                        current_control.check()
                        if not tripped and label == boundary:
                            tripped = True
                            raise OSError("uncertain directory boundary " + label)
                    inputs._checkpoint = uncertain_fault
                    rejected(lambda: inputs._create_fixed_inputs_test_local(
                        completion, uncertain_operation, uncertain_key, control,
                    ))
                finally:
                    inputs._checkpoint = real_checkpoint
                uncertain_root = completion_path / inputs.INPUT_NAME.text
                identity_before = uncertain_root.stat(follow_symlinks=False)
                rejected(lambda: inputs._create_fixed_inputs_test_local(
                    completion, uncertain_operation, uncertain_key, control,
                ))
                identity_after = uncertain_root.stat(follow_symlinks=False)
                assert tripped and (identity_after.st_dev, identity_after.st_ino) == (
                    identity_before.st_dev, identity_before.st_ino,
                )
                uncertain_root.rmdir()

            # A named root without a durable operation identity is preserved.
            hostile = completion_path / inputs.INPUT_NAME.text
            hostile.mkdir(mode=0o700)
            next_key = inputs._make_test_key_grant(material)
            next_operation = inputs._make_test_operation_grant("b" * 64)
            inputs._bind_test_operation_grant(next_operation, next_key)
            rejected(lambda: inputs._create_fixed_inputs_test_local(
                completion, next_operation, next_key, control,
            ))
            assert hostile.is_dir()
            hostile.rmdir()

            # Hostile graph mutations are rejected without modifying the
            # unknown/replaced object. Restorable cases share one exact graph.
            hostile_key = inputs._make_test_key_grant(material)
            hostile_operation = inputs._make_test_operation_grant("c" * 64)
            inputs._bind_test_operation_grant(hostile_operation, hostile_key)
            inputs._create_fixed_inputs_test_local(
                completion, hostile_operation, hostile_key, control,
            )
            owned_root = completion_path / inputs.INPUT_NAME.text
            verify_hostile = lambda: inputs._verify_fixed_inputs_test_local(
                completion, hostile_operation, control,
            )
            hostile_detach = inputs._make_test_detach_grant(hostile_operation)

            def reject_hostile():
                rejected(verify_hostile)
                rejected(lambda: inputs._remove_fixed_inputs_test_local(
                    completion, hostile_operation, hostile_detach, control,
                ))

            extra = owned_root / "unknown"
            extra.write_bytes(b"preserve\n")
            reject_hostile()
            assert extra.read_bytes() == b"preserve\n"
            extra.unlink()

            symlink = owned_root / "unknown-link"
            symlink.symlink_to("private")
            reject_hostile()
            assert symlink.is_symlink()
            symlink.unlink()

            hardlink = owned_root / "unknown-hardlink"
            os.link(owned_root / inputs.CLIENT_KEY, hardlink)
            reject_hostile()
            assert hardlink.stat().st_nlink == 2
            hardlink.unlink()

            os.setxattr(owned_root, b"user.cogs-hostile", b"preserve")
            reject_hostile()
            assert os.getxattr(owned_root, b"user.cogs-hostile") == b"preserve"
            os.removexattr(owned_root, b"user.cogs-hostile")

            changed_mode = owned_root / inputs.SERVER_KEY
            changed_mode.chmod(0o600)
            reject_hostile()
            assert changed_mode.stat().st_mode & 0o777 == 0o600
            changed_mode.chmod(0o400)

            manifest_path = owned_root / inputs.MANIFEST_NAME.text
            os.chown(manifest_path, 1, 1)
            reject_hostile()
            assert manifest_path.stat().st_uid == 1
            os.chown(manifest_path, 0, 0)
            os.chown(owned_root, 1, 1)
            reject_hostile()
            assert owned_root.stat().st_uid == 1
            os.chown(owned_root, 0, 0)

            mountpoint = owned_root / "share/fixture/package"
            library = ctypes.CDLL(None, use_errno=True)
            mounted = library.mount(b"tmpfs", os.fsencode(mountpoint), b"tmpfs",
                                    2 | 4 | 8, b"size=4096,mode=0555") == 0
            assert mounted, os.strerror(ctypes.get_errno())
            try:
                reject_hostile()
                assert os.path.ismount(mountpoint)
            finally:
                assert library.umount2(os.fsencode(mountpoint), 0) == 0

            replacement = owned_root / inputs.CLIENT_KEY
            replacement.unlink()
            replacement.write_bytes(b"hostile replacement\n")
            replacement.chmod(0o400)
            reject_hostile()
            assert replacement.read_bytes() == b"hostile replacement\n"

            # Route-level close failures poison operation and detach grants.
            # The exact CloseUncertainError is replayed; retry cannot succeed.
            def fail_one_close(route):
                real_close = fs.os.close
                failed_numbers = []
                result = None
                try:
                    def close_fault(number):
                        if not failed_numbers:
                            failed_numbers.append(number)
                            raise OSError("route per-fd close uncertainty")
                        return real_close(number)
                    fs.os.close = close_fault
                    try:
                        route()
                    except inputs.CloseUncertainError as error:
                        assert len(error.close_errors) == 1
                        result = error
                    else:
                        raise AssertionError("route close uncertainty was not raised")
                finally:
                    fs.os.close = real_close
                    for number in failed_numbers:
                        real_close(number)
                return result

            remove_path = Path(temporary) / "remove-close-completion"
            remove_path.mkdir(mode=0o700)
            remove_completion = held_directory(remove_path, control)
            try:
                remove_key = inputs._make_test_key_grant(material)
                remove_operation = inputs._make_test_operation_grant("8" * 64)
                inputs._bind_test_operation_grant(remove_operation, remove_key)
                inputs._create_fixed_inputs_test_local(
                    remove_completion, remove_operation, remove_key, control,
                )
                remove_detach = inputs._make_test_detach_grant(remove_operation)
                remove_route = lambda: inputs._remove_fixed_inputs_test_local(
                    remove_completion, remove_operation, remove_detach, control,
                )
                remove_error = fail_one_close(remove_route)
                assert (remove_path / inputs.INPUT_NAME.text).is_dir()
                try:
                    remove_route()
                except inputs.CloseUncertainError as retry_error:
                    assert retry_error is remove_error
                else:
                    raise AssertionError("poisoned remove route succeeded")
            finally:
                fs._close_node(remove_completion)

            create_path = Path(temporary) / "create-close-completion"
            create_path.mkdir(mode=0o700)
            create_completion = held_directory(create_path, control)
            try:
                close_key = inputs._make_test_key_grant(material)
                close_operation = inputs._make_test_operation_grant("9" * 64)
                inputs._bind_test_operation_grant(close_operation, close_key)
                create_route = lambda: inputs._create_fixed_inputs_test_local(
                    create_completion, close_operation, close_key, control,
                )
                create_error = fail_one_close(create_route)
                try:
                    create_route()
                except inputs.CloseUncertainError as retry_error:
                    assert retry_error is create_error
                else:
                    raise AssertionError("poisoned create route succeeded")
            finally:
                fs._close_node(create_completion)
        finally:
            fs._close_node(completion)
    print("completion Kata inputs LINUX EUID-0 FUNCTIONAL matrix passed")


linux_functional()
print("completion Kata input/control owner foundation matrix passed")

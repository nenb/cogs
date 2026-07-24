#!/usr/bin/env python3
"""Strict pin and publication-boundary tests."""

import hashlib
import ctypes
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fs = load("completion_rootfs_fs", REMOTE / "completion_rootfs_fs.py")
publish = load("completion_rootfs_publish", REMOTE / "completion_rootfs_publish.py")
raw = (REMOTE / "stage2-completion-rootfs-v1.json").read_bytes()
pins = publish._parse_pins(raw)
assert pins.entry_count == 4353
assert pins.manifest_size == 1049443 and pins.ustar_size == 136905728
assert publish._load_pins() == pins
for hostile in (
    raw[:-1],
    raw.replace(b'"entry_count": 4353', b'"entry_count": 4354'),
    raw.replace(b'"entry_count": 4353', b'"entry_count": true'),
    raw.replace(b'"version":', b'"extra":0,"version":', 1),
    raw.replace(b'"version":', b'"version":"duplicate","version":', 1),
    raw.replace(b'"manifest":', b'"manifest": ', 1),
):
    try:
        publish._parse_pins(hostile)
    except publish.PublicationError:
        pass
    else:
        raise AssertionError("hostile rootfs pins accepted")
names = tuple(name.text for name, _content in publish._contents(b"manifest", b"ustar", pins))
identity = {"mount_id": 1, "device": 1, "inode": 2, "kind": "directory", "mode": 0o700, "uid": 0, "gid": 0, "nlink": 2, "size": 4096, "mtime_ns": 1, "ctime_ns": 1}
def directory_authority(generation_value, inode_version=7):
    serialized = publish._generation_value(generation_value) if type(generation_value) is fs.HostGeneration else generation_value
    return {"generation": serialized, "inode_version": inode_version}
generation = {"mount_id": 1, "device": 1, "inode": 3, "kind": "file", "mode": 0o400, "uid": 0, "gid": 0, "nlink": 1, "size": 1, "mtime_ns": 1, "ctime_ns": 1}
anonymous_generation = {**generation, "nlink": 0, "ctime_ns": 0}
ready = {"generation": anonymous_generation, "sha256": "0" * 64, "size": 1}
values = []
previous = publish.ZERO_SHA256
events = [("intent", None, None), ("candidate-intent", None, None), ("candidate", None, directory_authority(identity))]
for index, name in enumerate(names, 2):
    next_identity = {**identity, "mtime_ns": index, "ctime_ns": index}
    events.extend((("file-intent", name, directory_authority(identity)), ("file-ready", name, ready), ("file", name, generation), ("candidate-generation", None, directory_authority(next_identity))))
    identity = next_identity
accepted_identity = {**identity, "ctime_ns": identity["ctime_ns"] + 1}
events.extend((("prepared", None, None), ("rename", None, None), ("accepted", None, directory_authority(accepted_identity))))
for phase, name, item_identity in events:
    value = publish._record(len(values), previous, phase, name, item_identity)
    line = publish._canonical(value)
    values.append(line)
    previous = hashlib.sha256(line).hexdigest()
    assert len(publish._parse_transaction(b"".join(values), names)) == len(values)
restart_values = []
previous = publish.ZERO_SHA256
replacement_ready = {**ready, "generation": {**anonymous_generation, "inode": 4}}
for phase, name, item_identity in (("intent", None, None), ("candidate-intent", None, None), ("candidate", None, directory_authority(identity)), ("file-intent", names[0], directory_authority(identity)), ("file-ready", names[0], ready), ("file-ready", names[0], replacement_ready)):
    value = publish._record(len(restart_values), previous, phase, name, item_identity)
    line = publish._canonical(value)
    restart_values.append(line)
    previous = hashlib.sha256(line).hexdigest()
publish._parse_transaction(b"".join(restart_values), names)
parser_prior = {**identity, "size": 4096, "mtime_ns": 10, "ctime_ns": 10}
parser_ready = {"generation": anonymous_generation, "sha256": "0" * 64, "size": 1}
for field, regressed in (("size", 4095), ("mtime_ns", 9), ("ctime_ns", 9)):
    parser_after = {**parser_prior, "mtime_ns": 11, "ctime_ns": 11, field: regressed}
    parser_lines = []
    parser_previous = publish.ZERO_SHA256
    parser_events = (("intent", None, None), ("candidate-intent", None, None), ("candidate", None, directory_authority(parser_prior)), ("file-intent", names[0], directory_authority(parser_prior)), ("file-ready", names[0], parser_ready), ("file", names[0], generation), ("candidate-generation", None, directory_authority(parser_after)))
    for parser_phase, parser_name, parser_identity in parser_events:
        parser_value = publish._record(len(parser_lines), parser_previous, parser_phase, parser_name, parser_identity)
        parser_line = publish._canonical(parser_value)
        parser_lines.append(parser_line)
        parser_previous = hashlib.sha256(parser_line).hexdigest()
    try:
        publish._parse_transaction(b"".join(parser_lines), (names[0],))
    except publish.PublicationError:
        pass
    else:
        raise AssertionError(f"candidate {field} regression accepted by transaction parser")
version_drift_lines = []
version_previous = publish.ZERO_SHA256
version_events = (("intent", None, None), ("candidate-intent", None, None), ("candidate", None, directory_authority(parser_prior)), ("file-intent", names[0], directory_authority(parser_prior)), ("file-ready", names[0], parser_ready), ("file", names[0], generation), ("candidate-generation", None, directory_authority({**parser_prior, "mtime_ns": 11, "ctime_ns": 11}, 8)))
for version_phase, version_name, version_identity in version_events:
    version_value = publish._record(len(version_drift_lines), version_previous, version_phase, version_name, version_identity)
    version_line = publish._canonical(version_value)
    version_drift_lines.append(version_line)
    version_previous = hashlib.sha256(version_line).hexdigest()
try:
    publish._parse_transaction(b"".join(version_drift_lines), (names[0],))
except publish.PublicationError:
    pass
else:
    raise AssertionError("candidate inode-version transition accepted")
for malformed_authority in ({"generation": parser_prior}, {"generation": parser_prior, "inode_version": True}, {"generation": parser_prior, "inode_version": 0x100000000}):
    try:
        publish._parse_directory_authority(malformed_authority)
    except publish.PublicationError:
        pass
    else:
        raise AssertionError("malformed directory authority accepted")
anonymous_key = fs.HostKey(1, 1, 9, "file")
anonymous_host = fs.HostGeneration(anonymous_key, 0o400, 0, 0, 0, 1, 1, 1)
linked_host = fs.HostGeneration(anonymous_key, 0o400, 0, 0, 1, 1, 1, 2)
publish._linked_generation_change(anonymous_host, linked_host)
prior_directory = fs.HostGeneration(fs.HostKey(1, 1, 11, "directory"), 0o700, 0, 0, 2, 4096, 10, 10)
linked_directory = fs.HostGeneration(prior_directory.key, 0o700, 0, 0, 2, 8192, 11, 11)
publish._directory_link_change(prior_directory, linked_directory)
for hostile_directory in (fs.HostGeneration(prior_directory.key, 0o700, 0, 0, 2, 4095, 11, 11), fs.HostGeneration(prior_directory.key, 0o700, 0, 0, 2, 4096, 9, 11)):
    try:
        publish._directory_link_change(prior_directory, hostile_directory)
    except publish.PublicationError:
        pass
    else:
        raise AssertionError("hostile candidate link transition accepted")
for replacement in (fs.HostGeneration(anonymous_key, 0o400, 0, 0, 1, 2, 1, 2), fs.HostGeneration(fs.HostKey(1, 1, 10, "file"), 0o400, 0, 0, 1, 1, 1, 2)):
    try:
        publish._linked_generation_change(anonymous_host, replacement)
    except publish.PublicationError:
        pass
    else:
        raise AssertionError("hostile anonymous-to-linked transition accepted")
try:
    publish._parse_transaction(b"".join(values).replace(b'"phase":"rename"', b'"phase":"accepted"'), names)
except publish.PublicationError:
    pass
else:
    raise AssertionError("hostile publication transaction accepted")
reuse_identity_read, reuse_identity_write = os.pipe()
reuse_operation_read, reuse_operation_write = os.pipe()
os.close(reuse_identity_write)
os.close(reuse_operation_write)
reuse_key = fs.HostKey(1, 1, 44, "directory")
recorded_directory = fs.HostGeneration(reuse_key, 0o700, 0, 0, 2, 4096, 10, 10)
reused_directory = fs.HostGeneration(reuse_key, 0o700, 0, 0, 2, 4096, 10, 11)
reuse_node = fs.HeldNode(fs.CheckedFd(reuse_identity_read, "reuse-identity"), fs.CheckedFd(reuse_operation_read, "reuse-operation"), reused_directory)
real_observe_authority = publish._observe_directory_authority
publish._observe_directory_authority = lambda _node, _control: publish.DirectoryAuthority(reused_directory, 7)
assert publish._require_rename_generation(reuse_node, directory_authority(recorded_directory), object()) == publish.DirectoryAuthority(reused_directory, 7)
try:
    publish._require_directory_generation(reuse_node, directory_authority(recorded_directory), object())
except publish.PublicationError:
    pass
else:
    raise AssertionError("same-inode candidate replacement accepted")
publish._observe_directory_authority = lambda _node, _control: publish.DirectoryAuthority(recorded_directory, 8)
try:
    publish._require_directory_generation(reuse_node, directory_authority(recorded_directory), object())
except publish.PublicationError:
    pass
else:
    raise AssertionError("candidate inode-version replacement accepted")
replacement_after_rename = fs.HostGeneration(reuse_key, 0o700, 0, 0, 2, 4097, 10, 12)
publish._observe_directory_authority = lambda _node, _control: publish.DirectoryAuthority(replacement_after_rename, 7)
try:
    publish._require_rename_generation(reuse_node, directory_authority(recorded_directory), object())
except publish.PublicationError:
    pass
else:
    raise AssertionError("same-inode accepted replacement authorized as rename")
finally:
    publish._observe_directory_authority = real_observe_authority
    fs._close_node(reuse_node)
ioctl_identity_read, ioctl_identity_write = os.pipe()
ioctl_operation_read, ioctl_operation_write = os.pipe()
os.close(ioctl_identity_write)
os.close(ioctl_operation_write)
ioctl_node = fs.HeldNode(fs.CheckedFd(ioctl_identity_read, "ioctl-identity"), fs.CheckedFd(ioctl_operation_read, "ioctl-operation"), recorded_directory)
real_ioctl = publish.fcntl.ioctl
real_platform = publish.sys.platform
ioctl_control = SimpleNamespace(check=lambda: None)

def mock_ioctl(_descriptor, request, raw, mutate):
    assert request == 0x80087601 and len(raw) == 8 and mutate is True
    raw[:] = publish.struct.pack("@L", 42)
    return 0

publish.sys.platform = "linux"
publish.fcntl.ioctl = mock_ioctl
assert publish._inode_version(ioctl_node, ioctl_control) == 42
publish.fcntl.ioctl = lambda _descriptor, _request, raw, _mutate: (raw.__setitem__(slice(None), publish.struct.pack("@L", 0x100000000)) or 0)
try:
    publish._inode_version(ioctl_node, ioctl_control)
except publish.PublicationError:
    pass
else:
    raise AssertionError("overlong inode version accepted")
finally:
    publish.fcntl.ioctl = real_ioctl
    publish.sys.platform = real_platform
    fs._close_node(ioctl_node)
if sys.platform == "linux":
    ext4_fixture = os.environ.get("COGS_APPROVED_EXT4_FIXTURE")
    if ext4_fixture is not None:
        class StatFs(ctypes.Structure):
            _fields_ = (("f_type", ctypes.c_long), ("remaining", ctypes.c_byte * 248))

        observed_fs = StatFs()
        assert ctypes.CDLL(None, use_errno=True).statfs(os.fsencode(ext4_fixture), ctypes.byref(observed_fs)) == 0
        assert observed_fs.f_type == 0xEF53, "approved publication fixture is not ext4"

        tiny_manifest = b"manifest\n"
        tiny_ustar = b"ustar\n"
        tiny_pins = publish.RootfsPins(b"{}\n", hashlib.sha256(tiny_manifest).hexdigest(), len(tiny_manifest), hashlib.sha256(tiny_ustar).hexdigest(), len(tiny_ustar), 1)
        intended_name = publish._contents(tiny_manifest, tiny_ustar, tiny_pins)[0][0]

        def ext4_publish_once(path):
            publication_fs = StatFs()
            assert ctypes.CDLL(None, use_errno=True).statfs(os.fsencode(path), ctypes.byref(publication_fs)) == 0 and publication_fs.f_type == 0xEF53
            control = fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False)
            held_identity = fs.CheckedFd(os.open(path, fs.IDENTITY_FLAGS), "ext4-publication-identity")
            held_operation = fs.CheckedFd(os.open(path, fs.DIRECTORY_FLAGS), "ext4-publication-directory")
            parent = fs.HeldNode(held_identity, held_operation, fs._observe_node(held_identity, held_operation, control))
            try:
                return publish._publish_unmasked(parent, tiny_manifest, tiny_ustar, tiny_pins, control)
            finally:
                fs._close_node(parent)

        def ext4_fault_case(case):
            with tempfile.TemporaryDirectory(dir=ext4_fixture) as publication_directory:
                publication_path = Path(publication_directory)
                publication_path.chmod(0o700)
                link_calls = {"count": 0}
                real_link = publish._link_anonymous

                def link_then_fail(directory, name, anonymous, control):
                    if name == intended_name:
                        link_calls["count"] += 1
                    real_link(directory, name, anonymous, control)
                    if name == intended_name and link_calls["count"] == 1:
                        raise OSError("ext4 post-link fault")

                publish._link_anonymous = link_then_fail
                try:
                    try:
                        ext4_publish_once(publication_path)
                    except OSError:
                        pass
                    else:
                        raise AssertionError("ext4 post-link fault was not observed")
                finally:
                    publish._link_anonymous = real_link

                candidate_fs = StatFs()
                candidate_path = publication_path / publish.CANDIDATE_NAME.text
                assert ctypes.CDLL(None, use_errno=True).statfs(os.fsencode(candidate_path), ctypes.byref(candidate_fs)) == 0 and candidate_fs.f_type == 0xEF53

                def count_retry_link(directory, name, anonymous, control):
                    if name == intended_name:
                        link_calls["count"] += 1
                    return real_link(directory, name, anonymous, control)

                publish._link_anonymous = count_retry_link
                tripped = {"value": False}
                real_file = publish._file
                real_read = fs._read_regular
                real_xattrs = fs._require_empty_fd_xattrs
                real_fsync = publish.os.fsync
                real_observe_node = fs._observe_node
                real_append_records = publish._append_records
                real_write = publish.os.write
                real_close = fs.CheckedFd.close
                real_snapshot_node = publish._snapshot_node
                real_renameat2 = publish._renameat2
                armed = {"observe": False}

                def target_file(directory, name, expected, control):
                    if name == intended_name and not tripped["value"] and case == "open":
                        tripped["value"] = True
                        raise OSError("linked open fault")
                    if name == intended_name and not tripped["value"] and case in {"read", "xattr"}:
                        target = "read" if case == "read" else "xattr"
                        if target == "read":
                            fs._read_regular = lambda *_args: (_ for _ in ()).throw(OSError("linked read fault"))
                        else:
                            fs._require_empty_fd_xattrs = lambda *_args: (_ for _ in ()).throw(OSError("linked xattr fault"))
                        tripped["value"] = True
                        try:
                            return real_file(directory, name, expected, control)
                        finally:
                            fs._read_regular = real_read
                            fs._require_empty_fd_xattrs = real_xattrs
                    return real_file(directory, name, expected, control)

                def candidate_fsync(descriptor):
                    target = os.readlink(f"/proc/self/fd/{descriptor}")
                    if target.endswith("/.accepted-candidate-v1") and case in {"candidate-fsync", "candidate-observe"}:
                        if case == "candidate-fsync" and not tripped["value"]:
                            tripped["value"] = True
                            raise OSError("candidate fsync fault")
                        armed["observe"] = True
                    return real_fsync(descriptor)

                def candidate_observe(identity_fd, operation_fd, control):
                    if case == "candidate-observe" and armed["observe"] and not tripped["value"] and operation_fd is not None:
                        target = os.readlink(f"/proc/self/fd/{operation_fd.number}")
                        if target.endswith("/.accepted-candidate-v1"):
                            tripped["value"] = True
                            raise OSError("candidate observe fault")
                    return real_observe_node(identity_fd, operation_fd, control)

                def compound_fault(transaction, parent, content_names, additions, control):
                    if additions[0][0] != "file" or case not in {"write", "file-fsync", "close", "readback", "parent-fsync", "exchange"}:
                        return real_append_records(transaction, parent, content_names, additions, control)
                    syncs = {"count": 0}

                    def fail_write(*_args):
                        tripped["value"] = True
                        raise OSError("compound write fault")

                    def fail_sync(descriptor):
                        syncs["count"] += 1
                        threshold = 1 if case == "file-fsync" else 2
                        if syncs["count"] == threshold:
                            tripped["value"] = True
                            raise OSError("compound fsync fault")
                        return real_fsync(descriptor)

                    def fail_close(descriptor, primary_error=None):
                        result = real_close(descriptor, primary_error)
                        if descriptor.role == "publication-snapshot" and not tripped["value"]:
                            tripped["value"] = True
                            raise OSError("compound close fault")
                        return result

                    def fail_readback(parent, name, inner_control):
                        if name == publish.TRANSACTION_NEXT_NAME and not tripped["value"]:
                            tripped["value"] = True
                            raise OSError("compound readback fault")
                        return real_snapshot_node(parent, name, inner_control)

                    def fail_exchange(parent, source, destination, flags):
                        result = real_renameat2(parent, source, destination, flags)
                        if flags == 2 and not tripped["value"]:
                            tripped["value"] = True
                            raise OSError("compound exchange fault")
                        return result

                    if case == "write":
                        publish.os.write = fail_write
                    if case in {"file-fsync", "parent-fsync"}:
                        publish.os.fsync = fail_sync
                    if case == "close":
                        fs.CheckedFd.close = fail_close
                    if case == "readback":
                        publish._snapshot_node = fail_readback
                    if case == "exchange":
                        publish._renameat2 = fail_exchange
                    try:
                        return real_append_records(transaction, parent, content_names, additions, control)
                    finally:
                        publish.os.write = real_write
                        publish.os.fsync = real_fsync
                        fs.CheckedFd.close = real_close
                        publish._snapshot_node = real_snapshot_node
                        publish._renameat2 = real_renameat2

                publish._file = target_file
                publish.os.fsync = candidate_fsync
                fs._observe_node = candidate_observe
                publish._append_records = compound_fault
                try:
                    try:
                        ext4_publish_once(publication_path)
                    except OSError:
                        pass
                    else:
                        raise AssertionError(f"ext4 {case} fault was not observed")
                finally:
                    publish._file = real_file
                    publish.os.fsync = real_fsync
                    fs._observe_node = real_observe_node
                    publish._append_records = real_append_records
                    publish.os.write = real_write
                    fs.CheckedFd.close = real_close
                    publish._snapshot_node = real_snapshot_node
                    publish._renameat2 = real_renameat2
                assert tripped["value"], f"ext4 {case} fault did not trip"
                first_published = ext4_publish_once(publication_path)
                assert first_published == ext4_publish_once(publication_path)
                assert link_calls["count"] == 1, "post-link retry attempted a second linkat"
                publish._link_anonymous = real_link

        for fault_case in ("open", "read", "xattr", "candidate-fsync", "candidate-observe", "write", "file-fsync", "close", "readback", "parent-fsync", "exchange"):
            ext4_fault_case(fault_case)

        def ext4_hostile_case(case):
            with tempfile.TemporaryDirectory(dir=ext4_fixture) as publication_directory:
                publication_path = Path(publication_directory)
                publication_path.chmod(0o700)
                real_link = publish._link_anonymous
                links = {"count": 0}
                stop_at = 2 if case == "prior" else 1

                def stop_after_link(directory, name, anonymous, control):
                    real_link(directory, name, anonymous, control)
                    links["count"] += 1
                    if links["count"] == stop_at:
                        raise OSError("hostile setup post-link fault")

                publish._link_anonymous = stop_after_link
                try:
                    try:
                        ext4_publish_once(publication_path)
                    except OSError:
                        pass
                finally:
                    publish._link_anonymous = real_link
                candidate_path = publication_path / publish.CANDIDATE_NAME.text
                target = candidate_path / intended_name.text
                if case == "extra":
                    extra = candidate_path / "hostile-extra"
                    extra.write_bytes(b"extra")
                    extra.chmod(0o400)
                elif case == "name":
                    target.rename(candidate_path / "hostile-name")
                elif case == "inode":
                    target.unlink()
                    target.write_bytes(publish.SENTINEL)
                    target.chmod(0o400)
                    os.chown(target, 0, 0)
                    os.utime(target, ns=(0, 0))
                else:
                    prior_name = intended_name if case == "prior" else intended_name
                    hostile_target = candidate_path / prior_name.text
                    hostile_target.chmod(0o600)
                    hostile_target.write_bytes(b"hostile")
                    hostile_target.chmod(0o400)
                try:
                    ext4_publish_once(publication_path)
                except publish.PublicationError:
                    pass
                else:
                    raise AssertionError(f"hostile ext4 {case} state was accepted")
                assert candidate_path.is_dir()

        for hostile_case in ("extra", "name", "inode", "content", "prior"):
            ext4_hostile_case(hostile_case)
        with tempfile.TemporaryDirectory(dir=ext4_fixture) as temporary:
            candidate_path = Path(temporary) / "candidate"

            def path_inode_version(path):
                version_control = fs.OperationControl(time.monotonic_ns() + 120_000_000_000, lambda: False)
                version_identity = fs.CheckedFd(os.open(path, fs.IDENTITY_FLAGS), "version-identity")
                version_operation = fs.CheckedFd(os.open(path, fs.DIRECTORY_FLAGS), "version-directory")
                version_node = fs.HeldNode(version_identity, version_operation, fs._observe_node(version_identity, version_operation, version_control))
                try:
                    return publish._inode_version(version_node, version_control)
                finally:
                    fs._close_node(version_node)

            candidate_path.mkdir()
            first = candidate_path.stat()
            first_version = path_inode_version(candidate_path)
            candidate_path.rmdir()
            def ordinary_authority(observed):
                return (
                    observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid,
                    observed.st_nlink, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns,
                )

            reused_stat = None
            reused_version = None
            for _attempt in range(4096):
                candidate_path.mkdir()
                current = candidate_path.stat()
                if ordinary_authority(current) == ordinary_authority(first):
                    reused_stat = current
                    reused_version = path_inode_version(candidate_path)
                    candidate_path.rmdir()
                    break
                candidate_path.rmdir()
            assert reused_stat is not None, "approved ext4 fixture did not reproduce identical ordinary-stat inode reuse"
            assert reused_version != first_version, "reused ext4 inode retained its publication inode version"
identity_read, identity_write = os.pipe()
operation_read, operation_write = os.pipe()
os.close(identity_write)
os.close(operation_write)
key = fs.HostKey(1, 1, 1, "file")
opened_generation = fs.HostGeneration(key, 0o400, 0, 0, 1, 1, 1, 1)
opened = fs.HeldNode(fs.CheckedFd(identity_read, "test-identity"), fs.CheckedFd(operation_read, "test-operation"), opened_generation)
recorded_generation = fs.HostGeneration(fs.HostKey(1, 1, 2, "file"), 0o400, 0, 0, 1, 1, 1, 1)
real_file = publish._file
real_enumerate = fs._enumerate_stable
publish._file = lambda _directory, _name, _raw, _control: opened
fs._enumerate_stable = lambda _directory, _control: SimpleNamespace(raw_names=(publish.SENTINEL_NAME.raw,))
try:
    publish._verify_inventory(object(), ((publish.SENTINEL_NAME, b"x"),), ({"identity": publish._generation_value(recorded_generation)},), False, object())
except publish.PublicationError:
    pass
else:
    raise AssertionError("replacement publication identity accepted")
finally:
    publish._file = real_file
    fs._enumerate_stable = real_enumerate
assert opened.identity_fd.disposition == opened.operation_fd.disposition == "closed"
source = (REMOTE / "completion_rootfs_publish.py").read_text()
assert "os.O_TMPFILE | os.O_RDWR" in source and "linkat" in source and "0x1000" in source and "_rename_noreplace" in source
assert "file-ready" in source and "publication-anonymous" in source
assert "0x80087601" in source and "_inode_version" in source and "inode_version" in source
assert "file-abort" not in source and "def _create_file" not in source
assert "rootfs.metadata.json" in source and "_parse_transaction" in source and "_transition_control" in source
assert b"qualification" not in raw and b"functional_test_image" in raw
for forbidden in ("argparse", "sys.argv", "if __name__", "rmtree", "os.walk", "glob", "subprocess", "socket"):
    assert forbidden not in source
print("completion rootfs publication tests passed")

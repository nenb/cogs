#!/usr/bin/env python3
"""Canonical tests and a non-authoritative Docker two-build functional harness."""

import dataclasses
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
FIXED = Path("/var/lib/cogs/stage2-completion-v1/source")
CACHE_SOURCE = ROOT / "deploy/aws-feasibility/.state/completion-v1/artifacts"
CONTAINER_SENTINEL = Path("/var/lib/cogs/.cogs-rootfs-functional-test-v1")
CONTAINER_SENTINEL_RAW = b"cogs-rootfs-functional-test-v1\n"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def portable():
    sys.path.insert(0, str(REMOTE))
    preflight = load("completion_archive_preflight", REMOTE / "completion_archive_preflight.py")
    plan = load("completion_rootfs_plan", REMOTE / "completion_rootfs_plan.py")
    canonical = load("completion_rootfs_canonical", REMOTE / "completion_rootfs_canonical.py")
    root = plan.ROOT_POLICY
    records = (
        preflight.MaterialRecord("a", "directory", 0o755, 0, 0, 1, 0, None, None, None, None, -1),
        preflight.MaterialRecord("a/file", "file", 0o644, 0, 0, 2, 1, None, None, None, "0" * 64, 0),
    )
    entries = tuple(plan.PlannedEntry("test", None, record, b"x" if record.kind == "file" else None) for record in records)
    value = plan.RootfsPlan(root, ("test",), entries, ())
    first = canonical._manifest(value)
    assert first.endswith(b"\n") and json.loads(first)["entries"][0]["path"] == "a"
    hostile = dataclasses.replace(value, entries=tuple(reversed(entries)))
    try:
        canonical._manifest(hostile)
    except canonical.CanonicalError:
        pass
    else:
        raise AssertionError("shuffled manifest accepted")
    header = canonical._header("a/file", records[1], b"0", 1)
    assert len(header) == 512 and header[257:265] == b"ustar\0" + b"00"
    checksum = int(header[148:154], 8)
    mutable = bytearray(header)
    mutable[148:156] = b"        "
    assert checksum == sum(mutable)
    source = (REMOTE / "completion_rootfs_canonical.py").read_text() + (REMOTE / "completion_rootfs_build.py").read_text()
    for forbidden in ("tarfile", "PAX", "GNU", "subprocess", "socket", "argparse", "sys.argv", "if __name__"):
        assert forbidden not in source
    print("completion rootfs canonical portable tests passed")


def prepare_real_workspace():
    def require(condition):
        if not condition:
            raise RuntimeError("unsafe Docker functional environment")

    require(sys.platform == "linux" and os.geteuid() == 0 and Path("/.dockerenv").is_file())
    mount = Path("/var/lib/cogs")
    mount_stat = mount.stat(follow_symlinks=False)
    require(stat.S_ISDIR(mount_stat.st_mode) and stat.S_IMODE(mount_stat.st_mode) == 0o700)
    require(mount_stat.st_uid == mount_stat.st_gid == 0 and mount_stat.st_dev != Path("/var/lib").stat().st_dev)
    lines = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines() if line.split()[4] == str(mount)]
    require(len(lines) == 1 and "-" in lines[0])
    separator = lines[0].index("-")
    require(lines[0][separator + 1] == "tmpfs" and {"rw", "nosuid", "nodev", "noexec"} <= set(lines[0][5].split(",")))
    observed = CONTAINER_SENTINEL.stat(follow_symlinks=False)
    require(stat.S_ISREG(observed.st_mode) and stat.S_IMODE(observed.st_mode) == 0o400)
    require(observed.st_uid == observed.st_gid == 0 and observed.st_nlink == 1 and observed.st_dev == mount_stat.st_dev)
    require(CONTAINER_SENTINEL.read_bytes() == CONTAINER_SENTINEL_RAW)
    require(tuple(path.name for path in mount.iterdir()) == (CONTAINER_SENTINEL.name,) and not FIXED.parent.exists())
    remote = FIXED / "deploy/aws-feasibility/remote"
    artifact_root = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts"
    cache = artifact_root / "cache"
    remote.mkdir(parents=True, mode=0o700)
    cache.mkdir(parents=True, mode=0o700)
    directories = [Path("/var/lib/cogs/stage2-completion-v1"), FIXED, FIXED / "deploy", FIXED / "deploy/aws-feasibility", remote, FIXED / "deploy/aws-feasibility/.state", FIXED / "deploy/aws-feasibility/.state/completion-v1", artifact_root, cache]
    for path in directories:
        path.chmod(0o700)
    names = (
        "completion_archive_preflight.py",
        "completion_rootfs_plan.py",
        "completion_rootfs_fs.py",
        "completion_rootfs_ledger.py",
        "completion_rootfs_builder.py",
        "completion_rootfs_materializer.py",
        "completion_rootfs_canonical.py",
        "completion_rootfs_publish.py",
        "completion_rootfs_build.py",
        "verify-completion-artifacts.py",
        "stage2-completion-artifacts-v1.json",
        "stage2-completion-rootfs-v1.json",
    )
    manifest_entries = [
        {"path": "deploy", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
        {"path": "deploy/aws-feasibility", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
        {"path": "deploy/aws-feasibility/remote", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
    ]
    for name in names:
        content = (REMOTE / name).read_bytes()
        target = remote / name
        target.write_bytes(content)
        mode = 0o644 if name == "stage2-completion-artifacts-v1.json" else 0o400
        target.chmod(mode)
        manifest_entries.append({"path": f"deploy/aws-feasibility/remote/{name}", "kind": "file", "mode": mode, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    sentinel_raw = b"cogs-stage2-source-v1\n"
    sentinel = FIXED / ".cogs-stage2-source-v1"
    sentinel.write_bytes(sentinel_raw)
    sentinel.chmod(0o400)
    manifest_entries.append({"path": sentinel.name, "kind": "file", "mode": 0o400, "size": len(sentinel_raw), "sha256": hashlib.sha256(sentinel_raw).hexdigest()})
    manifest_entries.sort(key=lambda item: item["path"].encode())
    revision = "9" * 40
    manifest_raw = json.dumps({"version": "cogs.stage2-source-manifest/v1", "revision": revision, "entries": manifest_entries}, separators=(",", ":")).encode() + b"\n"
    manifest = FIXED / ".cogs-stage2-source-manifest-v1.json"
    manifest.write_bytes(manifest_raw)
    manifest.chmod(0o400)
    artifact_sentinel = CACHE_SOURCE / ".cogs-stage2-completion-artifacts-v1"
    shutil.copyfile(artifact_sentinel, artifact_root / artifact_sentinel.name)
    (artifact_root / artifact_sentinel.name).chmod(0o600)
    for source in sorted((CACHE_SOURCE / "cache").iterdir()):
        target = cache / source.name
        shutil.copyfile(source, target)
        target.chmod(0o400)
    inventory = tuple((path.name, path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(cache.iterdir()))
    return revision, hashlib.sha256(manifest_raw).hexdigest(), inventory


def accommodate_docker_overlay(fs):
    def check(condition):
        if not condition:
            raise RuntimeError("Docker functional policy mismatch")

    original_xattrs = fs._require_empty_fd_xattrs
    ancestors = {(os.lstat(path).st_dev, os.lstat(path).st_ino) for path in ("/", "/var", "/var/lib")}
    functional_device = os.lstat("/var/lib/cogs").st_dev
    fs._open_workspace_anchor = lambda control: fs._open_root_node(control)

    def policy(node, expected, root_key):
        value = node.generation
        check(value.key.kind == expected.kind and value.mode == expected.mode)
        check(value.uid == expected.uid and value.gid == expected.gid)
        check((value.key.mount_id, value.key.device) == (root_key.mount_id, root_key.device) or value.key.device == functional_device)
        if expected.kind == "file":
            check(value.nlink == 1)

    def xattrs(node, control):
        if (node.generation.key.device, node.generation.key.inode) not in ancestors:
            original_xattrs(node, control)

    fs._require_policy = policy
    fs._require_empty_fd_xattrs = xattrs


def docker_functional_two_builds():
    revision, manifest_digest, before = prepare_real_workspace()
    remote = FIXED / "deploy/aws-feasibility/remote"
    sys.path.insert(0, str(remote))
    load("completion_archive_preflight", remote / "completion_archive_preflight.py")
    load("completion_rootfs_plan", remote / "completion_rootfs_plan.py")
    fs = load("completion_rootfs_fs", remote / "completion_rootfs_fs.py")
    load("completion_rootfs_ledger", remote / "completion_rootfs_ledger.py")
    builder = load("completion_rootfs_builder", remote / "completion_rootfs_builder.py")
    load("completion_rootfs_materializer", remote / "completion_rootfs_materializer.py")
    load("completion_rootfs_canonical", remote / "completion_rootfs_canonical.py")
    publication = load("completion_rootfs_publish", remote / "completion_rootfs_publish.py")
    build = load("completion_rootfs_build", remote / "completion_rootfs_build.py")
    accommodate_docker_overlay(fs)
    approval = fs.SourceApproval(revision, manifest_digest)
    outer = fs.OperationControl(time.monotonic_ns() + build.OUTER_SECONDS * 1_000_000_000, lambda: False)
    chain = builder._open_base_chain(outer)
    state = builder._bootstrap(chain, approval, outer)
    fs._close_node(state)
    fs._close_chain(chain)
    destination_path = Path("/var/lib/cogs/stage2-completion-v1")
    identity = fs.CheckedFd(os.open(destination_path, fs.IDENTITY_FLAGS), "destination-identity")
    operation = fs.CheckedFd(os.open(destination_path, fs.DIRECTORY_FLAGS), "destination-directory")
    destination = fs.HeldNode(identity, operation, fs._observe_node(identity, operation, outer))
    assert not (destination_path / "accepted").exists()
    hostile_umask = os.umask(0o777)
    try:
        first, second = build._two_build_outputs(approval, outer)
        assert first.manifest == second.manifest and first.ustar == second.ustar
        pins_value = publication._load_pins()
        try:
            publication._inode_version(destination, outer)
        except OSError as error:
            if error.errno != errno.ENOTTY:
                raise
            after = tuple((path.name, path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted((FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache").iterdir()))
            assert before == after and len(after) == 16
            fs._close_node(destination)
            print("rootfs publication skipped: tmpfs lacks FS_IOC_GETVERSION (non-authoritative functional run)", file=sys.stderr)
            skipped = {"status": "skipped", "reason": "FS_IOC_GETVERSION unsupported", "authority": "functional-only"}
            assert set(skipped) != {"manifest_sha256", "manifest_size", "ustar_sha256", "ustar_size", "entry_count"}
            print(json.dumps(skipped, sort_keys=True, separators=(",", ":")))
            return

        def held_directory(path, role):
            held_identity = fs.CheckedFd(os.open(path, fs.IDENTITY_FLAGS), role + "-identity")
            held_operation = fs.CheckedFd(os.open(path, fs.DIRECTORY_FLAGS), role + "-directory")
            return fs.HeldNode(held_identity, held_operation, fs._observe_node(held_identity, held_operation, outer))

        hostile_path = Path("/var/lib/cogs/publication-hostile")
        hostile_path.mkdir(mode=0o700)
        hostile_path.chmod(0o700)
        hostile_destination = held_directory(hostile_path, "hostile-publication")
        (hostile_path / ".accepted-candidate-v1").mkdir(mode=0o700)
        (hostile_path / ".accepted-candidate-v1").chmod(0o700)
        try:
            publication._publish(hostile_destination, second.manifest, second.ustar, pins_value, outer)
        except publication.PublicationError:
            pass
        else:
            raise AssertionError("unrecorded candidate identity was accepted")
        assert (hostile_path / ".accepted-candidate-v1").is_dir()
        fs._close_node(hostile_destination)
        (hostile_path / ".accepted-candidate-v1").rmdir()
        (hostile_path / ".accepted-transaction-v1").unlink()
        hostile_path.rmdir()

        snapshot_path = Path("/var/lib/cogs/publication-snapshot")
        snapshot_path.mkdir(mode=0o700)
        snapshot_path.chmod(0o700)
        snapshot_destination = held_directory(snapshot_path, "snapshot-publication")
        snapshot_umask = os.umask(0o077)
        content_names = tuple(name.text for name, _raw in publication._contents(second.manifest, second.ustar, pins_value))
        snapshot_control = publication._transition_control()
        snapshot_transaction = publication._open_transaction(snapshot_destination, content_names, snapshot_control)
        original_renameat2 = publication._renameat2

        def exchange_then_fail(parent, source, destination, flags):
            original_renameat2(parent, source, destination, flags)
            if flags == 2:
                raise RuntimeError("snapshot exchange fault")

        publication._renameat2 = exchange_then_fail
        try:
            publication._append_transaction(snapshot_transaction, snapshot_destination, content_names, "candidate-intent", snapshot_control)
        except RuntimeError:
            pass
        finally:
            publication._renameat2 = original_renameat2
        assert (snapshot_path / ".accepted-transaction-next-v1").is_file()
        recovered_snapshot = publication._open_transaction(snapshot_destination, content_names, snapshot_control)
        assert recovered_snapshot.records[-1]["phase"] == "candidate-intent"
        assert not (snapshot_path / ".accepted-transaction-next-v1").exists()
        snapshot_candidate_path = snapshot_path / ".accepted-candidate-v1"
        snapshot_candidate_path.mkdir(mode=0o700)
        snapshot_candidate_path.chmod(0o700)
        snapshot_candidate = held_directory(snapshot_candidate_path, "snapshot-candidate")
        recovered_snapshot = publication._append_transaction(recovered_snapshot, snapshot_destination, content_names, "candidate", snapshot_control, identity=publication._directory_authority_value(publication._observe_directory_authority(snapshot_candidate, snapshot_control)))
        for index, fail_after_exchange in enumerate((False, True)):
            name = publication._contents(second.manifest, second.ustar, pins_value)[index][0]
            intent_generation = publication._observe_directory_authority(snapshot_candidate, snapshot_control)
            recovered_snapshot = publication._append_transaction(recovered_snapshot, snapshot_destination, content_names, "file-intent", snapshot_control, name.text, publication._directory_authority_value(intent_generation))
            file_path = snapshot_candidate_path / name.text
            file_path.write_bytes(b"x")
            file_path.chmod(0o400)
            snapshot_file = fs._open_path_node(snapshot_candidate, name, "file", snapshot_control)
            anonymous_generation = dataclasses.replace(snapshot_file.generation, nlink=0, ctime_ns=max(0, snapshot_file.generation.ctime_ns - 1))
            recovered_snapshot = publication._append_transaction(recovered_snapshot, snapshot_destination, content_names, "file-ready", snapshot_control, name.text, publication._ready_value(anonymous_generation, b"x"))
            candidate_generation = publication._observe_directory_authority(snapshot_candidate, snapshot_control)
            tripped = {"value": False}

            def compound_exchange_fault(parent, source, destination, flags):
                if flags == 2 and not tripped["value"]:
                    tripped["value"] = True
                    if not fail_after_exchange:
                        raise RuntimeError("compound pre-exchange fault")
                    original_renameat2(parent, source, destination, flags)
                    raise RuntimeError("compound post-exchange fault")
                return original_renameat2(parent, source, destination, flags)

            publication._renameat2 = compound_exchange_fault
            try:
                publication._append_records(recovered_snapshot, snapshot_destination, content_names, (("file", name.text, publication._generation_value(snapshot_file.generation)), ("candidate-generation", None, publication._directory_authority_value(candidate_generation))), snapshot_control)
            except RuntimeError:
                pass
            else:
                raise AssertionError("compound exchange fault was not observed")
            finally:
                publication._renameat2 = original_renameat2
                fs._close_node(snapshot_file)
            assert tripped["value"]
            recovered_snapshot = publication._open_transaction(snapshot_destination, content_names, snapshot_control)
            assert recovered_snapshot.records[-1]["phase"] == "candidate-generation"
            assert not (snapshot_path / ".accepted-transaction-next-v1").exists()
        fs._close_node(snapshot_candidate)
        for name in content_names[:2]:
            (snapshot_candidate_path / name).unlink()
        snapshot_candidate_path.rmdir()
        fs._close_node(snapshot_destination)
        (snapshot_path / ".accepted-transaction-v1").unlink()
        snapshot_path.rmdir()
        os.umask(snapshot_umask)

        replaced_path = Path("/var/lib/cogs/publication-replaced")
        replaced_path.mkdir(mode=0o700)
        replaced_path.chmod(0o700)
        replaced_destination = held_directory(replaced_path, "replaced-publication")
        original_append = publication._append_transaction

        def capture_then_fail(transaction, parent, content_names, phase, control, name=None, identity=None):
            result = original_append(transaction, parent, content_names, phase, control, name, identity)
            if phase == "candidate":
                raise RuntimeError("candidate captured")
            return result

        publication._append_transaction = capture_then_fail
        try:
            publication._publish(replaced_destination, second.manifest, second.ustar, pins_value, outer)
        except RuntimeError:
            pass
        finally:
            publication._append_transaction = original_append
        (replaced_path / ".accepted-candidate-v1").rmdir()
        (replaced_path / ".accepted-candidate-v1").mkdir(mode=0o700)
        (replaced_path / ".accepted-candidate-v1").chmod(0o700)
        try:
            publication._publish(replaced_destination, second.manifest, second.ustar, pins_value, outer)
        except publication.PublicationError:
            pass
        else:
            raise AssertionError("replaced candidate identity was accepted")
        fs._close_node(replaced_destination)
        (replaced_path / ".accepted-candidate-v1").rmdir()
        (replaced_path / ".accepted-transaction-v1").unlink()
        replaced_path.rmdir()

        rollback_path = Path("/var/lib/cogs/publication-rollback")
        rollback_path.mkdir(mode=0o700)
        rollback_path.chmod(0o700)
        rollback_destination = held_directory(rollback_path, "rollback-publication")
        tiny_manifest = b"manifest\n"
        tiny_ustar = b"ustar\n"
        tiny_pins = publication.RootfsPins(b"", hashlib.sha256(tiny_manifest).hexdigest(), len(tiny_manifest), hashlib.sha256(tiny_ustar).hexdigest(), len(tiny_ustar), 1)
        real_write_all = publication._write_all
        write_fault = {"tripped": False}

        def publication_file_write_fault(descriptor, raw, control):
            if descriptor.role == "publication-anonymous" and not write_fault["tripped"]:
                write_fault["tripped"] = True
                raise OSError("anonymous publication write fault")
            return real_write_all(descriptor, raw, control)

        publication._write_all = publication_file_write_fault
        try:
            publication._publish_unmasked(rollback_destination, tiny_manifest, tiny_ustar, tiny_pins, outer)
        except BaseException:
            pass
        else:
            raise AssertionError("publication file rollback fault was not observed")
        finally:
            publication._write_all = real_write_all
        assert write_fault["tripped"]
        rollback_names = tuple(name.text for name, _raw in publication._contents(tiny_manifest, tiny_ustar, tiny_pins))
        rollback_transaction = publication._open_transaction(rollback_destination, rollback_names, publication._transition_control())
        assert rollback_transaction.records[-1]["phase"] == "file-intent"
        original_link_anonymous = publication._link_anonymous
        link_fault = {"tripped": False}

        def link_then_fail(directory, name, anonymous, control):
            original_link_anonymous(directory, name, anonymous, control)
            if not link_fault["tripped"]:
                link_fault["tripped"] = True
                raise OSError("uncertain anonymous link fault")

        publication._link_anonymous = link_then_fail
        try:
            publication._publish_unmasked(rollback_destination, tiny_manifest, tiny_ustar, tiny_pins, outer)
        except OSError:
            pass
        finally:
            publication._link_anonymous = original_link_anonymous
        assert link_fault["tripped"]
        original_append_records = publication._append_records
        compound_fault = {"tripped": False}

        def compound_before_snapshot(transaction, parent, content_names, additions, control):
            if additions[0][0] == "file" and not compound_fault["tripped"]:
                compound_fault["tripped"] = True
                raise OSError("compound pre-snapshot fault")
            return original_append_records(transaction, parent, content_names, additions, control)

        publication._append_records = compound_before_snapshot
        try:
            publication._publish_unmasked(rollback_destination, tiny_manifest, tiny_ustar, tiny_pins, outer)
        except OSError:
            pass
        finally:
            publication._append_records = original_append_records
        assert compound_fault["tripped"]
        assert publication._publish_unmasked(rollback_destination, tiny_manifest, tiny_ustar, tiny_pins, outer) == publication._publish_unmasked(rollback_destination, tiny_manifest, tiny_ustar, tiny_pins, outer)
        fs._close_node(rollback_destination)
        for child in (rollback_path / "accepted").iterdir():
            child.unlink()
        (rollback_path / "accepted").rmdir()
        (rollback_path / ".accepted-transaction-v1").unlink()
        rollback_path.rmdir()

        real_write = publication.os.write
        writes = {"count": 0}

        def short_then_fail(descriptor, raw):
            writes["count"] += 1
            if writes["count"] == 1:
                return real_write(descriptor, raw[: max(1, len(raw) // 2)])
            raise OSError("snapshot write fault")

        publication.os.write = short_then_fail
        try:
            publication._publish(destination, second.manifest, second.ustar, pins_value, outer)
        except OSError:
            pass
        finally:
            publication.os.write = real_write
        assert not any((destination_path / name).exists() for name in (".accepted-transaction-v1", ".accepted-transaction-next-v1", ".accepted-candidate-v1"))

        real_fsync = publication.os.fsync
        syncs = {"count": 0}

        def fsync_once_then_fail(descriptor):
            syncs["count"] += 1
            if syncs["count"] == 1:
                raise OSError("snapshot fsync fault")
            return real_fsync(descriptor)

        publication.os.fsync = fsync_once_then_fail
        try:
            publication._publish(destination, second.manifest, second.ustar, pins_value, outer)
        except OSError:
            pass
        finally:
            publication.os.fsync = real_fsync
        assert not any((destination_path / name).exists() for name in (".accepted-transaction-v1", ".accepted-transaction-next-v1", ".accepted-candidate-v1"))

        real_close = fs.CheckedFd.close
        closes = {"tripped": False}

        def close_once_then_fail(descriptor, primary_error=None):
            result = real_close(descriptor, primary_error)
            if descriptor.role == "publication-snapshot" and not closes["tripped"]:
                closes["tripped"] = True
                raise OSError("snapshot close fault")
            return result

        fs.CheckedFd.close = close_once_then_fail
        try:
            publication._publish(destination, second.manifest, second.ustar, pins_value, outer)
        except OSError:
            pass
        finally:
            fs.CheckedFd.close = real_close
        assert closes["tripped"]
        assert not any((destination_path / name).exists() for name in (".accepted-transaction-v1", ".accepted-transaction-next-v1", ".accepted-candidate-v1"))

        real_fstat = publication.os.fstat
        stats = {"count": 0}

        def fstat_once_then_fail(descriptor):
            target = os.readlink(f"/proc/self/fd/{descriptor}")
            if target.endswith(".accepted-transaction-next-v1"):
                stats["count"] += 1
                if stats["count"] == 1:
                    raise OSError("snapshot identity fault")
            return real_fstat(descriptor)

        publication.os.fstat = fstat_once_then_fail
        try:
            publication._publish(destination, second.manifest, second.ustar, pins_value, outer)
        except OSError:
            pass
        finally:
            publication.os.fstat = real_fstat
        assert not any((destination_path / name).exists() for name in (".accepted-transaction-v1", ".accepted-transaction-next-v1", ".accepted-candidate-v1"))

        original_append = publication._append_transaction
        original_append_records = publication._append_records
        for fault_phase in ("intent", "candidate-intent", "candidate", "file-intent", "file-ready", "file", "candidate-generation", "prepared", "rename"):
            tripped = {"value": False}

            def append_with_fault(transaction, parent, content_names, phase, control, name=None, identity=None):
                result = original_append(transaction, parent, content_names, phase, control, name, identity)
                if phase == fault_phase and not tripped["value"]:
                    tripped["value"] = True
                    raise RuntimeError("publication phase fault")
                return result

            def append_records_with_fault(transaction, parent, content_names, additions, control):
                result = original_append_records(transaction, parent, content_names, additions, control)
                if any(phase == fault_phase for phase, _name, _identity in additions) and not tripped["value"]:
                    tripped["value"] = True
                    raise RuntimeError("publication compound phase fault")
                return result

            publication._append_transaction = append_with_fault
            publication._append_records = append_records_with_fault
            try:
                publication._publish(destination, second.manifest, second.ustar, pins_value, outer)
            except RuntimeError:
                pass
            else:
                raise AssertionError("publication phase fault was not observed")
            finally:
                publication._append_transaction = original_append
                publication._append_records = original_append_records
            assert tripped["value"]
        original_rename = publication._rename_noreplace

        def rename_then_fail(parent):
            original_rename(parent)
            raise RuntimeError("uncertain rename fault")

        publication._rename_noreplace = rename_then_fail
        try:
            publication._publish(destination, second.manifest, second.ustar, pins_value, outer)
        except RuntimeError:
            pass
        else:
            raise AssertionError("uncertain rename fault was not observed")
        finally:
            publication._rename_noreplace = original_rename
        tripped = {"value": False}

        def accepted_then_fail(transaction, parent, content_names, phase, control, name=None, identity=None):
            result = original_append(transaction, parent, content_names, phase, control, name, identity)
            if phase == "accepted":
                tripped["value"] = True
                raise RuntimeError("accepted phase fault")
            return result

        publication._append_transaction = accepted_then_fail
        try:
            publication._publish(destination, second.manifest, second.ustar, pins_value, outer)
        except RuntimeError:
            pass
        finally:
            publication._append_transaction = original_append
        assert tripped["value"]
        candidate = publication._publish(destination, second.manifest, second.ustar, pins_value, outer)
    finally:
        os.umask(hostile_umask)
    accepted_path = destination_path / "accepted"
    assert not (destination_path / ".accepted-candidate-v1").exists()
    assert not (destination_path / ".accepted-transaction-next-v1").exists()
    cache = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache"
    after = tuple((path.name, path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(cache.iterdir()))
    assert before == after and len(after) == 16
    state_root = FIXED / "deploy/aws-feasibility/.state/completion-v1/rootfs-v1"
    assert sorted(path.name for path in state_root.iterdir()) == sorted((builder.STATE_SENTINEL_NAME.text, builder.LOCK_NAME.text))
    accepted_files = sorted(accepted_path.iterdir())
    assert [path.name for path in accepted_files] == [".cogs-rootfs-publication-v1", "rootfs.manifest.json", "rootfs.metadata.json", "rootfs.tar"]
    for path in accepted_files:
        observed = path.stat()
        assert observed.st_mode & 0o7777 == 0o400 and observed.st_nlink == 1 and observed.st_uid == observed.st_gid == 0
    pins = json.loads((accepted_path / "rootfs.metadata.json").read_bytes())
    manifest_bytes = (accepted_path / "rootfs.manifest.json").read_bytes()
    ustar_bytes = (accepted_path / "rootfs.tar").read_bytes()
    assert hashlib.sha256(manifest_bytes).hexdigest() == pins["manifest"]["sha256"]
    assert hashlib.sha256(ustar_bytes).hexdigest() == pins["ustar"]["sha256"]
    transaction_path = destination_path / ".accepted-transaction-v1"
    transaction_before = transaction_path.read_bytes()
    repeated = publication._publish(destination, manifest_bytes, ustar_bytes, publication._load_pins(), outer)
    assert repeated == candidate and transaction_path.read_bytes() == transaction_before
    assert transaction_path.stat().st_mode & 0o7777 == 0o400
    fs._close_node(destination)
    print(json.dumps(dataclasses.asdict(candidate), sort_keys=True, separators=(",", ":")))


if len(sys.argv) == 2 and sys.argv[1] == "--real":
    docker_functional_two_builds()
else:
    portable()

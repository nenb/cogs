#!/usr/bin/env python3
"""Canonical tests and a non-authoritative Docker two-build functional harness."""

import dataclasses
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
CONTAINER_SENTINEL = Path("/cogs-rootfs-functional-test-v1")
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
    assert sys.platform == "linux" and os.geteuid() == 0 and Path("/.dockerenv").is_file()
    observed = CONTAINER_SENTINEL.stat(follow_symlinks=False)
    assert stat.S_ISREG(observed.st_mode) and stat.S_IMODE(observed.st_mode) == 0o400
    assert observed.st_uid == observed.st_gid == 0 and observed.st_nlink == 1
    assert CONTAINER_SENTINEL.read_bytes() == CONTAINER_SENTINEL_RAW
    assert not FIXED.parent.exists()
    remote = FIXED / "deploy/aws-feasibility/remote"
    artifact_root = FIXED / "deploy/aws-feasibility/.state/completion-v1/artifacts"
    cache = artifact_root / "cache"
    remote.mkdir(parents=True, mode=0o700)
    cache.mkdir(parents=True, mode=0o700)
    directories = [Path("/var/lib/cogs"), Path("/var/lib/cogs/stage2-completion-v1"), FIXED, FIXED / "deploy", FIXED / "deploy/aws-feasibility", remote, FIXED / "deploy/aws-feasibility/.state", FIXED / "deploy/aws-feasibility/.state/completion-v1", artifact_root, cache]
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
    original_xattrs = fs._require_empty_fd_xattrs
    ancestors = {(os.lstat(path).st_dev, os.lstat(path).st_ino) for path in ("/", "/var", "/var/lib")}
    fs._open_workspace_anchor = lambda control: fs._open_root_node(control)

    def policy(node, expected, root_key):
        value = node.generation
        assert value.key.kind == expected.kind and value.mode == expected.mode
        assert value.uid == expected.uid and value.gid == expected.gid
        assert value.key.mount_id == root_key.mount_id and value.key.device == root_key.device
        if expected.kind == "file":
            assert value.nlink == 1

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
    stale_candidate = destination_path / ".accepted-candidate-v1"
    stale_candidate.mkdir(mode=0o700)
    stale_sentinel = stale_candidate / ".cogs-rootfs-publication-v1"
    stale_sentinel.write_bytes(b"cogs-rootfs-publication-v1\n")
    stale_sentinel.chmod(0o400)
    assert not (destination_path / "accepted").exists()
    hostile_umask = os.umask(0o777)
    try:
        candidate = build._pinned_publication(approval, destination, outer)
    finally:
        os.umask(hostile_umask)
    accepted_path = destination_path / "accepted"
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
    try:
        publication._publish(destination, manifest_bytes, ustar_bytes, publication._load_pins(), outer)
    except publication.PublicationError:
        pass
    else:
        raise AssertionError("existing accepted publication replaced")
    fs._close_node(destination)
    print(json.dumps(dataclasses.asdict(candidate), sort_keys=True, separators=(",", ":")))


if len(sys.argv) == 2 and sys.argv[1] == "--real":
    docker_functional_two_builds()
else:
    portable()

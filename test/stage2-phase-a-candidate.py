#!/usr/bin/env python3
"""Portable pure tests for the ADR0046 Phase A candidate runner."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run-stage2-phase-a-candidate.py"
spec = importlib.util.spec_from_file_location("stage2_phase_a_candidate", RUNNER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def rejected(callback):
    try:
        callback()
    except module.CandidateError:
        return
    raise AssertionError("hostile candidate input accepted")


def failure_code(callback):
    try:
        callback()
    except module.CandidateError as error:
        return error.code
    raise AssertionError("expected candidate failure")


assert tuple((item.component, item.release, item.size, item.sha256) for item in module.RUNTIME_ASSETS) == (
    ("kata", "3.32.0", 1547940938, "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01"),
    ("containerd", "2.2.1", 33645699, "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883"),
)
for asset in module.RUNTIME_ASSETS:
    assert module._strict_url(asset.url).hostname == "github.com"

kata = module.RUNTIME_ASSETS[0]
valid = "https://release-assets.githubusercontent.com/github-production-release-asset/123/abc?sig=fixed"
assert module._redirect_target(kata, valid) == valid
for hostile in (
    "http://release-assets.githubusercontent.com/github-production-release-asset/123/abc?sig=x",
    "https://evil.invalid/github-production-release-asset/123/abc?sig=x",
    "https://release-assets.githubusercontent.com/other/123?sig=x",
    "https://release-assets.githubusercontent.com/github-production-release-asset/123/abc",
):
    rejected(lambda hostile=hostile: module._redirect_target(kata, hostile))

base = module._base_report()
raw = module._canonical_report(base)
assert json.loads(raw) == base
for changed in (
    {**base, "authority": "committed"},
    {**base, "qualified": True},
    {**base, "claims": {**base["claims"], "runtime": True}},
    {**base, "blockers": []},
    {**base, "unexpected": True},
):
    rejected(lambda changed=changed: module._canonical_report(changed))

class FakeVerificationError(Exception):
    def __init__(self, stage=None):
        self.stage = stage

fake_verification_module = types.SimpleNamespace(VerificationError=FakeVerificationError)
for stage, expected in (
    (None, "cache-acquisition-unknown"),
    ("preflight", "cache-acquisition-preflight"),
    ("tls", "cache-acquisition-tls"),
    ("token.status", "cache-acquisition-token"),
    ("artifact.redirect.location", "cache-acquisition-redirect"),
    ("artifact.body", "cache-acquisition-body"),
    ("artifact.final.length", "cache-acquisition-response"),
    ("postverify", "cache-postverify"),
):
    code = failure_code(lambda stage=stage: module._verifier_call(
        fake_verification_module, "rootfs-contract-preflight",
        lambda: (_ for _ in ()).throw(FakeVerificationError(stage)), acquisition=stage is not None,
    ))
    assert code == ("rootfs-contract-preflight" if stage is None else expected)

calls = []
class FakeBuild:
    @staticmethod
    def _require_equal_builds(first, second):
        calls.append("equal")
        if first != second:
            raise module.CandidateError("rootfs-mismatch")
    @staticmethod
    def _require_pinned(candidate, pins):
        calls.append(("pin", candidate, pins))
class FakePublication:
    @staticmethod
    def _load_pins():
        calls.append("pins")
        return "committed-pins"
assert module._verify_candidate_pair(FakeBuild, FakePublication, "same", "same") == "committed-pins"
assert calls == ["equal", "pins", ("pin", "same", "committed-pins"), ("pin", "same", "committed-pins")]
calls.clear()
rejected(lambda: module._verify_candidate_pair(FakeBuild, FakePublication, "first", "mismatch"))
assert calls == ["equal"]

remote = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(remote))
import completion_rootfs_build as actual_build
import completion_rootfs_publish as actual_publish
assert actual_build.publication is actual_publish

candidate = types.SimpleNamespace(
    cache=tuple(range(16)), entry_count=4353, manifest=b"m" * 1049443,
    manifest_sha256="8" * 64, ustar_size=136905728, ustar_sha256="4" * 64,
)
fake_build = types.ModuleType("completion_rootfs_build")
fake_build._two_build_outputs = lambda _approval, _control: (candidate, candidate)
fake_build._require_equal_builds = lambda first, second: None if first is second else (_ for _ in ()).throw(AssertionError())
fake_build._require_pinned = lambda _candidate, _pins: None
fake_fs = types.ModuleType("completion_rootfs_fs")
fake_fs.SourceApproval = lambda revision, digest: (revision, digest)
fake_fs.OperationControl = lambda deadline, cancelled: (deadline, cancelled)
fake_publish = types.ModuleType("completion_rootfs_publish")
fake_publish._load_pins = lambda: object()
fake_verifier = types.SimpleNamespace(
    CONTRACT_PATH="contract", ARTIFACT_ROOT="artifacts", verify_contract=lambda _path: {"fixed": True},
    acquire_completion_artifacts=lambda *_args: None, verify_package_archives=lambda *_args: None,
)
original_modules = {name: sys.modules.get(name) for name in
                    ("completion_rootfs_build", "completion_rootfs_fs", "completion_rootfs_publish")}
original_helpers = (module._load_artifact_verifier, module._append_journal,
                    module._snapshot_cache, module._snapshot_rootfs_lifecycle)
try:
    sys.modules["completion_rootfs_build"] = fake_build
    sys.modules["completion_rootfs_fs"] = fake_fs
    sys.modules["completion_rootfs_publish"] = fake_publish
    module._load_artifact_verifier = lambda: fake_verifier
    module._append_journal = lambda *_args: None
    module._snapshot_cache = lambda _contract: {"cache": "fixed"}
    module._snapshot_rootfs_lifecycle = lambda: {"rootfs": "fixed"}
    result = module._rootfs_candidates("a" * 40, "b" * 64, time.monotonic() + 10)
    assert result["equal"] is True and result["pins_match"] is True and result["cache_count"] == 16
finally:
    module._load_artifact_verifier, module._append_journal, module._snapshot_cache, module._snapshot_rootfs_lifecycle = original_helpers
    for name, value in original_modules.items():
        if value is None:
            del sys.modules[name]
        else:
            sys.modules[name] = value

original_timeout = module.HOST_TOOL_SECONDS
module.HOST_TOOL_SECONDS = 0.2
started = time.monotonic()
try:
    rejected(lambda: module._stream_command(sys.executable, ("-c", "import os,signal,time; child=os.fork(); "
        "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(10)"), (0,)))
finally:
    module.HOST_TOOL_SECONDS = original_timeout
assert time.monotonic() - started < 4

module.HOST_TOOL_SECONDS = 2
try:
    code = failure_code(lambda: module._stream_command(sys.executable, ("-c",
        "import os,time; child=os.fork(); "
        "os._exit(0) if child==0 and False else None; "
        "(os.close(1),os.close(2),time.sleep(10),os._exit(0)) if child==0 else os._exit(0)"), (0,)))
    assert code in {"host-tool-descendants", "host-tool-unreaped"}
finally:
    module.HOST_TOOL_SECONDS = original_timeout

first = module._journal_record(0, "0" * 64, "genesis", {"fixed": True})
second = module._journal_record(1, first["sha256"], "asset-intent", {"name": "fixed"})
assert module._parse_journal(module._canonical(first) + b"\n" + module._canonical(second) + b"\n") == [first, second]
tampered = {**second, "body": {"name": "replacement"}}
rejected(lambda: module._parse_journal(module._canonical(first) + b"\n" + module._canonical(tampered) + b"\n"))

class Node:
    st_dev = 1
    st_ino = 2
    st_mode = 0o040700
    st_uid = 0
    st_gid = 0
    st_nlink = 2
    st_size = 64
state_identity = module._identity(Node())
journal_node = Node(); journal_node.st_ino = 3; journal_node.st_mode = 0o100600; journal_node.st_nlink = 1
journal_identity = module._identity(journal_node)
anchor_value = {
    "version": "cogs.stage2-phase-a-anchor/v1", "source_revision": "a" * 40,
    "source_manifest_sha256": "b" * 64, "trusted_parent_chain": [],
    "state": state_identity, "journal": journal_identity,
}
assert module._parse_anchor(module._canonical(anchor_value) + b"\n") == anchor_value
mutable_state = Node(); mutable_state.st_size = 4096; mutable_state.st_nlink = 99
module._validate_anchored_nodes(anchor_value, mutable_state, journal_node)
moved_state = Node(); moved_state.st_ino = 99
rejected(lambda: module._validate_anchored_nodes(anchor_value, moved_state, journal_node))
moved_journal = Node(); moved_journal.st_ino = 99; moved_journal.st_mode = 0o100600; moved_journal.st_nlink = 1
rejected(lambda: module._validate_anchored_nodes(anchor_value, mutable_state, moved_journal))
forged = module._canonical(anchor_value).replace(b'"version":', b'"version":"forged","version":', 1) + b"\n"
rejected(lambda: module._parse_anchor(forged))
anchor_node = Node(); anchor_node.st_ino = 4; anchor_node.st_mode = 0o100400; anchor_node.st_nlink = 1
anchor_identity = module._identity(anchor_node)
anchor_raw = module._canonical(anchor_value) + b"\n"
anchor_digest = module.hashlib.sha256(anchor_raw).hexdigest()
genesis = {"anchor_sha256": anchor_digest, "state": state_identity,
           "journal": journal_identity, "anchor": anchor_identity}
module._validate_anchor_journal(anchor_value, anchor_digest, genesis, anchor_node)
rejected(lambda: module._validate_anchor_journal(anchor_value, "0" * 64, genesis, anchor_node))
moved_anchor = Node(); moved_anchor.st_ino = 40; moved_anchor.st_mode = 0o100400; moved_anchor.st_nlink = 1
rejected(lambda: module._validate_anchor_journal(anchor_value, anchor_digest, genesis, moved_anchor))

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-replacement-") as temporary:
    directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    path = Path(temporary, "owned")
    path.write_bytes(b"owned")
    descriptor = os.open("owned", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    identity = module._identity(os.fstat(descriptor))
    path.unlink()
    path.write_bytes(b"replacement")
    rejected(lambda: module._unlink_exact(directory, "owned", descriptor, identity,
                                          module.hashlib.sha256(b"owned").hexdigest()))
    assert path.read_bytes() == b"replacement"
    os.close(descriptor)
    os.close(directory)

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-assets-cleanup-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    assets = Path(temporary, "assets")
    assets.mkdir(mode=0o700)
    directory_identity = module._identity(assets.stat(follow_symlinks=False))
    body = b"asset-bytes"
    final = assets / "fixed.bin"
    final.write_bytes(body)
    final.chmod(0o400)
    file_identity = module._identity(final.stat(follow_symlinks=False))
    populated_directory = module._identity(assets.stat(follow_symlinks=False))
    assert (populated_directory["size"], populated_directory["nlink"]) != (
        directory_identity["size"], directory_identity["nlink"])
    records = [
        {"kind": "asset-directory-owned", "body": {"identity": directory_identity}},
        {"kind": "asset-final-owned", "body": {
            "name": final.name, "identity": file_identity, "sha256": module.hashlib.sha256(body).hexdigest(),
        }},
    ]
    original_assets, original_open_dir = module.ASSETS, module._open_dir
    try:
        module.ASSETS = assets
        module._open_dir = lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        assert module._cleanup_assets.__globals__["ASSETS"] == assets
        module._cleanup_assets(records)
        assert not assets.exists()
    finally:
        module.ASSETS, module._open_dir = original_assets, original_open_dir

with tempfile.TemporaryDirectory(prefix="cogs-phase-a-export-cleanup-",
                                 dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as temporary:
    export_root = Path(temporary, "export")
    export_root.mkdir(mode=0o755)
    directory_identity = module._identity(export_root.stat(follow_symlinks=False))
    exported = export_root / "candidate.json"
    raw_export = b'{"authority":"candidate","qualified":false}\n'
    exported.write_bytes(raw_export)
    exported.chmod(0o444)
    populated_directory = module._identity(export_root.stat(follow_symlinks=False))
    assert (populated_directory["size"], populated_directory["nlink"]) != (
        directory_identity["size"], directory_identity["nlink"])
    owned = {
        "directory": directory_identity, "file": module._identity(exported.stat(follow_symlinks=False)),
        "sha256": module.hashlib.sha256(raw_export).hexdigest(),
    }
    records = [{"kind": "export-owned", "body": owned}]
    originals = (module.EXPORT_ROOT, module.EXPORT_REPORT, module._fixed_preflight,
                 module._require_state, module._append_journal)
    appended = []
    try:
        module.EXPORT_ROOT = export_root
        module.EXPORT_REPORT = exported
        module._fixed_preflight = lambda _approval: None
        module._require_state = lambda: records
        module._append_journal = lambda kind, body: appended.append((kind, body))
        assert module._cleanup_export() == 0
        assert not export_root.exists()
        assert appended == [("export-cleaned", {"sha256": owned["sha256"]})]
    finally:
        (module.EXPORT_ROOT, module.EXPORT_REPORT, module._fixed_preflight,
         module._require_state, module._append_journal) = originals

# The direct KVM proof is fixed to linux/kvm.h KVM_GET_API_VERSION and accepts
# only ABI version 12. No VM process or host package mutation is involved.
class Device:
    st_mode = 0o020600
    st_dev = 1
    st_ino = 2
    st_rdev = 3

originals = (module.os.stat, module.os.access, module.os.open, module.os.fstat, module.os.close, module.fcntl.ioctl)
closed = []
try:
    module.os.stat = lambda *_args, **_kwargs: Device()
    module.os.access = lambda *_args, **_kwargs: True
    module.os.open = lambda *_args, **_kwargs: 99
    module.os.fstat = lambda descriptor: Device() if descriptor == 99 else None
    module.os.close = lambda descriptor: closed.append(descriptor)
    module.fcntl.ioctl = lambda descriptor, request: 12 if (descriptor, request) == (99, module.KVM_GET_API_VERSION) else None
    assert module._prove_kvm() == {"device_present": True, "device_accessible": True, "api_version": 12}
    assert closed == [99]
    module.fcntl.ioctl = lambda *_args: 11
    rejected(module._prove_kvm)
finally:
    module.os.stat, module.os.access, module.os.open, module.os.fstat, module.os.close, module.fcntl.ioctl = originals

source = RUNNER.read_text(encoding="utf-8")
assert "KVM_GET_API_VERSION = 0xAE00" in source and "fcntl.ioctl(descriptor, KVM_GET_API_VERSION)" in source
assert "extractall" not in source and ".extract(" not in source
assert "completion_kata_coordinator" not in source
assert "runtime-extraction-unsafe-or-unknown" in source
assert "build._require_equal_builds(first, second)" in source
assert "start_new_session=True" in source and "os.killpg(process.pid" in source
assert "EXPORT_REPORT" in source and '"export-owned"' in source
assert '128, 0o600' in source and 'sentinel_identity["mode"] == 0o600' in source
print("stage2 phase-a candidate portable tests passed")

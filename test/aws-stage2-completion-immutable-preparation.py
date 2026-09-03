#!/usr/bin/env python3
"""Fresh-root fault/order matrix for immutable pre-custody preparation."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from unittest.mock import patch

REMOTE = Path(__file__).resolve().parents[1] / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
spec = importlib.util.spec_from_file_location(
    "completion_kata_immutable_preparation_test",
    REMOTE / "completion_kata_immutable_preparation.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
import completion_rootfs_prebuilt as prebuilt
import completion_rootfs_prebuilt_acquisition as prebuilt_acquisition


def descriptor_value():
    digest = "1" * 64
    return {
        "version": prebuilt.VERSION, "authority": prebuilt.AUTHORITY,
        "artifact": {"version": prebuilt.ARTIFACT_VERSION, "os": "linux", "architecture": prebuilt.ARCHITECTURE, "format": prebuilt.FORMAT},
        "registry": {"host": prebuilt.REGISTRY_HOST, "repository": prebuilt.REGISTRY_REPOSITORY,
                     "manifest_media_type": prebuilt.REGISTRY_MANIFEST_MEDIA_TYPE,
                     "manifest_digest": digest, "layer_media_type": prebuilt.REGISTRY_LAYER_MEDIA_TYPE,
                     "layer_digest": prebuilt.USTAR_SHA256, "layer_size": prebuilt.USTAR_SIZE},
        "rootfs": {"metadata_sha256": prebuilt.METADATA_SHA256, "metadata_size": prebuilt.METADATA_SIZE,
                   "manifest_sha256": prebuilt.MANIFEST_SHA256, "manifest_size": prebuilt.MANIFEST_SIZE,
                   "ustar_sha256": prebuilt.USTAR_SHA256, "ustar_size": prebuilt.USTAR_SIZE,
                   "entry_count": prebuilt.ENTRY_COUNT, "source_date_epoch": prebuilt.model.SOURCE_DATE_EPOCH},
        "producer": {"revision": "2" * 40, "source_manifest_sha256": digest,
                     "input_contract_sha256": prebuilt.INPUT_CONTRACT_SHA256,
                     "package_manifest_sha256": digest, "provenance_sha256": digest,
                     "qualification_receipt_sha256": digest, "publication_receipt_sha256": digest},
    }

# Extractor admission closes every ownership/mode/executable predicate and
# observes capacity on the actual fixed-source filesystem.
regular = stat.S_IFREG | 0o755
assert module._extractor_identity(os.stat_result((regular, 1, 1, 1, 0, 0, 1, 0, 0, 0)), True)
for seen, executable in (
    (os.stat_result((stat.S_IFDIR | 0o755, 1, 1, 1, 0, 0, 1, 0, 0, 0)), True),
    (os.stat_result((regular, 1, 1, 1, 1, 0, 1, 0, 0, 0)), True),
    (os.stat_result((stat.S_IFREG | 0o775, 1, 1, 1, 0, 0, 1, 0, 0, 0)), True),
    (os.stat_result((regular, 1, 1, 1, 0, 0, 1, 0, 0, 0)), False),
):
    assert not module._extractor_identity(seen, executable)
original_extractors, original_statvfs, original_source = module.EXTRACTORS, module.os.statvfs, module.SOURCE_ROOT
with tempfile.TemporaryDirectory() as temporary:
    observed = []
    module.EXTRACTORS = ()
    module.SOURCE_ROOT = Path(temporary)
    module.os.statvfs = lambda path: (observed.append(path) or type("Space", (), {
        "f_bavail": 12 * 1024**3, "f_frsize": 1, "f_favail": 200_000})())
    module._extractor_preflight()
    assert observed == [module.SOURCE_ROOT]
module.EXTRACTORS, module.os.statvfs, module.SOURCE_ROOT = original_extractors, original_statvfs, original_source
class Device:
    def __init__(self, device): self.device = device
    def lstat(self): return type("Seen", (), {"st_dev": self.device})()
original_source, original_completion = module.SOURCE_ROOT, module.COMPLETION_ROOT
module.SOURCE_ROOT, module.COMPLETION_ROOT = Device(1), Device(2)
try:
    module._verify_extraction_filesystem()
except module.ImmutablePreparationError:
    pass
else:
    raise AssertionError("separate extraction filesystem accepted")
module.SOURCE_ROOT, module.COMPLETION_ROOT = original_source, original_completion

# Runtime manifests use canonical size zero for symlinks; lstat size is the
# platform link-target byte count and is not a file-content size.
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    module.STAGED_RUNTIME = root / "runtime"
    module.KATA_ROOT = root / "kata"
    module.STAGED_RUNTIME.mkdir()
    module.KATA_ROOT.mkdir()
    regular = module.STAGED_RUNTIME / "containerd"
    regular.write_bytes(b"runtime")
    regular.chmod(0o500)
    link = module.KATA_ROOT / "image"
    link.symlink_to("kata-containers.img")
    expected = {"launch": {"artifacts": [
        {"path": str(regular), "kind": "file", "mode": 0o500,
         "size": 7, "sha256": hashlib.sha256(b"runtime").hexdigest(), "link_target": None},
        {"path": str(link), "kind": "symlink", "mode": stat.S_IMODE(link.lstat().st_mode),
         "size": 0, "sha256": None, "link_target": "kata-containers.img"},
    ]}}
    module._verify_installed(expected)
    expected["launch"]["artifacts"][1]["size"] = len("kata-containers.img")
    try:
        module._verify_installed(expected)
    except module.ImmutablePreparationError:
        pass
    else:
        raise AssertionError("noncanonical symlink size was accepted")


def configure(root, fail_at=None):
    source = root / "var/lib/cogs/stage2-completion-v1/source"
    completion = source / "deploy/aws-feasibility/.state/completion-v1"
    completion.mkdir(parents=True)
    opt = root / "opt"
    opt.mkdir()
    module.SOURCE_ROOT = source
    module.CONTROL_ROOT = root / "var/lib/cogs/stage2-completion-v1/control"
    module.COMPLETION_ROOT = completion
    module.ARTIFACT_ROOT = completion / "artifacts"
    module.PREPARATION_ROOT = completion / "immutable-preparation-v1"
    module.RUNTIME_CACHE = module.PREPARATION_ROOT / "runtime-cache"
    module.EXTRACTED_ROOT = module.PREPARATION_ROOT / "extracted"
    module.RECEIPT = module.PREPARATION_ROOT / "receipt.json"
    module.OWNERSHIP = module.PREPARATION_ROOT / "ownership.json"
    module.STAGED_RUNTIME = completion / "kata-runtime-v1"
    module.IMMUTABLE_STAGING = completion / ".kata-runtime-v1.immutable-staging"
    module.KATA_PARENT = opt
    module.KATA_ROOT = opt / "kata"
    prebuilt_root = root / "var/lib/cogs/stage2-completion-v1/prebuilt-rootfs-input-v1"
    module.preparation.PREBUILT_INPUT_ROOT = prebuilt_root
    module.preparation.PREBUILT_DESCRIPTOR_ROOT = root / "var/lib/cogs/stage2-prebuilt-rootfs-descriptor-v1"
    module.preparation.PREBUILT_DESCRIPTOR_PATH = module.preparation.PREBUILT_DESCRIPTOR_ROOT / "descriptor.json"
    module.preparation.PREBUILT_USTAR_PATH = prebuilt_root / "rootfs.tar"
    prebuilt_acquisition.ROOT = prebuilt_root
    events = []
    module._reject_ambient_authority = lambda: events.append("gate")
    module._chown_root = lambda _descriptor: None
    artifact_rows = tuple({"cache_name": f"asset-{index:02d}", "size": len(f"asset-{index:02d}".encode()),
                           "sha256": hashlib.sha256(f"asset-{index:02d}".encode()).hexdigest()}
                          for index in range(16))
    module._fixed_contract = lambda: {"bounds": {"artifact_count": 16}}
    module._artifact_rows = lambda _contract: artifact_rows
    descriptor = descriptor_value()
    module._expected_runtime = lambda: {
        "rootfs": {"prebuilt_descriptor": descriptor,
                   "prebuilt_descriptor_sha256": hashlib.sha256(
                       module.preparation.canonical_bytes(descriptor)).hexdigest()}}
    prebuilt.load_authority = lambda _descriptor, _raw: object()

    def stable(path, expected, mode=0o400):
        raw = path.read_bytes()
        if path.parent == module.RUNTIME_CACHE:
            assert raw == expected["role"].encode()
            return
        wanted = path.name.encode()
        assert raw == wanted and len(raw) == expected["size"]
        assert hashlib.sha256(raw).hexdigest() == expected["sha256"]

    def acquisition(descriptor_raw):
        events.append("rootfs-one")
        prebuilt_root.mkdir(mode=0o700)
        path = prebuilt_root / "rootfs.tar"
        path.write_bytes(b"prebuilt-test")
        path.chmod(0o400)
        if fail_at == "rootfs":
            raise module.ImmutablePreparationError()
        parsed = prebuilt.decode_fixed_descriptor(descriptor_raw)
        return prebuilt_acquisition.AcquisitionReceipt(
            hashlib.sha256(descriptor_raw).hexdigest(), parsed.manifest_digest,
            parsed.layer_digest, parsed.layer_size, "a" * 64, "b" * 64,
            str(path), True)

    def remove_prebuilt(_descriptor, cleanup_descriptor_raw):
        assert cleanup_descriptor_raw == module.preparation.canonical_bytes(descriptor)
        if prebuilt_root.exists():
            paths = list(prebuilt_root.iterdir())
            if paths:
                assert len(paths) == 1 and paths[0].name == "rootfs.tar"
                assert paths[0].read_bytes() == b"prebuilt-test"
                assert stat.S_IMODE(paths[0].stat().st_mode) == 0o400
                paths[0].unlink()
            prebuilt_root.rmdir()

    prebuilt_acquisition.acquire_fixed = acquisition
    module._remove_prebuilt_input = remove_prebuilt

    def download(pin, _deadline):
        events.append("download-" + pin["role"])
        path = module.RUNTIME_CACHE / pin["name"]
        path.write_bytes(pin["role"].encode())
        return path

    def extract(_archive, destination):
        events.append("extract-" + destination.name)
        destination.mkdir()
        if destination.name == "kata":
            (destination / "opt/kata").mkdir(parents=True)
            target = destination / "opt/kata/fixture"
        else:
            target = destination / "verified"
        target.write_bytes(b"fixed")
        target.chmod(0o400)
        if fail_at == "extract-" + destination.name:
            raise module.ImmutablePreparationError()

    def values(_expected, archives, extracted):
        events.append("layout-readback")
        assert set(archives) == set(extracted) == {"kata", "containerd"}
        result = []
        for pin in module.preparation.ARCHIVES:
            rows = module.preparation.extracted_postwalk(extracted[pin["role"]])
            section = module.preparation.section(rows)
            result.append({**pin, "layout": section, "extracted": section})
        return result

    def static_rows():
        active = module.STAGED_RUNTIME if module.STAGED_RUNTIME.exists() else module.IMMUTABLE_STAGING
        if not active.exists():
            return []
        bin_seen = (active / "bin").lstat()
        rows = [{"path": "bin", "kind": "directory", "mode": 0o500,
                 "uid": bin_seen.st_uid, "gid": bin_seen.st_gid, "size": 0,
                 "link_target": None, "sha256": None}]
        for name in ("containerd", "ctr"):
            path = active / "bin" / name
            if path.exists():
                seen = path.lstat()
                rows.append({"path": f"bin/{name}", "kind": "file", "mode": 0o500,
                             "uid": seen.st_uid, "gid": seen.st_gid,
                             "size": len(b"not-launched"), "link_target": None,
                             "sha256": hashlib.sha256(b"not-launched").hexdigest()})
        return rows
    module._static_runtime_rows = static_rows

    def publish(extracted):
        events.append("publish-static")
        (module.IMMUTABLE_STAGING / "bin").mkdir(parents=True)
        for name in ("containerd", "ctr"):
            path = module.IMMUTABLE_STAGING / "bin" / name
            path.write_bytes(b"not-launched")
            path.chmod(0o500)
        (module.IMMUTABLE_STAGING / "bin").chmod(0o500)
        module.IMMUTABLE_STAGING.rename(module.STAGED_RUNTIME)
        module.STAGED_RUNTIME.chmod(0o500)
        (extracted["kata"] / "opt/kata").rename(module.KATA_ROOT)
        if fail_at == "publish":
            raise module.ImmutablePreparationError()

    def verify(_expected):
        events.append("installed-readback")
        assert (module.STAGED_RUNTIME / "bin/containerd").read_bytes() == b"not-launched"
        assert (module.KATA_ROOT / "fixture").read_bytes() == b"fixed"

    module._stable_file = stable
    module._extractor_preflight = lambda: events.append("extractor-preflight")
    module._download_runtime = download
    module._run_extract = extract
    module._archive_values = values
    module._publish_runtime = publish
    module._verify_installed = verify
    return events


# Diagnostic recovery accepts the external custody directory only when every
# canonical member equals the already validated diagnostic control projection.
diagnostic_descriptor = descriptor_value()
diagnostic_runtime = {"rootfs": {
    "prebuilt_descriptor": diagnostic_descriptor,
    "prebuilt_descriptor_sha256": hashlib.sha256(
        module.preparation.canonical_bytes(diagnostic_descriptor)).hexdigest(),
}}
diagnostic_custody = {
    "package_manifest": {"kind": "package"},
    "provenance": {"kind": "provenance"},
    "qualification_receipt": {"kind": "qualification"},
    "publication_receipt": {"kind": "publication"},
    "signature_verification_sha256": hashlib.sha256(b"signature").hexdigest(),
}
diagnostic_paths = {
    module.preparation.PREBUILT_DESCRIPTOR_PATH:
        module.preparation.canonical_bytes(diagnostic_descriptor),
    module.preparation.PREBUILT_PACKAGE_PATH:
        module.preparation.canonical_bytes(diagnostic_custody["package_manifest"]),
    module.preparation.PREBUILT_PROVENANCE_PATH:
        module.preparation.canonical_bytes(diagnostic_custody["provenance"]),
    module.preparation.PREBUILT_QUALIFICATION_RECEIPT_PATH:
        module.preparation.canonical_bytes(diagnostic_custody["qualification_receipt"]),
    module.preparation.PREBUILT_PUBLICATION_RECEIPT_PATH:
        module.preparation.canonical_bytes(diagnostic_custody["publication_receipt"]),
    module.preparation.PREBUILT_SIGNATURE_VERIFICATION_PATH: b"signature",
}
with patch.object(module, "_descriptor_root") as diagnostic_root, \
     patch.object(module, "_read_external_member",
                  side_effect=lambda path: diagnostic_paths[path]):
    assert module._diagnostic_descriptor_bytes(
        diagnostic_runtime, diagnostic_custody) == diagnostic_paths[
            module.preparation.PREBUILT_DESCRIPTOR_PATH]
    diagnostic_root.assert_called_once()
with patch.object(module, "_descriptor_root"), \
     patch.object(module, "_read_external_member", return_value=b"changed"):
    try:
        module._diagnostic_descriptor_bytes(diagnostic_runtime, diagnostic_custody)
    except module.ImmutablePreparationError:
        pass
    else:
        raise AssertionError("changed diagnostic custody was accepted")

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    events = configure(root)
    result = module.prepare()
    assert result["rootfs_artifact_count"] == 1
    assert result["runtime_archive_count"] == 2
    assert result["control_verified"] is True
    assert events == [
        "gate", "extractor-preflight", "rootfs-one", "download-kata", "download-containerd",
        "extract-kata", "extract-containerd", "layout-readback",
        "publish-static", "installed-readback",
    ]
    receipt = json.loads(module.RECEIPT.read_bytes())
    assert receipt["forbidden_surfaces"] == [
        "containerd", "ctr", "kvm", "qmp", "ssh", "task", "guest-network"]
    assert module.STAGED_RUNTIME.exists() and module.KATA_ROOT.exists()
    assert stat.S_IMODE(module.STAGED_RUNTIME.lstat().st_mode) == 0o500
    assert stat.S_IMODE((module.STAGED_RUNTIME / "bin").lstat().st_mode) == 0o500
    module.recover_failed_preparation()
    assert not module.PREPARATION_ROOT.exists()
    assert not module.STAGED_RUNTIME.exists() and not module.KATA_ROOT.exists()
    assert not module.ARTIFACT_ROOT.exists()

# Immutable cleanup may proceed beside only an independently authenticated
# idle rootfs owner. Active or uncertain rootfs state remains a hard stop.
original_rootfs_idle = module._rootfs_state_idle
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); configure(root)
    module.prepare()
    rootfs_state = module.COMPLETION_ROOT / "rootfs-v1"
    rootfs_state.mkdir(mode=0o700)
    module._rootfs_state_idle = lambda: True
    module.recover_failed_preparation()
    assert rootfs_state.is_dir() and not module.PREPARATION_ROOT.exists()
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); configure(root)
    module.prepare()
    (module.COMPLETION_ROOT / "rootfs-v1").mkdir(mode=0o700)
    module._rootfs_state_idle = lambda: False
    try:
        module.recover_failed_preparation()
    except module.ImmutablePreparationError:
        pass
    else:
        raise AssertionError("active rootfs state did not block immutable recovery")
    assert module.PREPARATION_ROOT.exists()
module._rootfs_state_idle = original_rootfs_idle

# A completed lifecycle retires its journal while intentionally retaining the
# authenticated operation infrastructure for fixed-root settlement. Immutable
# rollback accepts only that independently classified idle shape.
original_operation_idle = module._operation_state_idle
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); configure(root)
    module.prepare()
    operation_state = module.COMPLETION_ROOT / "kata-operation-v1"
    operation_state.mkdir(mode=0o700)
    module._operation_state_idle = lambda: True
    module.recover_failed_preparation()
    assert operation_state.is_dir() and not module.PREPARATION_ROOT.exists()
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); configure(root)
    module.prepare()
    (module.COMPLETION_ROOT / "kata-operation-v1").mkdir(mode=0o700)
    module._operation_state_idle = lambda: False
    try:
        module.recover_failed_preparation()
    except module.ImmutablePreparationError:
        pass
    else:
        raise AssertionError("active operation state did not block immutable recovery")
    assert module.PREPARATION_ROOT.exists()
module._operation_state_idle = original_operation_idle

for cut in ("rootfs", "extract-kata", "extract-containerd", "publish"):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        configure(root, cut)
        try:
            module.prepare()
        except BaseException:
            pass
        else:
            raise AssertionError("fault cut unexpectedly succeeded: " + cut)
        if cut.startswith("extract-"):
            assert module.PREPARATION_ROOT.exists(), "uncertain extracted bytes were deleted"
        else:
            assert not module.PREPARATION_ROOT.exists()
            assert not module.STAGED_RUNTIME.exists()
            assert not module.KATA_ROOT.exists()
            assert not module.ARTIFACT_ROOT.exists()

# A SIGTERM-style interrupted runtime download leaves no Python finally path.
# Recovery authenticates only the exact root-created partial or its crash-cut
# quarantine generation; changed policy is preserved.
for suffix in (".partial", ".partial.removing"):
    with tempfile.TemporaryDirectory() as temporary:
        configure(Path(temporary))
        def interrupted(pin, _deadline, suffix=suffix):
            path = module.RUNTIME_CACHE / ("." + pin["name"] + suffix)
            path.write_bytes(b"interrupted")
            path.chmod(0o600)
            raise KeyboardInterrupt()
        module._download_runtime = interrupted
        try:
            module.prepare()
        except BaseException:
            pass
        else:
            raise AssertionError("interrupted runtime download unexpectedly succeeded")
        assert not module.PREPARATION_ROOT.exists()
        assert not module.ARTIFACT_ROOT.exists()

with tempfile.TemporaryDirectory() as temporary:
    configure(Path(temporary))
    def changed_partial(pin, _deadline):
        path = module.RUNTIME_CACHE / ("." + pin["name"] + ".partial")
        path.write_bytes(b"changed-policy")
        path.chmod(0o644)
        raise KeyboardInterrupt()
    module._download_runtime = changed_partial
    try:
        module.prepare()
    except BaseException:
        pass
    else:
        raise AssertionError("changed runtime partial unexpectedly succeeded")
    changed = next(module.RUNTIME_CACHE.glob("*.partial"))
    assert changed.read_bytes() == b"changed-policy"
    # The failed rollback already settled later independent artifact custody.
    # Correcting only the diagnostic fixture's policy exercises restart from
    # an absent transaction-owned artifact root without hiding foreign state.
    changed.chmod(0o600)
    module.recover_failed_preparation()
    assert not module.PREPARATION_ROOT.exists() and not module.ARTIFACT_ROOT.exists()

# A retained exact cache object remains while transaction-created siblings are
# removed after failure.
with tempfile.TemporaryDirectory() as temporary:
    configure(Path(temporary), "rootfs")
    cache = module.ARTIFACT_ROOT / "cache"
    cache.mkdir(parents=True)
    module.ARTIFACT_ROOT.chmod(0o700)
    cache.chmod(0o700)
    retained = cache / "asset-00"
    retained.write_bytes(b"asset-00")
    retained.chmod(0o400)
    try:
        module.prepare()
    except BaseException:
        pass
    else:
        raise AssertionError("retained-cache fault unexpectedly succeeded")
    assert retained.read_bytes() == b"asset-00"
    assert set(path.name for path in cache.iterdir()) == {"asset-00"}
    assert not module.PREPARATION_ROOT.exists()

# Changed immutable staging and foreign cache material are never adopted or
# hidden by an ignore-errors rollback. Exact independent material may settle.
with tempfile.TemporaryDirectory() as temporary:
    configure(Path(temporary))
    module.prepare()
    changed = module.STAGED_RUNTIME / "bin/containerd"
    changed.chmod(0o600)
    changed.write_bytes(b"changed")
    try:
        module.recover_failed_preparation()
    except BaseException:
        pass
    else:
        raise AssertionError("changed immutable staging was removed")
    assert changed.read_bytes() == b"changed"

with tempfile.TemporaryDirectory() as temporary:
    configure(Path(temporary))
    module.prepare()
    changed_asset = module.preparation.PREBUILT_USTAR_PATH
    changed_asset.chmod(0o600)
    changed_asset.write_bytes(b"changed")
    try:
        module.recover_failed_preparation()
    except BaseException:
        pass
    else:
        raise AssertionError("changed transaction cache material was removed")
    assert changed_asset.read_bytes() == b"changed"

with tempfile.TemporaryDirectory() as temporary:
    configure(Path(temporary))
    module.prepare()
    foreign = module.preparation.PREBUILT_INPUT_ROOT / "foreign"
    foreign.write_bytes(b"foreign")
    try:
        module.recover_failed_preparation()
    except BaseException:
        pass
    else:
        raise AssertionError("foreign cache material was ignored")
    assert foreign.read_bytes() == b"foreign"

with tempfile.TemporaryDirectory() as temporary:
    source_root = Path(temporary) / "source"
    (source_root / "deploy/aws-feasibility").mkdir(parents=True)
    module.SOURCE_ROOT = source_root
    module.COMPLETION_ROOT = source_root / "deploy/aws-feasibility/.state/completion-v1"
    module._prepare_state_parents()
    assert module.COMPLETION_ROOT.is_dir()
    assert not module.COMPLETION_ROOT.stat().st_mode & 0o022

isolated = subprocess.run(
    (sys.executable, "-I", "-B", "-c",
     "import runpy,sys;runpy.run_path(sys.argv[1],run_name='isolated_import')",
     str(REMOTE / "completion_kata_immutable_preparation.py")),
    cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    timeout=30, check=False)
assert isolated.returncode == 0, isolated.stderr
source = (REMOTE / "completion_kata_immutable_preparation.py").read_text()
assert "def prepare():" in source and "def main():" in source
assert "subprocess.Popen" not in source
assert "containerd --" not in source and "ctr --" not in source
assert "AWS_" in source and "DENIED_ENV" in source
assert "ignore_errors" not in source and "shutil.rmtree" not in source
assert "_remove_verified_tree" in source and "completion_artifact_acquisition" not in source
assert "rootfs_artifact_count\": 16" not in source
if os.environ.get("COGS_EXPECT_NO_KVM") == "1":
    assert not Path("/dev/kvm").exists()
    recovered = subprocess.run(
        (sys.executable, "-B", str(Path(__file__).with_name(
            "aws-stage2-completion-kata-mutable-bridges.py")),
         "--runtime-removal-parent"),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False)
    assert recovered.returncode == 0, (recovered.stdout, recovered.stderr)
    assert b"fresh-process post-containerd-removal no-KVM recovery passed" in recovered.stdout
print("fresh-root immutable preparation transaction/no-KVM fault matrix passed")

#!/usr/bin/env python3
"""Fresh-root fault/order matrix for immutable pre-custody preparation."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REMOTE = Path(__file__).resolve().parents[1] / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
spec = importlib.util.spec_from_file_location(
    "completion_kata_immutable_preparation_test",
    REMOTE / "completion_kata_immutable_preparation.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


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
    events = []
    module._reject_ambient_authority = lambda: events.append("gate")
    module._chown_root = lambda _descriptor: None
    artifact_rows = tuple({"cache_name": f"asset-{index:02d}", "size": len(f"asset-{index:02d}".encode()),
                           "sha256": hashlib.sha256(f"asset-{index:02d}".encode()).hexdigest()}
                          for index in range(16))
    module._fixed_contract = lambda: {"bounds": {"artifact_count": 16}}
    module._artifact_rows = lambda _contract: artifact_rows
    module._expected_runtime = lambda: None

    def stable(path, expected, mode=0o400):
        raw = path.read_bytes()
        if path.parent == module.RUNTIME_CACHE:
            assert raw == expected["role"].encode()
            return
        wanted = path.name.encode()
        assert raw == wanted and len(raw) == expected["size"]
        assert hashlib.sha256(raw).hexdigest() == expected["sha256"]

    def acquisition(_contract):
        events.append("rootfs-16")
        cache = module.ARTIFACT_ROOT / "cache"
        created_count = 0
        for row in artifact_rows:
            path = cache / row["cache_name"]
            if path.exists():
                continue
            path.write_bytes(path.name.encode())
            path.chmod(0o400)
            created_count += 1
            if fail_at == "rootfs" and created_count == 4:
                raise module.ImmutablePreparationError()

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
    module._acquire_rootfs_assets = acquisition
    module._download_runtime = download
    module._run_extract = extract
    module._archive_values = values
    module._publish_runtime = publish
    module._verify_installed = verify
    module.artifact_verifier.verify_package_archives = lambda *_args: events.append("rootfs-readback")
    return events


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    events = configure(root)
    result = module.prepare()
    assert result["rootfs_artifact_count"] == 16
    assert result["runtime_archive_count"] == 2
    assert result["control_verified"] is False
    assert events == [
        "gate", "rootfs-16", "download-kata", "download-containerd",
        "extract-kata", "extract-containerd", "layout-readback",
        "publish-static", "installed-readback", "rootfs-readback",
    ]
    receipt = json.loads(module.RECEIPT.read_bytes())
    assert receipt["forbidden_surfaces"] == [
        "containerd", "ctr", "kvm", "qmp", "ssh", "task", "guest-network"]
    assert module.STAGED_RUNTIME.exists() and module.KATA_ROOT.exists()
    module.recover_failed_preparation()
    assert not module.PREPARATION_ROOT.exists()
    assert not module.STAGED_RUNTIME.exists() and not module.KATA_ROOT.exists()
    assert not module.ARTIFACT_ROOT.exists()

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
    changed_asset = module.ARTIFACT_ROOT / "cache/asset-00"
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
    foreign = module.ARTIFACT_ROOT / "cache/foreign"
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
assert "_remove_verified_tree" in source and "artifact_cache_created" in source
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

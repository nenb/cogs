#!/usr/bin/env python3
"""Fresh-root fault/order matrix for immutable pre-custody preparation."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
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
    module.STAGED_RUNTIME = completion / "kata-runtime-v1"
    module.KATA_PARENT = opt
    module.KATA_ROOT = opt / "kata"
    events = []
    module._reject_ambient_authority = lambda: events.append("gate")
    module._chown_root = lambda _descriptor: None
    module._fixed_contract = lambda: {"bounds": {"artifact_count": 16}}
    module._expected_runtime = lambda: None

    def acquisition(_contract):
        events.append("rootfs-16")
        module.ARTIFACT_ROOT.mkdir(parents=True)
        if fail_at == "rootfs":
            raise module.ImmutablePreparationError()

    def download(pin, _deadline):
        events.append("download-" + pin["role"])
        path = module.RUNTIME_CACHE / pin["name"]
        path.write_bytes(pin["role"].encode())
        return path

    def extract(_archive, destination):
        events.append("extract-" + destination.name)
        destination.mkdir()
        (destination / "verified").write_bytes(b"fixed")
        if fail_at == "extract-" + destination.name:
            raise module.ImmutablePreparationError()

    def values(_expected, archives, extracted):
        events.append("layout-readback")
        assert set(archives) == set(extracted) == {"kata", "containerd"}
        return [{**pin, "layout": {"verified": True}, "extracted": {"verified": True}}
                for pin in module.preparation.ARCHIVES]

    def publish(_extracted):
        events.append("publish-static")
        (module.STAGED_RUNTIME / "bin").mkdir(parents=True)
        (module.STAGED_RUNTIME / "bin/containerd").write_bytes(b"not-launched")
        (module.STAGED_RUNTIME / "bin/ctr").write_bytes(b"not-launched")
        module.KATA_ROOT.mkdir()
        (module.KATA_ROOT / "fixture").write_bytes(b"not-launched")
        if fail_at == "publish":
            raise module.ImmutablePreparationError()

    def verify(_expected):
        events.append("installed-readback")
        assert (module.STAGED_RUNTIME / "bin/containerd").read_bytes() == b"not-launched"
        assert (module.KATA_ROOT / "fixture").read_bytes() == b"not-launched"

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

for cut in ("rootfs", "extract-kata", "extract-containerd", "publish"):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        configure(root, cut)
        try:
            module.prepare()
        except module.ImmutablePreparationError:
            pass
        else:
            raise AssertionError("fault cut unexpectedly succeeded: " + cut)
        assert not module.PREPARATION_ROOT.exists()
        assert not module.STAGED_RUNTIME.exists()
        assert not module.KATA_ROOT.exists()

source = (REMOTE / "completion_kata_immutable_preparation.py").read_text()
assert "def prepare():" in source and "def main():" in source
assert "subprocess.Popen" not in source
assert "containerd --" not in source and "ctr --" not in source
assert "AWS_" in source and "DENIED_ENV" in source
if os.environ.get("COGS_EXPECT_NO_KVM") == "1":
    assert not Path("/dev/kvm").exists()
print("fresh-root immutable preparation transaction/no-KVM fault matrix passed")

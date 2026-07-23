#!/usr/bin/env python3
"""Strict pin and publication-boundary tests."""

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


load("completion_rootfs_fs", REMOTE / "completion_rootfs_fs.py")
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
source = (REMOTE / "completion_rootfs_publish.py").read_text()
assert "O_CREAT | os.O_EXCL" in source and "renameat2" in source and "_rename_noreplace" in source
assert "rootfs.metadata.json" in source and "_verify_candidate" in source and "_cleanup_candidate" in source
assert b"qualification" not in raw and b"functional_test_image" in raw
for forbidden in ("argparse", "sys.argv", "if __name__", "rmtree", "os.walk", "glob", "subprocess", "socket"):
    assert forbidden not in source
print("completion rootfs publication tests passed")

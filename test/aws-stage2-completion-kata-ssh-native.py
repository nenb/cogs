#!/usr/bin/env python3
"""Required non-AWS Linux/x86-64 SSH/input native qualification entry."""
import os
from pathlib import Path
import platform
import subprocess
import sys

if (os.environ.get("COGS_REQUIRE_STAGE2_KATA_NATIVE_SSH_INPUT") != "1"
        or sys.platform != "linux" or platform.machine() != "x86_64" or os.geteuid() != 0):
    raise RuntimeError("exact root Linux SSH/input qualification admission required")

root = Path(__file__).resolve().parents[1]
environment = {
    "HOME": "/root", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1", "COGS_REQUIRE_STAGE2_KATA_NATIVE_FOUNDATIONS": "1",
}
shard = os.environ.get("COGS_STAGE2_KATA_NATIVE_TEST_SHARD")
if shard is not None:
    if shard != "baseline":
        raise RuntimeError("native SSH/input wrapper only admits the baseline shard")
    environment["COGS_STAGE2_KATA_NATIVE_TEST_SHARD"] = shard
# The baseline shard owns operation/process execution; this wrapper independently
# requires the production SSH/input composition without duplicating that long run.
for probe in ("test/aws-stage2-completion-kata-ssh-production.py",):
    result = subprocess.run(("/usr/bin/python3", "-I", "-B", probe), cwd=root,
                            env=environment, check=False)
    if result.returncode != 0:
        raise RuntimeError("native SSH/input qualification probe failed")

for name in ("cogs-stage2-attested-static-v1.elf",
             "cogs-stage2-attested-static-v1.building",
             "cogs-stage2-attested-ssh-contract-v1.json",
             "cogs-stage2-attested-ssh-keygen-contract-v1.json"):
    path = Path("/tmp") / name
    if path.exists() or path.is_symlink():
        raise RuntimeError("native SSH/input fixture residue")

print("completion Kata native SSH/input qualification passed")

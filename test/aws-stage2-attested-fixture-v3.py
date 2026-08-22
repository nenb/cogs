#!/usr/bin/env python3
"""Optimization-safe additive V3 attested static fixture contract tests."""
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
sys.path.insert(0, str(ROOT / "test"))
import completion_guest_workloads_v3 as guest
import completion_kata_command_policy as policy
import completion_kata_process as process
from stage2_attested_fixture import ensure_attested_static_fixture
from stage2_attested_fixture_v3 import (
    EXPECTED_STDOUT, OUTPUT, SHA256, SIZE, SOURCE, ensure_attested_static_fixture_v3,
)


def check(value, message):
    if not value:
        raise RuntimeError(message)


expected = EXPECTED_STDOUT.read_bytes()
parsed = guest.parse_guest_workload_output(expected)
check(len(expected) == 2947 and expected.endswith(b"\n"), "V3 reviewed stdout identity")
check(len(expected.splitlines()) == 30 and len(parsed.network_markers) == 8
      and len(parsed.samples) == 21, "V3 reviewed stdout cardinality")
check(expected.startswith(guest.GUEST_READY_MARKER), "V3 reviewed ready marker")
check(SOURCE.name == "attested-static-v3.c" and OUTPUT.name.endswith("static-v3.elf"),
      "V3 fixture path version")

for role, command_id in (("ssh", "SSH_READY"), ("ssh-keygen", "SSH_KEYGEN_CLIENT")):
    fixture = ROOT / f"test/fixtures/stage2-completion/attested-{role}-contract-v3.json"
    raw = fixture.read_bytes()
    descriptor = policy.REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS_V3[role]
    check(hashlib.sha256(raw).hexdigest() == descriptor["contract_sha256"],
          "V3 synthetic contract descriptor")
    contract = process._parse_contract(raw, descriptor["contract_sha256"])
    check(contract.command_id == command_id
          and contract.executable.logical_path == str(OUTPUT)
          and contract.executable.sha256 == SHA256 and contract.executable.size == SIZE
          and contract.loader is None and contract.libraries == (),
          "V3 synthetic contract semantics")

native = sys.platform == "linux" and platform.machine() == "x86_64"
if native:
    v1 = ensure_attested_static_fixture()
    v3 = ensure_attested_static_fixture_v3()
    executed = subprocess.run((str(v3), "-F"), stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=10, check=False)
    check(executed.returncode == 0 and executed.stdout == expected and executed.stderr == b"",
          "V3 executable stdout differs")
    with tempfile.TemporaryDirectory(prefix="cogs-attested-v3-keys-") as temporary:
        for key_name in ("client", "server"):
            products = []
            for executable, suffix in ((v1, "v1"), (v3, "v3")):
                path = Path(temporary) / f"{key_name}-{suffix}"
                created = subprocess.run((str(executable), "-q", "-f", str(path)),
                                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, timeout=10, check=False)
                public = subprocess.run((str(executable), "-y", "-f", str(path)),
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=10, check=False)
                check(created.returncode == public.returncode == 0
                      and created.stdout == created.stderr == public.stderr == b"",
                      "synthetic key command failed")
                products.append((path.read_bytes(), path.with_suffix(".pub").read_bytes(),
                                 public.stdout))
            check(products[0] == products[1], "V3 keygen behavior differs from historical V1")
    staged = []
    prior = os.environ.get("COGS_KATA_SYNTHETIC_ATTESTATION_V3")
    try:
        for role in ("ssh", "ssh-keygen"):
            source = ROOT / f"test/fixtures/stage2-completion/attested-{role}-contract-v3.json"
            target = Path(policy.REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS_V3[role]["contract_path"])
            check(not target.exists() and not target.is_symlink(), "V3 contract stage occupied")
            target.write_bytes(source.read_bytes()); os.chmod(target, 0o600); staged.append(target)
        os.environ["COGS_KATA_SYNTHETIC_ATTESTATION_V3"] = "1"
        owner = process._open_synthetic_attested_executable_owner_v3_for_tests()
        retained_ssh = process._claim_attested_executable(owner, "ssh")
        retained_key = process._claim_attested_executable(owner, "ssh-keygen")
        check(retained_ssh.sha256 == retained_key.sha256 == SHA256,
              "V3 synthetic owner did not claim fixed executable")
        process._release_attested_executable(retained_ssh)
        process._release_attested_executable(retained_key)
    finally:
        if prior is None:
            os.environ.pop("COGS_KATA_SYNTHETIC_ATTESTATION_V3", None)
        else:
            os.environ["COGS_KATA_SYNTHETIC_ATTESTATION_V3"] = prior
        for path in reversed(staged):
            path.unlink(missing_ok=True)

print("additive V3 attested static fixture tests passed")

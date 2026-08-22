#!/usr/bin/env python3
"""Pinned-container no-KVM integration checks for the unreviewed-G stop."""
import ast
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_kata_coordinator as coordinator
import completion_kata_network as network


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def identities(paths):
    result = {}
    for path in paths:
        try:
            seen = os.lstat(path)
            result[path] = (seen.st_dev, seen.st_ino, seen.st_mode, seen.st_size,
                            seen.st_mtime_ns, seen.st_ctime_ns)
        except FileNotFoundError:
            result[path] = None
    return result


require(sys.platform.startswith("linux") and os.uname().machine == "x86_64",
        "exact Linux/amd64 container required")
require(not os.path.exists("/dev/kvm"), "Docker test must not receive KVM")
require(not (REMOTE / "stage2-completion-local-control-v2").exists(),
        "reviewed G unexpectedly exists in implementation H")

observed_paths = (
    "/var/lib/cogs", "/run/cogs-stage2-local-private-v2",
    "/run/cogs-stage2-ssh", "/run/netns/cogs-stage2-ssh-v1",
)
before = identities(observed_paths)
require(all(value is None for value in before.values()), "container baseline is not clean")
completed = subprocess.run(
    (sys.executable, "-I", "-B", "-c",
     "import sys; sys.path.insert(0, " + repr(str(REMOTE))
     + "); import runpy; runpy.run_module('completion_local_full',run_name='__main__')"),
    cwd=REMOTE,
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    env={"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
         "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "TZ": "UTC"},
    timeout=20, check=False)
require(completed.returncode == 3 and completed.stdout == b"" and completed.stderr == b"",
        "current missing G did not produce the fixed blocked result: "
        + repr((completed.returncode, completed.stdout, completed.stderr)))
require(identities(observed_paths) == before,
        "missing G reached a mutable lifecycle path")

source = (REMOTE / "completion_kata_coordinator.py").read_text()
tree = ast.parse(source)
functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
for name in ("_run_fixed_local_qualification", "_recover_fixed_local_qualification"):
    node = functions[name]
    require(not node.args.args and node.args.vararg is node.args.kwarg is None,
            "coordinator entry accepts caller data")
require("preparation_bridge._claim_fixed_static_preparation()" in source
        and "preparation_bridge._claim_fixed_live_mapping(" in source
        and "preparation_bridge._claim_fixed_executable_owner(" in source,
        "V2 preparation custody is not composed")
operation_source = (REMOTE / "completion_kata_operation_bridge.py").read_text()
require("fs.SourceApproval(" not in operation_source
        and "preparation._fixed_source_approval(" in operation_source
        and "source is lifecycle.source_approval" in operation_source,
        "operation bridge reconstructed SourceApproval")
execution_source = (REMOTE / "completion_kata_execution_bridge.py").read_text()
require("mapping[\"live_mapping_sha256\"]" in execution_source
        and "evidence._RuntimeOwnerResult(" in execution_source,
        "runtime/live mapping typed proof route differs")
try:
    network.GuestNetworkProof(network.CAUSAL_GUEST_MARKERS, "1" * 64, "1" * 64)
except network.NetworkError:
    pass
else:
    raise AssertionError("caller created GuestNetworkProof")

# A second isolated interpreter exercises the real production OFD owner and
# reconstructs its cleanup authority after all retained owner descriptors are
# closed. The same matrix proves RELEASING and close uncertainty never regain
# authority. No KVM or fake NFT owner is involved.
nft_recovery = subprocess.run(
    (sys.executable, "-I", "-B", str(ROOT / "test/aws-stage2-completion-kata-nft-owner.py")),
    cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    env={"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
         "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "TZ": "UTC"},
    timeout=30, check=False)
require(nft_recovery.returncode == 0 and
        b"persistent NFT owner hostile-cut matrix passed" in nft_recovery.stdout,
        "fresh-process durable NFT recovery failed: "
        + repr((nft_recovery.returncode, nft_recovery.stdout, nft_recovery.stderr)))

print("pinned Linux no-KVM final integration and missing-G refusal passed")

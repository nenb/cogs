#!/usr/bin/env python3
"""Bound the hosted host-link quiet period before exact network admission."""
import os
from pathlib import Path
import subprocess
import sys
import time

if sys.flags.optimize:
    raise RuntimeError("host network stabilization refuses Python optimization")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_kata_network as network

DEADLINE_SECONDS = 300
SAMPLE_INTERVAL_SECONDS = 1
STABLE_SAMPLES = 5
IP_ENV = {"HOME": "/root", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


def main():
    if (sys.argv != [sys.argv[0]] or os.geteuid() != 0
            or os.environ.get("COGS_REQUIRE_STAGE2_HOST_NETWORK_STABILITY") != "1"):
        return 64
    deadline = time.monotonic() + DEADLINE_SECONDS
    previous = None; stable = 0
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            observed = subprocess.run(
                ("/usr/sbin/ip", "-j", "-d", "link", "show"), env=IP_ENV,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=min(5, max(0.001, remaining)), check=False)
        except (OSError, subprocess.SubprocessError):
            return 65
        if (observed.returncode != 0 or observed.stderr
                or len(observed.stdout) > network.MAX_JSON):
            return 65
        try: binding = network._pre_admission_host_links_binding(observed.stdout)
        except network.NetworkError: return 65
        if binding is None:
            previous = None; stable = 0
        elif binding == previous:
            stable += 1
        else:
            previous = binding; stable = 1
        if stable == STABLE_SAMPLES:
            return 0
        remaining = deadline - time.monotonic()
        if remaining > 0: time.sleep(min(SAMPLE_INTERVAL_SECONDS, remaining))
    return 75


if __name__ == "__main__":
    status = main()
    if status != 0: os.write(2, b"stage2-host-network-stabilization-failed\n")
    raise SystemExit(status)

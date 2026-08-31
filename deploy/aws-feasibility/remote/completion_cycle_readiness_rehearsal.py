#!/usr/bin/env python3
"""Zero-argument real readiness-route rehearsal with no receipt issuance."""
import os
import sys
import completion_kata_coordinator as coordinator


def main():
    if sys.argv != [sys.argv[0]]:
        raise SystemExit(64)
    if coordinator._run_fixed_readiness_rehearsal() is not None:
        raise SystemExit(70)
    os.write(1, b"cogs-stage2-readiness-rehearsal-pass\n")


if __name__ == "__main__":
    main()

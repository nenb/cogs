#!/usr/bin/env python3
"""Zero-argument private marker-only readiness-cycle owner entry."""
import os
from pathlib import Path
import sys

_REMOTE_MODULE_ROOT = Path(__file__).resolve().parent
if not _REMOTE_MODULE_ROOT.is_dir():
    raise ImportError("fixed remote module root is unavailable")
sys.path.insert(0, str(_REMOTE_MODULE_ROOT))
import completion_cycle_evidence as evidence
import completion_kata_coordinator as coordinator


def main():
    receipt = coordinator._run_fixed_readiness_cycle()
    raw = evidence._consume_cycle_receipt(receipt)
    offset = 0
    while offset < len(raw):
        written = os.write(1, raw[offset:])
        if written <= 0:
            raise OSError("cycle receipt stdout write made no progress")
        offset += written


if __name__ == "__main__":
    main()

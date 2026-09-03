#!/usr/bin/env python3
"""Zero-argument non-cloud formal full-cycle owner entry."""
import os
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent
if not _ROOT.is_dir(): raise ImportError("fixed remote module root is unavailable")
sys.path.insert(0, str(_ROOT))
import completion_cycle_evidence as evidence
import completion_kata_coordinator as coordinator


def main():
    raw = evidence._consume_cycle_receipt(coordinator._run_formal_local_full_cycle())
    offset = 0
    while offset < len(raw):
        written = os.write(1, raw[offset:])
        if written <= 0: raise OSError("formal cycle receipt stdout made no progress")
        offset += written


if __name__ == "__main__": main()

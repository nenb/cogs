#!/usr/bin/env python3
"""Zero-argument sealed current-source full diagnostic; no receipt can issue."""
import os
from pathlib import Path
import sys

_REMOTE_MODULE_ROOT = Path(__file__).resolve().parent
if not _REMOTE_MODULE_ROOT.is_dir():
    raise ImportError("fixed remote module root is unavailable")
sys.path.insert(0, str(_REMOTE_MODULE_ROOT))
import completion_kata_coordinator as coordinator


def main():
    if sys.argv != [sys.argv[0]]:
        raise SystemExit(64)
    if coordinator._run_current_source_full_diagnostic() is not None:
        raise SystemExit(70)
    os.write(1, b"cogs-stage2-current-source-full-diagnostic-pass\n")


if __name__ == "__main__":
    main()

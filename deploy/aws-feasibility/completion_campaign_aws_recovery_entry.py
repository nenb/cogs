#!/usr/bin/env python3
"""Sole zero-argument cleanup-only AWS campaign crash-recovery entry."""
from dataclasses import asdict, is_dataclass
import json
import os
from pathlib import Path
import sys

_DIAGNOSTIC = b"stage2-production-recovery: owner.failed\n"
_MODULE_ROOT = Path(__file__).resolve().parent


def _fail():
    try: os.write(2, _DIAGNOSTIC)
    except BaseException: pass
    raise SystemExit(2) from None


def main():
    if sys.argv != [sys.argv[0]]: raise SystemExit(64)
    if not _MODULE_ROOT.is_dir(): raise ImportError("fixed campaign module root unavailable")
    sys.path.insert(0, str(_MODULE_ROOT))
    import completion_campaign_aws_adapter as adapter
    value = adapter.recover_fixed_campaign()
    if not is_dataclass(value): raise RuntimeError("typed cleanup receipt required")
    raw = json.dumps(asdict(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    offset = 0
    while offset < len(raw):
        written = os.write(1, raw[offset:])
        if written <= 0: raise RuntimeError("cleanup write made no progress")
        offset += written


def cli():
    try: main()
    except SystemExit as error:
        if error.code == 64: raise
        _fail()
    except BaseException: _fail()


if __name__ == "__main__": cli()

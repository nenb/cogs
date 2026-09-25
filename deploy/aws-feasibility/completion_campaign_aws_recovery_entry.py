#!/usr/bin/env python3
"""Sole zero-argument cleanup-only AWS campaign crash-recovery entry."""
from dataclasses import asdict, is_dataclass
import json
import os
from pathlib import Path
import sys

_MODULE_ROOT = Path(__file__).resolve().parent
_ADAPTER = None


def _fail():
    phase = "owner" if _ADAPTER is None else _ADAPTER.failure_phase()
    diagnostic = f"stage2-production-recovery: {phase}.failed\n".encode("ascii")
    try: os.write(2, diagnostic)
    except BaseException: pass
    raise SystemExit(2) from None


def main():
    global _ADAPTER
    if sys.argv != [sys.argv[0]]: raise SystemExit(64)
    if not _MODULE_ROOT.is_dir(): raise ImportError("fixed campaign module root unavailable")
    sys.path.insert(0, str(_MODULE_ROOT))
    import completion_campaign_aws_adapter as adapter
    _ADAPTER = adapter
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

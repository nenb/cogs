#!/usr/bin/env python3
"""Sole zero-argument future AWS campaign and cleanup-only recovery entry."""
from dataclasses import asdict, is_dataclass
import json
import os
import sys

import completion_campaign_aws_adapter as adapter


def _write(value):
    if not is_dataclass(value):
        raise RuntimeError("typed terminal receipt required")
    raw = json.dumps(asdict(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    if os.write(1, raw) != len(raw): raise RuntimeError("short terminal write")


def main():
    if sys.argv != [sys.argv[0]]: raise SystemExit(64)
    _write(adapter.run_fixed_campaign())


if __name__ == "__main__":
    main()

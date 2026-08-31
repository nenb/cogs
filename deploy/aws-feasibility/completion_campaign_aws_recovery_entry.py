#!/usr/bin/env python3
"""Sole zero-argument cleanup-only AWS campaign crash-recovery entry."""
from dataclasses import asdict, is_dataclass
import json
import os
import sys

import completion_campaign_aws_adapter as adapter


def main():
    if sys.argv != [sys.argv[0]]: raise SystemExit(64)
    value = adapter.recover_fixed_campaign()
    if not is_dataclass(value): raise RuntimeError("typed cleanup receipt required")
    raw = json.dumps(asdict(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    if os.write(1, raw) != len(raw): raise RuntimeError("short cleanup write")


if __name__ == "__main__":
    main()

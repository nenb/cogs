#!/usr/bin/env python3
"""Fixed zero-argument dispatcher for one split AWS campaign segment."""
from dataclasses import asdict, is_dataclass
import json
import os
from pathlib import Path
import sys

_DIAGNOSTIC = b"stage2-production-campaign: owner.failed\n"
_MODULE_ROOT = Path(__file__).resolve().parent


def _fail():
    try: os.write(2, _DIAGNOSTIC)
    except BaseException: pass
    raise SystemExit(2) from None


def _write(value):
    if not is_dataclass(value):
        raise RuntimeError("typed terminal receipt required")
    raw = json.dumps(asdict(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    offset = 0
    while offset < len(raw):
        written = os.write(1, raw[offset:])
        if written <= 0: raise RuntimeError("terminal write made no progress")
        offset += written


def main():
    if sys.argv != [sys.argv[0]]: raise SystemExit(64)
    if not _MODULE_ROOT.is_dir(): raise ImportError("fixed campaign module root unavailable")
    sys.path.insert(0, str(_MODULE_ROOT))
    import completion_campaign_aws_adapter as adapter
    segment = os.environ.get("COGS_STAGE2_CAMPAIGN_SEGMENT")
    run_id_text = os.environ.get("COGS_STAGE2_GITHUB_RUN_ID", "")
    attempt_text = os.environ.get("COGS_STAGE2_GITHUB_RUN_ATTEMPT", "")
    if not run_id_text.isdigit() or str(int(run_id_text)) != run_id_text:
        raise RuntimeError("invalid run id")
    if attempt_text != "1": raise RuntimeError("only first attempt is admissible")
    run_id, attempt = int(run_id_text), int(attempt_text)
    if os.environ.get("COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC") == "1":
        if segment != "diagnostic": raise RuntimeError("invalid diagnostic segment")
        receipt = adapter.run_fixed_diagnostic_campaign(run_id, attempt)
    elif segment == "cycles-1-3":
        receipt = adapter.run_fixed_first_segment(run_id, attempt)
    elif segment == "cycles-4-7":
        expected = os.environ.get("COGS_STAGE2_CONTINUATION_SHA256", "")
        receipt = adapter.run_fixed_second_segment(run_id, attempt, expected)
    else:
        raise RuntimeError("invalid campaign segment")
    _write(receipt)


def cli():
    try: main()
    except SystemExit as error:
        if error.code == 64: raise
        _fail()
    except BaseException: _fail()


if __name__ == "__main__": cli()

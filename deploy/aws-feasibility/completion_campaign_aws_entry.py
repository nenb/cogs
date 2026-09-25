#!/usr/bin/env python3
"""Fixed zero-argument dispatcher for one split AWS campaign segment."""
from dataclasses import asdict, is_dataclass
import json
import os
from pathlib import Path
import sys

_MODULE_ROOT = Path(__file__).resolve().parent
_ADAPTER = None


def _fail():
    phase = "owner" if _ADAPTER is None else _ADAPTER.failure_phase()
    diagnostic = f"stage2-production-campaign: {phase}.failed\n".encode("ascii")
    try: os.write(2, diagnostic)
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
    global _ADAPTER
    if sys.argv != [sys.argv[0]]: raise SystemExit(64)
    if not _MODULE_ROOT.is_dir(): raise ImportError("fixed campaign module root unavailable")
    sys.path.insert(0, str(_MODULE_ROOT))
    import completion_campaign_aws_adapter as adapter
    _ADAPTER = adapter
    diagnostic = os.environ.get("COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC") == "1"
    split_convergence = os.environ.get("COGS_STAGE2_SPLIT_CONVERGENCE") == "1"
    if diagnostic and not split_convergence:
        receipt = adapter.run_fixed_diagnostic_campaign()
    elif adapter.CONTINUATION_ADMISSION.exists():
        # Phase two is selected only by the root-staged authenticated capability.
        receipt = adapter.run_fixed_second_segment()
    else:
        names = (
            "COGS_STAGE2_WORKFLOW_REVISION", "COGS_STAGE2_GITHUB_RUN_ID",
            "COGS_STAGE2_PRODUCER_JOB_ID", "COGS_STAGE2_APPROVAL_ARTIFACT_RUN_ID",
            "COGS_STAGE2_APPROVAL_ARTIFACT_ID", "COGS_STAGE2_APPROVAL_ARTIFACT_DIGEST",
            "COGS_STAGE2_APPROVAL_ARTIFACT_NAME")
        values = {name: os.environ.get(name, "") for name in names}
        numeric = [values[name] for name in names[1:5]]
        if any(not item.isdigit() or str(int(item)) != item or int(item) <= 0
               for item in numeric):
            raise RuntimeError("invalid phase-one provenance")
        receipt = adapter.run_fixed_first_segment(
            values[names[0]], *(int(item) for item in numeric),
            values[names[5]], values[names[6]])
    _write(receipt)


def cli():
    try: main()
    except SystemExit as error:
        if error.code == 64: raise
        _fail()
    except BaseException: _fail()


if __name__ == "__main__": cli()

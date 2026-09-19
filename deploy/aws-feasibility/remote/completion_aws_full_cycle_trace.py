#!/usr/bin/env python3
"""Private one-shot AWS full-cycle tracer; never an evidence producer."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import traceback

# GetCommandInvocation returns only the first 8,000 stderr characters.
_MAX_DIAGNOSTIC_BYTES = 7_500
_written = 0


def _emit(event: str, **fields: object) -> None:
    global _written
    value = {"version": "cogs.stage2-aws-full-cycle-trace/v1", "event": event, **fields}
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    if _written + len(raw) > _MAX_DIAGNOSTIC_BYTES:
        return
    offset = 0
    while offset < len(raw):
        count = os.write(2, raw[offset:])
        if count <= 0:
            raise OSError("trace stderr made no progress")
        offset += count
    _written += len(raw)


def _exception(error: BaseException) -> None:
    rendered = "".join(traceback.TracebackException.from_exception(
        error, limit=30, compact=True).format())
    _emit("exception", exception_type=type(error).__name__,
          message=str(error)[:1000], traceback=rendered[-4000:])


def _write_stdout(raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        count = os.write(1, raw[offset:])
        if count <= 0:
            raise OSError("trace receipt stdout made no progress")
        offset += count


class _TracingOwners:
    """Delegate unchanged owner calls while recording only boundaries and failures."""

    def __init__(self, target: object):
        self._target = target

    def __getattr__(self, name: str):
        value = getattr(self._target, name)
        if not callable(value):
            return value

        def traced(*args, **kwargs):
            _emit("owner-call-start", owner_call=name)
            try:
                result = value(*args, **kwargs)
            except BaseException as error:
                _emit("owner-call-failed", owner_call=name,
                      exception_type=type(error).__name__, message=str(error)[:1000])
                _exception(error)
                raise
            _emit("owner-call-passed", owner_call=name)
            return result

        return traced


def main() -> None:
    if sys.argv != [sys.argv[0]]:
        raise SystemExit(64)
    module_root = Path(
        "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote")
    if not module_root.is_dir():
        raise RuntimeError("fixed remote module root is unavailable")
    sys.path.insert(0, str(module_root))
    import completion_cycle_evidence as evidence
    import completion_kata_coordinator as coordinator

    coordinator._owners = _TracingOwners(coordinator._owners)
    _emit("full-cycle-start")
    previous_umask = os.umask(0o022)
    _emit("diagnostic-hotpatch", owner_call="full-cycle", umask="0022")
    try:
        receipt = coordinator._run_fixed_full_cycle()
    finally:
        os.umask(previous_umask)
    _emit("full-cycle-passed")
    _write_stdout(evidence._consume_cycle_receipt(receipt))


def cli() -> None:
    try:
        main()
    except SystemExit:
        raise
    except BaseException as error:
        _emit("full-cycle-failed", exception_type=type(error).__name__,
              message=str(error)[:1000])
        _exception(error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    cli()

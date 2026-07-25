#!/usr/bin/env python3
"""Scheduling-only monotonic guards for the ADR0047 Phase A workflow."""

import os
import re
import sys
import time

ANCHOR_ENV = "COGS_STAGE2_PHASE_A_BUDGET_ANCHOR_NS"
BOUNDARIES = {
    "source": 600,
    "observe": 3900,
    "cleanup": 5100,
    "residue": 5160,
    "render": 5200,
    "validate": 5240,
    "export": 5280,
    "upload": 5290,
    "export-cleanup": 5390,
    "final": 5400,
}
KILL_RESERVE_SECONDS = 5


class BudgetError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise BudgetError()


def _anchor(raw):
    _fail(type(raw) is str and re.fullmatch(r"[1-9][0-9]{0,19}", raw) is not None)
    value = int(raw)
    _fail(value <= (1 << 63) - 1)
    return value


def _deadline(anchor_raw, boundary):
    _fail(boundary in BOUNDARIES)
    return _anchor(anchor_raw) + BOUNDARIES[boundary] * 1_000_000_000


def check(anchor_raw, boundary, now_ns):
    _fail(type(now_ns) is int and _anchor(anchor_raw) <= now_ns <= _deadline(anchor_raw, boundary))


def timeout_seconds(anchor_raw, boundary, now_ns):
    check(anchor_raw, boundary, now_ns)
    remaining = _deadline(anchor_raw, boundary) - now_ns - KILL_RESERVE_SECONDS * 1_000_000_000
    _fail(remaining >= 1_000_000_000)
    return remaining // 1_000_000_000


def main(argv):
    _fail(len(argv) == 2 and argv[0] in {"check", "timeout"} and argv[1] in BOUNDARIES)
    anchor = os.environ.get(ANCHOR_ENV)
    now = time.monotonic_ns()
    if argv[0] == "check":
        check(anchor, argv[1], now)
    else:
        value = timeout_seconds(anchor, argv[1], now)
        _fail(sys.stdout.write(str(value) + "\n") == len(str(value)) + 1)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except BudgetError:
        raise SystemExit(2)

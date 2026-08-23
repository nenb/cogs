#!/usr/bin/env python3
"""Pure fixed marker-only guest readiness program and exact output codec.

This module is inert data.  It grants no SSH, process, lifecycle, receipt, or
publication authority and deliberately imports no workload implementation.
"""

from __future__ import annotations

import hashlib

GUEST_READY_MARKER = b"COGS_STAGE2_SSH_READINESS_V1\n"
GUEST_OUTPUT_LIMIT = len(GUEST_READY_MARKER)
_GUEST_PROGRAM = b"""set -eu
umask 077
[ \"$#\" -eq 0 ]
export HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin TZ=UTC
/usr/bin/printf '%s\\n' COGS_STAGE2_SSH_READINESS_V1
"""
GUEST_PROGRAM_SHA256 = hashlib.sha256(_GUEST_PROGRAM).hexdigest()
MARKER_SHA256 = hashlib.sha256(GUEST_READY_MARKER).hexdigest()
PARSER_ID = "completion_guest_readiness_v1.parse_guest_readiness_output/v1"
PARSER_SHA256 = hashlib.sha256(PARSER_ID.encode("ascii")).hexdigest()


class ReadinessProgramError(ValueError):
    """The marker-only program output was not exact."""


def guest_program_bytes() -> bytes:
    return _GUEST_PROGRAM


def parse_guest_readiness_output(raw: bytes) -> bytes:
    if type(raw) is not bytes or raw != GUEST_READY_MARKER:
        raise ReadinessProgramError("exact marker-only readiness output required")
    return GUEST_READY_MARKER

"""Read-only codec and fail-closed facts for the fixed local Kata entry.

A report is data, never authority.  Host/runtime attestation and later lifecycle
owners are intentionally absent in ADR0099 Slice A, so the committed route
cannot qualify or mutate the host.
"""
from dataclasses import dataclass
import json
import os
import platform
import stat
import sys

VERSION = "cogs.stage2-kata-qualification/v1"
FIXED_ROOT = "/var/lib/cogs/stage2-completion-v1/source"
MAX_REPORT = 4096
BLOCKER_ORDER = (
    "wrong-platform", "wrong-architecture", "not-root", "wrong-source-location",
    "source-not-clean-qualified", "host-tools-unqualified", "runtime-fixtures-unqualified",
    "network-fixtures-unqualified", "ssh-fixture-unqualified", "kvm-missing-or-unqualified",
)
AUTHORITIES = frozenset({"committed-local-preflight"})


class QualificationError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise QualificationError()


@dataclass(frozen=True)
class Preflight:
    """Validated facts only.  Constructing this value grants no authority."""
    linux: bool
    amd64: bool
    root: bool
    fixed_location: bool
    clean_source: bool
    host_tools: bool
    runtime_fixtures: bool
    network_fixtures: bool
    ssh_fixture: bool
    kvm: bool

    def __post_init__(self):
        _fail(all(type(getattr(self, name)) is bool for name in self.__dataclass_fields__))


def _report(checks, authority):
    _fail(type(checks) is tuple and len(checks) == len(BLOCKER_ORDER))
    _fail(all(type(item) is bool for item in checks) and authority in AUTHORITIES)
    blockers = [name for name, passed in zip(BLOCKER_ORDER, checks, strict=True) if not passed]
    return {
        "version": VERSION,
        "qualified": not blockers,
        "blockers": blockers,
        "external_mutations_invoked": 0,
        "authority": authority,
    }


def canonical_report(report):
    _fail(type(report) is dict and set(report) == {
        "version", "qualified", "blockers", "external_mutations_invoked", "authority",
    })
    _fail(report["version"] == VERSION and type(report["qualified"]) is bool)
    blockers = report["blockers"]
    _fail(type(blockers) is list and all(type(item) is str for item in blockers))
    _fail(blockers == [item for item in BLOCKER_ORDER if item in blockers])
    _fail(len(blockers) == len(set(blockers)) and set(blockers) <= set(BLOCKER_ORDER))
    _fail(report["qualified"] == (not blockers))
    _fail(report["external_mutations_invoked"] == 0)
    _fail(type(report["external_mutations_invoked"]) is int)
    _fail(report["authority"] in AUTHORITIES)
    raw = json.dumps(
        report, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8") + b"\n"
    _fail(len(raw) <= MAX_REPORT)
    return raw


def load_report(raw):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_REPORT)
    _fail(raw.endswith(b"\n") and b"\x00" not in raw)
    try:
        pairs = json.loads(
            raw,
            object_pairs_hook=lambda rows: rows,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        _fail(type(pairs) is list)
        value = {}
        for key, item in pairs:
            _fail(type(key) is str and key not in value)
            value[key] = item
    except QualificationError:
        raise
    except (UnicodeError, ValueError, TypeError) as error:
        raise QualificationError() from error
    _fail(canonical_report(value) == raw)
    return value


def _kvm_candidate():
    try:
        observed = os.stat("/dev/kvm", follow_symlinks=False)
        return stat.S_ISCHR(observed.st_mode) and os.access("/dev/kvm", os.R_OK | os.W_OK)
    except OSError:
        return False


def committed_facts():
    """Collect read-only platform facts; absent attestations remain hard false."""
    attested = False
    return Preflight(
        platform.system() == "Linux",
        platform.machine() == "x86_64",
        os.geteuid() == 0,
        os.path.realpath(os.getcwd()) == FIXED_ROOT,
        False,
        attested,
        attested,
        attested,
        attested,
        _kvm_candidate() and attested,
    )


def committed_report():
    facts = committed_facts()
    checks = tuple(getattr(facts, name) for name in facts.__dataclass_fields__)
    return _report(checks, "committed-local-preflight")


def require_committed_facts():
    """Validate facts directly; never return a gate, token, seal, or owner."""
    facts = committed_facts()
    report = committed_report()
    _fail(not report["blockers"])
    return facts


def main():
    _fail(len(sys.argv) == 1)
    raw = canonical_report(committed_report())
    _fail(sys.stdout.buffer.write(raw) == len(raw))
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except QualificationError:
        raise SystemExit(2)

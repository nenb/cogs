"""Read-only, fail-closed preflight for the fixed Stage 2 composition.

Caller-created facts are useful only as explicitly marked offline fakes.  The
sealed committed collector is the sole route to a production preflight gate;
it currently reports blockers and therefore issues no gate.
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
AUTHORITIES = frozenset({"offline-fake", "committed-local-preflight"})


class QualificationError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise QualificationError()


@dataclass(frozen=True)
class Preflight:
    """Caller-created offline facts.  This type can never issue authority."""
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
    return {"version": VERSION, "qualified": not blockers, "blockers": blockers,
            "external_mutations_invoked": 0, "authority": authority}


def evaluate(value):
    """Evaluate a fake only; even an all-true result remains marked offline-fake."""
    _fail(type(value) is Preflight)
    return _report(tuple(getattr(value, name) for name in value.__dataclass_fields__), "offline-fake")


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
    _fail(type(report["external_mutations_invoked"]) is int and report["external_mutations_invoked"] == 0)
    _fail(report["authority"] in AUTHORITIES)
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    _fail(len(raw) <= MAX_REPORT)
    return raw


def load_report(raw):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_REPORT and raw.endswith(b"\n") and b"\x00" not in raw)
    try:
        pairs = json.loads(raw, object_pairs_hook=lambda rows: rows,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        _fail(type(pairs) is list)
        value = {}
        for key, item in pairs:
            _fail(type(key) is str and key not in value)
            value[key] = item
    except QualificationError:
        raise
    except BaseException as error:
        raise QualificationError() from error
    _fail(canonical_report(value) == raw)
    return value


def _committed_routes():
    seal = object()
    class CommittedFacts:
        __slots__ = ("checks",)
        def __init__(self, key, checks):
            _fail(key is seal)
            self.checks = checks
    class CommittedGate:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal)
            return super().__new__(cls)
    def kvm_candidate():
        try:
            observed = os.stat("/dev/kvm", follow_symlinks=False)
            return stat.S_ISCHR(observed.st_mode) and os.access("/dev/kvm", os.R_OK | os.W_OK)
        except OSError:
            return False
    def collect():
        # No environment/configuration input and no mutation.  Committed exact
        # fixture attestations do not yet exist, so those facts remain false.
        return CommittedFacts(seal, (
            platform.system() == "Linux", platform.machine() == "x86_64", os.geteuid() == 0,
            os.path.realpath(os.getcwd()) == FIXED_ROOT, False, False, False, False, False,
            kvm_candidate() and False,
        ))
    def report():
        return _report(collect().checks, "committed-local-preflight")
    def claim():
        value = collect()
        _fail(not _report(value.checks, "committed-local-preflight")["blockers"])
        return CommittedGate(seal)
    return report, claim


committed_report, _claim_committed_gate = _committed_routes()
del _committed_routes


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

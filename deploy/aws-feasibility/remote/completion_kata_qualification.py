"""Read-only, fail-closed preflight for the fixed Stage 2 composition.

Caller-created facts are useful only as explicitly marked offline fakes.  The
sealed committed collector is the sole route to a production preflight gate;
it currently reports blockers and therefore issues no gate.
"""
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
import platform
import stat
import sys
import time
import completion_kata_process as kata_process
import completion_kata_runtime as kata_runtime

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


@dataclass(frozen=True)
class RuntimeDiscoveryFacts:
    assets: tuple[dict, dict]
    archives: tuple[kata_runtime.ArchiveFacts, ...]
    host_closures: tuple[kata_process.HostElfClosure, ...]
    supervision: tuple[kata_process.ArchiveStreamOutcome, ...]


_ASSET_PINS = (
    {"component": "kata", "release": "3.32.0", "name": "kata-static-3.32.0-amd64.tar.zst",
     "compression": "zstd", "size": 1547940938,
     "sha256": "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01"},
    {"component": "containerd", "release": "2.2.1", "name": "containerd-static-2.2.1-linux-amd64.tar.gz",
     "compression": "gzip", "size": 33645699,
     "sha256": "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883"},
)
_DISCOVERY_VERSION = "cogs.stage2-phase-b-runtime-discovery/v1"
_DISCOVERY_STAGE = "phase-b-runtime-discovery"
_DISCOVERY_MAX_REPORT = 524_288
_DISCOVERY_SCHEMA = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "schemas", "stage2-phase-b-qualification-v1.json"))
_DISCOVERY_MEMBERS = (
    (("kata-runtime", "opt/kata/bin/kata-runtime"),
     ("kata-shim", "opt/kata/bin/containerd-shim-kata-v2"),
     ("qemu", "opt/kata/bin/qemu-system-x86_64"),
     ("virtiofsd", "opt/kata/libexec/virtiofsd"),
     ("kata-config", "opt/kata/share/defaults/kata-containers/configuration-qemu.toml")),
    (("containerd", "bin/containerd"), ("ctr", "bin/ctr")),
)
_DISCOVERY_ROLES = tuple(tuple(role for role, _member in rows) for rows in _DISCOVERY_MEMBERS)
_DISCOVERY_LINKS = ("symlink-relative-in-root", "symlink-absolute", "symlink-escape",
                    "hardlink-member", "hardlink-missing", "hardlink-absolute", "hardlink-escape")
_discovery_seal = object()
_ELF_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-")


def _discovery_canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode() + b"\n"
    except (TypeError, ValueError, RecursionError) as error:
        raise QualificationError() from error


def _hex(value, length=64):
    _fail(type(value) is str and len(value) == length and set(value) <= set("0123456789abcdef"))


def _uint_exact(value, maximum=(1 << 63) - 1, minimum=0):
    _fail(type(value) is int and minimum <= value <= maximum)
    return value


def _fd_pin(descriptor, pin, deadline_ns):
    _fail(type(descriptor) is int and descriptor >= 0)
    _fail(type(pin) is dict and tuple(pin) == ("component", "release", "name", "compression", "size", "sha256"))
    _fail(any(pin == fixed for fixed in _ASSET_PINS))
    try:
        observed = os.fstat(descriptor)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        offset = os.lseek(descriptor, 0, os.SEEK_CUR)
    except OSError as error:
        raise QualificationError() from error
    _fail(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 0 and
          stat.S_IMODE(observed.st_mode) == 0o400 and observed.st_uid == observed.st_gid == 0 and
          observed.st_size == pin["size"] and flags & os.O_ACCMODE == os.O_RDONLY and offset == 0)
    digest = hashlib.sha256()
    cursor = 0
    while cursor < observed.st_size:
        _fail(time.monotonic_ns() < deadline_ns)
        try:
            part = os.pread(descriptor, min(1_048_576, observed.st_size - cursor), cursor)
        except OSError as error:
            raise QualificationError() from error
        _fail(part)
        digest.update(part)
        cursor += len(part)
    after = os.fstat(descriptor)
    _fail(digest.hexdigest() == pin["sha256"] and
          (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns) ==
          (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))


class _RuntimeDiscoveryOwner:
    __slots__ = ("_key", "_host", "_used", "_pins")

    def __init__(self, key, pins):
        _fail(key is _discovery_seal)
        self._key = key
        self._used = False
        self._pins = pins
        self._host = kata_process._bind_runtime_discovery_host()

    def collect(self, archive_fds, intent_cb, started_cb, settled_cb, deadline_ns):
        _fail(not self._used)
        self._used = True
        archives = []
        outcomes = []
        try:
            _fail(type(archive_fds) is tuple)
            _fail(len(archive_fds) == 2)
            _fail(all(type(item) is int for item in archive_fds))
            _fail(archive_fds[0] != archive_fds[1])
            _fail(callable(intent_cb))
            _fail(callable(started_cb))
            _fail(callable(settled_cb))
            _fail(type(deadline_ns) is int)
            _fail(not isinstance(deadline_ns, bool))
            for descriptor, pin in zip(archive_fds, self._pins, strict=True):
                _fd_pin(descriptor, pin, deadline_ns)
            for asset, descriptor in zip(kata_runtime.FixedArchive, archive_fds, strict=True):
                enumerator = kata_runtime._new_fixed_tar_enumerator(asset)
                stream = self._host.open_archive_stream(
                    asset, descriptor, intent_cb, started_cb, settled_cb, deadline_ns)
                try:
                    while True:
                        chunk = stream.read()
                        if not chunk:
                            break
                        enumerator.feed(chunk)
                    archives.append(enumerator.finish())
                    outcomes.append(stream.settle())
                except BaseException:
                    stream.close()
                    raise
            result = RuntimeDiscoveryFacts(
                tuple(dict(item) for item in _ASSET_PINS), tuple(archives),
                self._host.closures, tuple(outcomes))
            _validate_runtime_facts(result)
            return result
        finally:
            self._host.close()


def bind_runtime_discovery():
    """Bind the three fixed host closures and return one one-shot collector."""
    return _RuntimeDiscoveryOwner(_discovery_seal, _ASSET_PINS)


def runtime_discovery_residue(started_rows=()):
    """Fresh aggregate observation of descriptors and every durable process row."""
    return kata_process._runtime_discovery_process_residue(started_rows)


def _validate_archive(value, pin, expected_roles):
    _fail(type(value) is kata_runtime.ArchiveFacts and value.component == pin["component"] and
          value.compression == pin["compression"])
    _uint_exact(value.stream_bytes, 16 * 1024**3, 1)
    _uint_exact(value.member_count, 20_000, 1)
    _uint_exact(value.member_bytes, 16 * 1024**3)
    _uint_exact(value.rejected_type_count, value.member_count)
    _hex(value.manifest_sha256)
    _fail(type(value.links) is kata_runtime.LinkFacts)
    _hex(value.links.sha256)
    _fail(value.type_counts == tuple((name, count) for name, count in value.type_counts) and
          tuple(name for name, _count in value.type_counts) == ("directory", "file", "hardlink", "symlink"))
    for _name, count in value.type_counts:
        _uint_exact(count, value.member_count)
    _fail(sum(count for _name, count in value.type_counts) + value.rejected_type_count == value.member_count)
    _fail(tuple(name for name, _count in value.links.counts) == _DISCOVERY_LINKS)
    for _name, count in value.links.counts:
        _uint_exact(count, value.member_count)
    _fail(sum(count for _name, count in value.links.counts) ==
          dict(value.type_counts)["hardlink"] + dict(value.type_counts)["symlink"])
    _fail(type(value.roles) is tuple and
          tuple(item.role for item in value.roles) == tuple(expected_roles))
    asset_index = tuple(pin["component"] for pin in _ASSET_PINS).index(pin["component"])
    expected_members = dict(_DISCOVERY_MEMBERS[asset_index])
    for role in value.roles:
        _fail(type(role) is kata_runtime.RoleMember and role.role in expected_roles)
        _fail(role.kind == "file" and role.member == expected_members[role.role])
    _fail(type(value.blockers) is tuple and value.blockers == tuple(sorted(set(value.blockers))) and
          len(value.blockers) <= 16 and all(type(item) is str and 0 < len(item) <= 64 for item in value.blockers))


def _closure_rows(value):
    return [{"needed": list(item.needed), "role": item.role, "sha256": item.sha256,
             "size": item.size, "soname": item.soname} for item in value.objects]


def _validate_runtime_facts(facts):
    _fail(type(facts) is RuntimeDiscoveryFacts and type(facts.assets) is tuple and len(facts.assets) == 2 and
          all(type(item) is dict for item in facts.assets) and tuple(facts.assets) == tuple(_ASSET_PINS))
    _fail(type(facts.archives) is tuple and len(facts.archives) == 2 and
          type(facts.host_closures) is tuple and len(facts.host_closures) == 3 and
          type(facts.supervision) is tuple and len(facts.supervision) == 2)
    for archive, pin, roles in zip(facts.archives, _ASSET_PINS, _DISCOVERY_ROLES, strict=True):
        _validate_archive(archive, pin, roles)
    for closure, tool in zip(facts.host_closures, ("python3-parser", "zstd", "gzip"), strict=True):
        _fail(type(closure) is kata_process.HostElfClosure and closure.tool == tool and
              type(closure.objects) is tuple and 1 <= len(closure.objects) <= 128 and
              len(closure.objects) == len(set(closure.objects)))
        _fail(closure.objects == tuple(sorted(closure.objects,
              key=lambda item: (item.role, item.soname or "", item.sha256))))
        for item in closure.objects:
            _fail(type(item) is kata_process.HostElfObject and item.role in {"executable", "loader", "library"})
            _uint_exact(item.size, 128 * 1024**2, 1)
            _hex(item.sha256)
            _fail(type(item.needed) is tuple and len(item.needed) == len(set(item.needed)) <= 128 and
                  all(type(name) is str and 0 < len(name) <= 255 and set(name) <= _ELF_CHARS for name in item.needed) and
                  (item.soname is None or type(item.soname) is str and set(item.soname) <= _ELF_CHARS))
        sonames = {item.soname for item in closure.objects if item.soname is not None}
        _fail(all(set(item.needed) <= sonames for item in closure.objects))
        _fail(sum(item.role == "executable" for item in closure.objects) == 1 and
              sum(item.role == "loader" for item in closure.objects) == 1)
        _fail(closure.total_bytes == sum(item.size for item in closure.objects) and closure.total_bytes <= 512 * 1024**2)
        _hex(closure.closure_sha256)
        _fail(closure.closure_sha256 == hashlib.sha256(_discovery_canonical(_closure_rows(closure))).hexdigest())
    _fail(sum(item.total_bytes for item in facts.host_closures) <= 512 * 1024**2)
    closure_by_tool = {item.tool: item for item in facts.host_closures}
    for archive, outcome, tool in zip(facts.archives, facts.supervision, ("zstd", "gzip"), strict=True):
        _fail(type(outcome) is kata_process.ArchiveStreamOutcome and
              outcome.identity.component == archive.component and outcome.identity.closure_sha256 == closure_by_tool[tool].closure_sha256)
        _fail(outcome.status == 0 and outcome.stdout_bytes == archive.stream_bytes and
              outcome.descendants_absent is True and outcome.reaped is True and outcome.errors == ())
        _hex(outcome.stderr_sha256)
        _hex(outcome.identity.spec_sha256)


def _archive_report(value):
    return {"stream_bytes": value.stream_bytes, "member_count": value.member_count,
            "member_bytes": value.member_bytes, "type_counts": dict(value.type_counts),
            "rejected_type_count": value.rejected_type_count, "manifest_sha256": value.manifest_sha256,
            "links": {"counts": dict(value.links.counts), "sha256": value.links.sha256},
            "roles": [asdict(item) for item in value.roles], "blockers": list(value.blockers)}


def canonical_runtime_discovery_report(facts, source_revision, source_manifest_sha256, duration_ms,
                                       cleanup_proved, residue_proved):
    _validate_runtime_facts(facts)
    _hex(source_revision, 40)
    _hex(source_manifest_sha256)
    _uint_exact(duration_ms, 5_280_000)
    _fail(cleanup_proved is True and residue_proved is True and runtime_discovery_residue() is True)
    blockers = ["candidate-non-authoritative", "runtime-layout-uncommitted"]
    blockers.extend(item for archive in facts.archives for item in archive.blockers)
    blockers = list(dict.fromkeys(blockers))
    assets = []
    for pin, archive, outcome in zip(_ASSET_PINS, facts.archives, facts.supervision, strict=True):
        assets.append({**pin, "archive": _archive_report(archive), "supervision": {
            "direct_children": 1, "helper_descendants": 0, "status": outcome.status, "reaped": outcome.reaped}})
    closures = [{"tool": item.tool, "objects": [{"role": child.role, "soname": child.soname,
                 "size": child.size, "sha256": child.sha256, "needed": list(child.needed)}
                 for child in item.objects], "total_bytes": item.total_bytes,
                 "closure_sha256": item.closure_sha256} for item in facts.host_closures]
    value = {"version": _DISCOVERY_VERSION, "stage": _DISCOVERY_STAGE, "authority": "candidate",
             "qualified": False, "promotion": False,
             "source": {"revision": source_revision, "manifest_sha256": source_manifest_sha256},
             "duration_ms": duration_ms, "checks": {"assets": "pass",
                 "archive_enumeration": "fail" if any(item.blockers for item in facts.archives) else "pass",
                 "host_elf_closures": "pass", "supervision": "pass", "cleanup": "pass", "residue": "pass"},
             "assets": assets, "host_elf_closures": closures,
             "claims": {name: False for name in ("rootfs", "kvm", "lifecycle", "extraction", "publication", "production")},
             "blockers": blockers}
    raw = _discovery_canonical(value)
    _fail(len(raw) <= _DISCOVERY_MAX_REPORT)
    _validate_runtime_report(value)
    return raw


class _DiscoveryPairs(list): pass


def _pairs(rows):
    result = {}
    for key, value in rows:
        _fail(type(key) is str and key not in result)
        result[key] = value
    return result


def _runtime_schema():
    try:
        with open(_DISCOVERY_SCHEMA, "rb", buffering=0) as stream:
            raw = stream.read(65_537)
        _fail(0 < len(raw) <= 65_536 and b"\0" not in raw)
        schema = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                            parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        _fail(type(schema) is dict)
        return schema
    except QualificationError:
        raise
    except BaseException as error:
        raise QualificationError() from error


def _validate_runtime_report(value):
    _fail(type(value) is dict and set(value) == {"version", "stage", "authority", "qualified", "promotion",
          "source", "duration_ms", "checks", "assets", "host_elf_closures", "claims", "blockers"})
    _fail(value["version"] == _DISCOVERY_VERSION and value["stage"] == _DISCOVERY_STAGE and
          value["authority"] == "candidate" and value["qualified"] is False and value["promotion"] is False)
    _fail(type(value["source"]) is dict and set(value["source"]) == {"revision", "manifest_sha256"})
    _hex(value["source"]["revision"], 40)
    _hex(value["source"]["manifest_sha256"])
    _uint_exact(value["duration_ms"], 5_280_000)
    _fail(value["claims"] == {name: False for name in ("rootfs", "kvm", "lifecycle", "extraction", "publication", "production")})
    _fail(type(value["blockers"]) is list and value["blockers"][:2] ==
          ["candidate-non-authoritative", "runtime-layout-uncommitted"] and len(value["blockers"]) == len(set(value["blockers"])) <= 18)
    checks = value["checks"]
    _fail(type(checks) is dict and set(checks) == {"assets", "archive_enumeration", "host_elf_closures", "supervision", "cleanup", "residue"} and
          checks["assets"] == checks["host_elf_closures"] == checks["supervision"] == checks["cleanup"] == checks["residue"] == "pass" and
          checks["archive_enumeration"] in {"pass", "fail"})
    assets = value["assets"]
    _fail(type(assets) is list and len(assets) == 2)
    for item, pin, roles in zip(assets, _ASSET_PINS, _DISCOVERY_ROLES, strict=True):
        _fail(type(item) is dict and set(item) == set(pin) | {"archive", "supervision"} and
              all(item[name] == pin[name] for name in pin))
        archive = item["archive"]
        _fail(type(archive) is dict and set(archive) == {"stream_bytes", "member_count", "member_bytes", "type_counts",
              "rejected_type_count", "manifest_sha256", "links", "roles", "blockers"})
        _uint_exact(archive["stream_bytes"], 16 * 1024**3, 1)
        _uint_exact(archive["member_count"], 20_000, 1)
        _uint_exact(archive["member_bytes"], 16 * 1024**3)
        _uint_exact(archive["rejected_type_count"], archive["member_count"])
        _hex(archive["manifest_sha256"])
        _fail(type(archive["type_counts"]) is dict and tuple(archive["type_counts"]) == ("directory", "file", "hardlink", "symlink"))
        _fail(sum(_uint_exact(count, archive["member_count"]) for count in archive["type_counts"].values()) +
              archive["rejected_type_count"] == archive["member_count"])
        links = archive["links"]
        _fail(type(links) is dict and set(links) == {"counts", "sha256"})
        _hex(links["sha256"])
        _fail(type(links["counts"]) is dict and set(links["counts"]) == set(_DISCOVERY_LINKS))
        _fail(sum(_uint_exact(count, archive["member_count"]) for count in links["counts"].values()) ==
              archive["type_counts"]["hardlink"] + archive["type_counts"]["symlink"])
        _fail(type(archive["roles"]) is list and
              tuple(row.get("role") for row in archive["roles"] if type(row) is dict) == tuple(roles) and
              len(archive["roles"]) == len(roles))
        asset_index = tuple(pin["component"] for pin in _ASSET_PINS).index(pin["component"])
        expected_members = dict(_DISCOVERY_MEMBERS[asset_index])
        for row in archive["roles"]:
            _fail(type(row) is dict and set(row) == {"role", "member", "kind"})
            _fail(row["kind"] == "file" and row["member"] == expected_members[row["role"]])
        _fail(type(archive["blockers"]) is list and archive["blockers"] == sorted(set(archive["blockers"])) and
              len(archive["blockers"]) <= 16 and all(type(code) is str and code and len(code) <= 64 and
              set(code) <= set("abcdefghijklmnopqrstuvwxyz0123456789-") for code in archive["blockers"]))
        _fail(item["supervision"] == {"direct_children": 1, "helper_descendants": 0, "status": 0, "reaped": True})
    closures = value["host_elf_closures"]
    _fail(type(closures) is list and [item.get("tool") for item in closures if type(item) is dict] == ["python3-parser", "zstd", "gzip"])
    for closure in closures:
        _fail(set(closure) == {"tool", "objects", "total_bytes", "closure_sha256"} and type(closure["objects"]) is list and 1 <= len(closure["objects"]) <= 128)
        _hex(closure["closure_sha256"])
        total = 0
        for item in closure["objects"]:
            _fail(type(item) is dict and set(item) == {"role", "soname", "size", "sha256", "needed"} and
                  item["role"] in {"executable", "loader", "library"} and type(item["needed"]) is list and
                  len(item["needed"]) == len(set(item["needed"])) <= 128 and
                  all(type(name) is str and 0 < len(name) <= 255 and set(name) <= _ELF_CHARS for name in item["needed"]))
            _fail(item["soname"] is None or type(item["soname"]) is str and
                  0 < len(item["soname"]) <= 255 and set(item["soname"]) <= _ELF_CHARS)
            total += _uint_exact(item["size"], 128 * 1024**2, 1)
            _hex(item["sha256"])
        sonames = {item["soname"] for item in closure["objects"] if item["soname"] is not None}
        _fail(all(set(item["needed"]) <= sonames for item in closure["objects"]))
        _fail(sum(item["role"] == "executable" for item in closure["objects"]) == 1 and
              sum(item["role"] == "loader" for item in closure["objects"]) == 1)
        _fail(len(closure["objects"]) == len({_discovery_canonical(item) for item in closure["objects"]}))
        _fail(closure["objects"] == sorted(closure["objects"], key=lambda item:
              (item["role"], item["soname"] or "", item["sha256"])))
        _fail(closure["closure_sha256"] == hashlib.sha256(_discovery_canonical(closure["objects"])).hexdigest())
        _fail(closure["total_bytes"] == total <= 512 * 1024**2)
    _fail(sum(closure["total_bytes"] for closure in closures) <= 512 * 1024**2)
    derived = list(dict.fromkeys(["candidate-non-authoritative", "runtime-layout-uncommitted"] +
        [code for asset in assets for code in asset["archive"]["blockers"]]))
    _fail(value["blockers"] == derived and checks["archive_enumeration"] ==
          ("fail" if any(asset["archive"]["blockers"] for asset in assets) else "pass"))


def load_runtime_discovery_report(raw):
    _fail(type(raw) is bytes and 0 < len(raw) <= _DISCOVERY_MAX_REPORT and raw.endswith(b"\n") and b"\0" not in raw)
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except QualificationError:
        raise
    except BaseException as error:
        raise QualificationError() from error
    try:
        schema = _runtime_schema()
        _fail(kata_runtime._validate_phase_b_schema(value, schema) is True)
        _validate_runtime_report(value)
        _fail(_discovery_canonical(value) == raw)
    except QualificationError:
        raise
    except BaseException as error:
        raise QualificationError() from error
    return value


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

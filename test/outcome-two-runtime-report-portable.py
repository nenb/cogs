#!/usr/bin/env python3
"""Report codecs and cBPF oracle (semantic corpus: native-qualification-common.test.ts)."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import struct
import sys
from types import SimpleNamespace
if sys.flags.optimize:
    raise RuntimeError("Outcome 2 report tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
CLOSURE_PATH = REMOTE / "completion_trusted_runtime_closure.py"
LAUNCHER_PATH = REMOTE / "completion_trusted_runtime_launcher.py"
SCHEMA_PATH = ROOT / "schemas/trusted-runtime-closure-v1.json"
GOLDEN_PATH = ROOT / "test/fixtures/outcome-two/reports/runtime-closure-v1.canonical.jsonl"
MUTATIONS_PATH = ROOT / "test/fixtures/outcome-two/reports/mutations.jsonl"
sys.path.insert(0, str(REMOTE))
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()
def recompute(value):
    for tool in value["tools"]:
        tool["closure_sha256"] = digest(tool["objects"])
        mapped = [[item["role"], item["sha256"]] for item in tool["objects"]]
        tool["mapping_sha256"] = digest(mapped)
    digest_view = [
        {key: item for key, item in tool.items() if key != "mapping_sha256"}
        for tool in value["tools"]
    ]
    value["closure_sha256"] = digest(digest_view)
    return value
def mutate(golden, name):
    value = copy.deepcopy(golden)
    tool = value["tools"][0]
    object_ = tool["objects"][0]
    if name == "tool-order":
        value["tools"][0], value["tools"][1] = value["tools"][1], value["tools"][0]
    elif name == "object-order":
        tool["objects"][2], tool["objects"][3] = tool["objects"][3], tool["objects"][2]
    elif name == "duplicate-needed":
        object_["needed"].append(object_["needed"][0])
    elif name == "missing-provider":
        object_["needed"] = ["libmissing.so.1"]
    elif name == "duplicate-provider":
        tool["objects"][3]["soname"] = tool["objects"][2]["soname"]
    elif name == "seal-profile":
        tool["seal_profile"] = "linux-memfd-exec-seals-v1"
    elif name == "sealed-executable":
        tool["sealed_executable"] = True
    elif name == "wrong-role":
        tool["objects"][1]["role"] = "library"
    elif name == "bad-soname":
        tool["objects"][2]["soname"] = "bad name"
        for candidate in tool["objects"]:
            candidate["needed"] = [
                "bad name" if item == "libalpha.so.1" else item
                for item in candidate["needed"]
            ]
    elif name == "needed-overflow":
        object_["needed"] = [f"lib{index}.so" for index in range(129)]
    elif name == "boolean-size":
        object_["size"] = True
    elif name == "extra-field":
        tool["extra"] = False
    elif name == "prohibited-path":
        value["host_path"] = "/usr/lib/secret"
    elif name == "prohibited-environment":
        value["environment"] = {"HOME": "/secret"}
    elif name == "prohibited-address":
        value["mapping_address"] = "0x7fff"
    elif name == "prohibited-command-output":
        value["command_output"] = "secret"
    elif name == "prohibited-identifier":
        value["pid"] = 123
    elif name not in {"aggregate-digest", "tool-closure-digest", "mapping-digest"}:
        raise AssertionError(f"unknown semantic mutation: {name}")
    recompute(value)
    if name == "aggregate-digest":
        value["closure_sha256"] = "0" * 64
    elif name == "tool-closure-digest":
        tool["closure_sha256"] = "0" * 64
        digest_view = [
            {key: item for key, item in row.items() if key != "mapping_sha256"}
            for row in value["tools"]
        ]
        value["closure_sha256"] = digest(digest_view)
    elif name == "mapping-digest":
        tool["mapping_sha256"] = "0" * 64
    return value
def encoding_mutation(raw, name):
    mutations = {
        "duplicate-key": lambda: raw.replace(b"{", b'{"version":"duplicate",', 1),
        "leading-whitespace": lambda: b" " + raw,
        "trailing-whitespace": lambda: raw[:-1] + b" \n",
        "pretty-json": lambda: json.dumps(json.loads(raw), indent=2).encode() + b"\n",
        "missing-lf": lambda: raw[:-1],
        "extra-lf": lambda: raw + b"\n",
        "invalid-utf8": lambda: raw[:-1] + b"\xff\n",
        "float": lambda: raw.replace(b'"size":101', b'"size":101.0', 1),
        "constant": lambda: raw.replace(b'"size":101', b'"size":NaN', 1),
        "oversized": lambda: b"{" + b" " * 131_072 + b"}\n",
    }
    if name not in mutations:
        raise AssertionError(f"unknown encoding mutation: {name}")
    return mutations[name]()
# Independent Linux ABI policy specification, not production-derived expectations.
BIT, ARCH, DENY, ALLOW, KILL = 0x40000000, 0xC000003E, 0x00050001, 0x7FFF0000, 0x80000000
OLD_POLICY = "aacfce0e5eeb2fb79a1708b32f5383f89b381898ad7e6bd911905d87483b6bb2"
NEW_POLICY = "8689e7141c034a63af052ba0d59c0f7a396e88c22428061d89892440bccf15e7"
FORBIDDEN = (
    59, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    288, 299, 307, 425, 426, 427, 56, 57, 58, 435, 272, 308, 165, 166,
    155, 161, 428, 429, 430, 431, 432, 433, 442, 250, 248, 249, 298,
    321, 323, 101, 175, 176, 313, 105, 106, 113, 114, 116, 117, 119,
    122, 123, 126, 317, 319, 304, 303, 434, 438, 310, 311, 246, 320,
    444, 445, 446, 32, 33, 292, 72,
)
# Frozen pre-change specification: never obtained by deleting production rows.
OLD_PREFIX = (
    (0x20, 0, 0, 4), (0x15, 1, 0, ARCH), (0x06, 0, 0, KILL), (0x20, 0, 0, 0),
    (0x15, 0, 10, 322), (0x20, 0, 0, 16), (0x15, 0, 6, 198), (0x20, 0, 0, 20),
    (0x15, 0, 4, 0), (0x20, 0, 0, 48), (0x15, 0, 2, 0x1000), (0x20, 0, 0, 52),
    (0x15, 1, 0, 0), (0x06, 0, 0, DENY), (0x06, 0, 0, ALLOW),
    (0x15, 0, 4, 157), (0x20, 0, 0, 16), (0x15, 1, 0, 21),
    (0x06, 0, 0, DENY), (0x06, 0, 0, ALLOW), (0x20, 0, 0, 0),
)
OLD_PROGRAM = OLD_PREFIX + tuple(row for n in FORBIDDEN for row in
    ((0x15, 0, 1, n), (0x06, 0, 0, DENY))) + ((0x06, 0, 0, ALLOW),)
GUARD = ((0x45, 0, 1, BIT), (0x06, 0, 0, DENY))
def bpf_bytes(program):
    return b"".join(struct.pack("<HBBI", *row) for row in program)
def policy_oracle(nr, args, arch=ARCH):
    nr &= 0xFFFFFFFF
    args = tuple(a & 0xFFFFFFFFFFFFFFFF for a in args)
    if arch & 0xFFFFFFFF != ARCH: return KILL
    if nr & BIT: return DENY
    if nr == 322: return ALLOW if args[0] == 198 and args[4] == 0x1000 else DENY
    if nr == 157: return ALLOW if args[0] & 0xFFFFFFFF == 21 else DENY
    return DENY if nr in FORBIDDEN else ALLOW
class BpfInvalid(ValueError): pass
class BpfMachine:
    """Strict supported-subset verifier/interpreter, not the full kernel verifier."""
    def __init__(self, program, mutation=False):
        self.program = tuple(program)
        if not 0 < len(program) <= 4096: raise BpfInvalid("length")
        branches = (0x15, 0x45, 0x35) if mutation else (0x15, 0x45)
        for pc, row in enumerate(program):
            if type(row) is not tuple or len(row) != 4: raise BpfInvalid("row")
            if any(type(v) is not int or not 0 <= v <= high for v, high in
                   zip(row, (0xFFFF, 0xFF, 0xFF, 0xFFFFFFFF))): raise BpfInvalid("width")
            code, jt, jf, k = row
            if code not in (0x20, 0x06, *branches, *((0x54,) if mutation else ())):
                raise BpfInvalid("opcode")
            if code not in branches and (jt or jf): raise BpfInvalid("unused jumps")
            if code == 0x20 and (k % 4 or k > 60): raise BpfInvalid("load")
            targets = (pc + 1 + jt, pc + 1 + jf) if code in branches else (pc + 1,)
            if code != 0x06 and any(t >= len(program) for t in targets): raise BpfInvalid("target")
    def run(self, nr, args=(0,) * 6, arch=ARCH, ip=0, trace=None):
        if len(args) != 6: raise BpfInvalid("six arguments required")
        data = struct.pack("<IIQ6Q", nr & 0xFFFFFFFF, arch & 0xFFFFFFFF,
                           ip & 0xFFFFFFFFFFFFFFFF, *(a & 0xFFFFFFFFFFFFFFFF for a in args))
        pc, accumulator = 0, 0
        for _ in range(len(self.program) + 1):
            if not 0 <= pc < len(self.program): raise BpfInvalid("execution bounds")
            if trace is not None: trace.append(pc)
            code, jt, jf, k = self.program[pc]
            if code == 0x06: return k
            if code == 0x20: accumulator = struct.unpack_from("<I", data, k)[0]
            elif code == 0x54: accumulator &= k  # mutation-only AND-K
            else:
                match = accumulator == k if code == 0x15 else (
                    accumulator >= k if code == 0x35 else bool(accumulator & k))
                pc += jt if match else jf
            pc += 1
        raise BpfInvalid("termination")
def production_seccomp_contract(launcher):
    program = launcher._seccomp_program()
    assert tuple(launcher._DENIED_SYSCALLS.values()) == FORBIDDEN
    assert program == OLD_PROGRAM[:4] + GUARD + OLD_PROGRAM[4:]
    assert len(program) == 176 and len(bpf_bytes(program)) == 1408
    assert hashlib.sha256(bpf_bytes(OLD_PROGRAM)).hexdigest() == OLD_POLICY
    assert hashlib.sha256(bpf_bytes(program)).hexdigest() == launcher._seccomp_digest() == NEW_POLICY
def exact_rejection(function, raw, expected_type, expected_code):
    try:
        function(raw)
    except BaseException as error:
        code = getattr(error, "code", str(error))
        if type(error) is not expected_type or code != expected_code:
            raise AssertionError(
                f"wrong rejection: {type(error).__name__}/{code}"
            ) from error
        return
    raise AssertionError("production predicate accepted its hostile input")
def production_observation_mutation(launcher):
    if "_build_observed_result" not in launcher._coordinate_with_ops.__code__.co_names:
        raise AssertionError("production coordinator bypasses observed-result construction")
    names = set(tuple(launcher.RuntimeQualificationResult.__dataclass_fields__)[7:])
    cleanup_names = {
        "children_reaped", "descendants_reaped", "descriptors_restored",
        "mounts_restored", "namespace_handles_released", "namespaces_released",
        "paths_restored",
    }
    tool = {name: True for name in names - cleanup_names}
    cleanup = {name: True for name in cleanup_names}
    complete = {name: True for name in names}
    if launcher._build_observed_result((tool, dict(tool)), cleanup) != complete:
        raise AssertionError("complete production observation construction diverged")
    for changed in names:
        first = dict(tool)
        final = dict(cleanup)
        target = final if changed in cleanup_names else first
        target[changed] = False
        call = lambda _raw: launcher._build_observed_result((first, tool), final)
        mismatch = "observation-mismatch" if changed in cleanup_names else "observation-drift"
        exact_rejection(call, b"", launcher.RuntimeLauncherError, mismatch)
        target.pop(changed)
        code = "cleanup-observation-shape" if changed in cleanup_names else "observation-shape"
        exact_rejection(call, b"", launcher.RuntimeLauncherError, code)
def production_parser_contract(launcher):
    stat_record = b"7 (worker) S " + b" ".join([b"1"] * 49) + b"\n"
    maps_record = b"00400000-00401000 r-xp 00000000 08:01 123 /tool\n"
    status_record = launcher._status("child", 0, pid=7)
    cases = (
        (
            lambda raw: launcher._parse_proc_stat(raw, 7),
            stat_record, stat_record.replace(b"7 ", b"8 ", 1), "stat-framing",
        ),
        (launcher._parse_maps, maps_record, maps_record.replace(b"r-xp", b"r-qp"), "maps-record"),
        (
            lambda raw: launcher._parse_sandbox_status(raw, "child", 0),
            status_record, status_record[:-1] + b',"x":0}', "status-shape",
        ),
    )
    for parser, accepted, hostile, code in cases:
        parser(accepted)
        exact_rejection(parser, hostile, launcher.RuntimeLauncherError, code)
def manifest():
    records = [json.loads(line) for line in MUTATIONS_PATH.read_text().splitlines()]
    header, *rows = records
    fields = ("id", "production_method", "primitive_fault", "intended_code", "cleanup_domains", "sentinel")
    if set(header) != {"type", "version", "acceptance_ids", "case_fields"}:
        raise AssertionError("report manifest header is not closed")
    if header["type"] != "header" or tuple(header["case_fields"]) != fields:
        raise AssertionError("report manifest contract changed")
    if any(set(row) != set(fields) for row in rows):
        raise AssertionError("report manifest row is not closed")
    identifiers = [row["id"] for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError("duplicate report case identity")
    return rows
def hostile_bytes(golden, raw, row):
    fault = row["primitive_fault"]
    if set(fault) == {"family", "name", "schema"} and fault["family"] == "semantic":
        return canonical(mutate(golden, fault["name"])) + b"\n"
    if set(fault) == {"family", "name"} and fault["family"] == "encoding":
        return encoding_mutation(raw, fault["name"])
    raise AssertionError("report primitive fault is not closed")
def production_objects(closure, golden):
    closures = []
    mappings = []
    identity = 100
    for tool_record in golden["tools"]:
        objects = []
        for record in tool_record["objects"]:
            generation = closure.SourceGeneration(
                8, identity, record["size"], 1, 1, stat.S_IFREG | 0o555, 0, 0
            )
            identity += 1
            metadata = SimpleNamespace(
                interpreter=None,
                soname=record["soname"],
                needed=tuple(record["needed"]),
            )
            objects.append(closure.AuthenticatedObject(
                record["role"], "/held/object", 900 + identity, generation, (),
                record["size"], record["sha256"], metadata,
            ))
        closures.append(closure.ResolvedToolClosure(
            tool_record["tool"], objects[0], objects[1], tuple(objects[2:])
        ))
        mapped = tuple((item["role"], item["sha256"]) for item in tool_record["objects"])
        mappings.append(closure.MappedToolClosure(
            tool_record["tool"], mapped, tool_record["mapping_sha256"]
        ))
    return tuple(closures), tuple(mappings)
def dispatch(row, methods, hostile):
    codes = []
    events = []
    for name, method in methods:
        try:
            method(hostile)
        except BaseException as error:
            code = getattr(error, "code", str(error))
            codes.append([type(error).__name__, code])
            events.append(f"{name}:raise:{type(error).__name__}:{code}")
        else:
            codes.append("OK")
            events.append(f"{name}:return")
    if row["production_method"] != [name for name, _method in methods]:
        raise AssertionError(f"{row['id']}: production dispatch changed")
    if row["intended_code"] != codes:
        raise AssertionError(f"{row['id']}: exact exception class/code changed")
    if row["sentinel"] != events:
        raise AssertionError(f"{row['id']}: production predicate sentinel changed")
    return tuple(events)
def prove_oracle_edge_deletions(row, methods, hostile):
    proved = 0
    for index, expected in enumerate(row["intended_code"]):
        if expected == "OK":
            continue
        deleted = list(methods)
        deleted[index] = (deleted[index][0], lambda _raw: None)
        try:
            dispatch(row, tuple(deleted), hostile)
        except AssertionError:
            proved += 1
        else:
            raise AssertionError(f"{row['id']}: deleting oracle {methods[index][0]} stayed green")
    return proved
def emit_schema_corpus():
    raw = GOLDEN_PATH.read_bytes()
    golden = json.loads(raw)
    print(json.dumps({"id": "golden", "schema": True, "value": golden}, separators=(",", ":")))
    for row in manifest():
        fault = row["primitive_fault"]
        if fault["family"] == "semantic":
            value = mutate(golden, fault["name"])
            print(json.dumps({"id": row["id"], "schema": fault["schema"], "value": value}, separators=(",", ":")))
def parent():
    rows = manifest()
    closure = load("completion_trusted_runtime_closure", CLOSURE_PATH)
    launcher = load("completion_trusted_runtime_launcher", LAUNCHER_PATH)
    production_seccomp_contract(launcher)
    production_observation_mutation(launcher)
    production_parser_contract(launcher)
    producer = closure._producer_decode_report
    consumer = launcher._decode_report
    producer_reencode = closure._producer_reencode_report
    consumer_reencode = launcher._consumer_reencode_report
    schema_method = launcher._SourceAdmission._validate_tracked_schema
    if len({schema_method.__code__, producer.__code__, consumer.__code__}) != 3:
        raise AssertionError("three production report decoders collapsed")
    if producer_reencode.__code__ is consumer_reencode.__code__:
        raise AssertionError("producer and consumer report encoders collapsed")
    schema_holder = SimpleNamespace(_schema_bytes=SCHEMA_PATH.read_bytes())
    methods = (
        ("launcher._SourceAdmission._validate_tracked_schema", lambda value: schema_method(schema_holder, value)),
        ("closure._producer_decode_report", producer),
        ("launcher._decode_report", consumer),
    )
    raw = GOLDEN_PATH.read_bytes()
    golden = json.loads(raw)
    closures, mappings = production_objects(closure, golden)
    calls = []
    def schema_gate(value):
        calls.append(value)
        return schema_method(schema_holder, value)
    admission = SimpleNamespace(_validate_tracked_schema=schema_gate)
    constructed, constructed_value = closure._construct_report(
        closure._Ops(), admission, closures, mappings
    )
    if constructed != raw or constructed_value != golden or calls != [raw]:
        raise AssertionError("production report construction diverged from golden")
    owner = object.__new__(closure.PreparedRuntimeClosure)
    checkpoints = []
    owner._state, owner._ops = closure._OwnerState.READY, SimpleNamespace(checkpoint=checkpoints.append)
    owner._revalidate_ready_report = lambda: constructed
    owner._poison_owner = lambda error: (_ for _ in ()).throw(error)
    if owner._canonical_report_bytes() is not constructed or checkpoints != [
        "comparison.before-revalidate", "comparison.after-revalidate"
    ] or len(constructed) > closure._MAX_REPORT:
        raise AssertionError("trusted comparison report escaped its canonical bound")
    owner._state = closure._OwnerState.CLOSED
    try: owner._canonical_report_bytes()
    except closure.RuntimeClosureError: pass
    else: raise AssertionError("closed preparation disclosed report bytes")
    producer_value = producer(raw)
    consumer_value = consumer(raw)
    schema_method(schema_holder, raw)
    if producer_reencode(producer_value) != raw or consumer_reencode(consumer_value) != raw:
        raise AssertionError("production report re-encoder diverged")
    if producer_value is consumer_value or producer_value != consumer_value:
        raise AssertionError("production report codec values are not independent and equal")
    launcher._require_identical_closure_reports(raw, bytes(raw))
    drift = copy.deepcopy(golden)
    drift["tools"][0]["objects"][0]["sha256"] = hashlib.sha256(b"fresh-report-drift").hexdigest()
    drift_raw = canonical(recompute(drift)) + b"\n"
    try: launcher._require_identical_closure_reports(raw, drift_raw)
    except launcher.RuntimeLauncherError as error:
        if error.code != "closure-report-drift": raise
    else: raise AssertionError("distinct canonical preparation reports compared equal")
    identifiers = [row["id"] for row in rows]
    declared = set(identifiers)
    if len(declared) != len(identifiers):
        raise AssertionError("duplicate declared report case")
    selected = set()
    consumed = set()
    oracle = set()
    for row in rows:
        selected.add(row["id"])
        hostile = hostile_bytes(golden, raw, row)
        events = dispatch(row, methods, hostile)
        if not events or tuple(row["sentinel"]) != events:
            raise AssertionError(f"{row['id']}: report cut was not causally consumed")
        consumed.add(row["id"])
        expected_oracles = sum(expected != "OK" for expected in row["intended_code"])
        if prove_oracle_edge_deletions(row, methods, hostile) != expected_oracles:
            raise AssertionError(f"{row['id']}: report oracle edge cardinality changed")
        oracle.add(row["id"])
    if not declared == selected == consumed == oracle:
        raise AssertionError("report declared/selected/consumed/oracle mismatch")
    prohibited = (b"/usr/", b"HOME", b"0x7", b"command_output", b'"pid"')
    if any(item in raw for item in prohibited):
        raise AssertionError("golden report disclosed prohibited metadata")
    print("Outcome 2 runtime report portable tests passed")
if __name__ == "__main__":
    if sys.argv == [sys.argv[0], "--schema-corpus"]:
        emit_schema_corpus()
    elif len(sys.argv) == 1:
        parent()
    else:
        raise SystemExit(2)

#!/usr/bin/env python3
"""Exercise report construction and each independent production report codec."""
import copy
import errno
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
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
def bpf_result(program, syscall, arguments=(), architecture=0xC000003E):
    words = {0: syscall, 4: architecture}
    for index, value in enumerate(arguments):
        words[16 + index * 8] = value & 0xFFFFFFFF
        words[20 + index * 8] = (value >> 32) & 0xFFFFFFFF
    accumulator = 0
    pc = 0
    while pc < len(program):
        code, yes, no, constant = program[pc]
        if code == 0x20:
            accumulator = words.get(constant, 0)
        elif code == 0x15:
            pc += yes if accumulator == constant else no
        elif code == 0x06:
            return constant
        else:
            raise AssertionError(f"unsupported production cBPF opcode: {code:#x}")
        pc += 1
    raise AssertionError("production cBPF program fell through")
def production_seccomp_contract(launcher):
    socket_routes = {
        "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair",
        "setsockopt", "getsockopt", "accept4", "recvmmsg", "sendmmsg",
    }
    if not socket_routes <= set(launcher._DENIED_SYSCALLS):
        raise AssertionError("production seccomp syscall table is incomplete")
    program = launcher._seccomp_program()
    architecture_first = program[0] == (0x20, 0, 0, 4) and program[3] == (0x20, 0, 0, 0)
    if not architecture_first or bpf_result(program, 0, architecture=0) != 0x80000000:
        raise AssertionError("seccomp architecture gate does not precede syscall dispatch")
    denied = 0x00050000 | errno.EPERM
    if any(bpf_result(program, number) != denied for number in launcher._DENIED_SYSCALLS.values()):
        raise AssertionError("modeled seccomp table route was not denied")
    fcntl_number = launcher._DENIED_SYSCALLS["fcntl"]
    allowed_commands = (fcntl.F_GETFD, fcntl.F_GETFL)
    denied_commands = (fcntl.F_DUPFD, fcntl.F_DUPFD_CLOEXEC, fcntl.F_SETFD,
                       fcntl.F_SETFL, -1, 0xFFFFFFFF)
    if any(bpf_result(program, fcntl_number, (198, command)) != 0x7FFF0000
           for command in allowed_commands):
        raise AssertionError("production fcntl read-only query was denied")
    if any(bpf_result(program, fcntl_number, (198, command)) != denied
           for command in denied_commands):
        raise AssertionError("production fcntl mutation/duplication route was admitted")
    other_commands = set(range(256)) - set(allowed_commands)
    if any(bpf_result(program, fcntl_number, (198, command)) != denied
           for command in other_commands):
        raise AssertionError("production fcntl unknown command route was admitted")
    hostile_widths = tuple((high << 32) | command
                           for high in (1, 0xFFFFFFFF)
                           for command in allowed_commands)
    if any(bpf_result(program, fcntl_number, (198, command)) != denied
           for command in hostile_widths):
        raise AssertionError("production fcntl filter ignored the 64-bit command high word")
    fixed = (198, 0, 0, 0, launcher._AT_EMPTY_PATH)
    hostile = (
        (199, *fixed[1:]),
        ((1 << 32) | 198, *fixed[1:]),
        (*fixed[:4], 0),
        (*fixed[:4], launcher._AT_EMPTY_PATH | 1),
        (*fixed[:4], launcher._AT_EMPTY_PATH | (1 << 32)),
    )
    if bpf_result(program, 322, fixed) != 0x7FFF0000:
        raise AssertionError("fixed production execveat shape was not admitted")
    if any(bpf_result(program, 322, arguments) != denied for arguments in hostile):
        raise AssertionError("production execveat filter admitted a hostile shape")
    set_mode = bpf_result(program, 157, (launcher._PR_SET_SECCOMP,))
    get_mode = bpf_result(program, 157, (launcher._PR_GET_SECCOMP,))
    if set_mode != denied or get_mode != 0x7FFF0000:
        raise AssertionError("production prctl seccomp argument filter changed")
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

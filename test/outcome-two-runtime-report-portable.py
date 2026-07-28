#!/usr/bin/env python3
"""Actual report construction and three independent production validation paths."""

import copy
import errno
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
    """Recompute every digest except the one isolated after this function."""
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

def report_bytes(value):
    return canonical(value) + b"\n"

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
    if name == "duplicate-key":
        return raw.replace(b"{", b'{"version":"duplicate",', 1)
    if name == "leading-whitespace":
        return b" " + raw
    if name == "trailing-whitespace":
        return raw[:-1] + b" \n"
    if name == "pretty-json":
        return json.dumps(json.loads(raw), indent=2).encode() + b"\n"
    if name == "missing-lf":
        return raw[:-1]
    if name == "extra-lf":
        return raw + b"\n"
    if name == "invalid-utf8":
        return raw[:-1] + b"\xff\n"
    if name == "float":
        return raw.replace(b'"size":101', b'"size":101.0', 1)
    if name == "constant":
        return raw.replace(b'"size":101', b'"size":NaN', 1)
    if name == "oversized":
        return b"{" + b" " * 131_072 + b"}\n"
    raise AssertionError(f"unknown encoding mutation: {name}")

def bpf_result(program, syscall, arguments=(), architecture=0xC000003E):
    words = {0: syscall, 4: architecture}
    for index, value in enumerate(arguments):
        words[16 + index * 8] = value & 0xFFFFFFFF
        words[20 + index * 8] = value >> 32
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
        "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg",
        "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername",
        "socketpair", "setsockopt", "getsockopt", "accept4", "recvmmsg", "sendmmsg",
    }
    if not socket_routes <= set(launcher._DENIED_SYSCALLS):
        raise AssertionError("production seccomp syscall table is incomplete")
    program = launcher._seccomp_program()
    if (program[0] != (0x20, 0, 0, 4) or program[3] != (0x20, 0, 0, 0)
            or bpf_result(program, 0, architecture=0) != 0x80000000):
        raise AssertionError("seccomp architecture gate does not precede syscall dispatch")
    denied = 0x00050000 | errno.EPERM
    if any(bpf_result(program, number) != denied for number in set(launcher._DENIED_SYSCALLS.values())):
        raise AssertionError("modeled seccomp table route was not denied")
    fixed = (198, 0, 0, 0, launcher._AT_EMPTY_PATH)
    hostile = ((199, *fixed[1:]), ((1 << 32) | 198, *fixed[1:]), (*fixed[:4], 0),
               (*fixed[:4], launcher._AT_EMPTY_PATH | 1),
               (*fixed[:4], launcher._AT_EMPTY_PATH | (1 << 32)))
    if bpf_result(program, 322, fixed) != 0x7FFF0000:
        raise AssertionError("fixed production execveat shape was not admitted")
    if any(bpf_result(program, 322, arguments) != denied for arguments in hostile):
        raise AssertionError("production execveat argument filter admitted a hostile shape")
    if (bpf_result(program, 157, (launcher._PR_SET_SECCOMP,)) != denied
            or bpf_result(program, 157, (launcher._PR_GET_SECCOMP,)) != 0x7FFF0000):
        raise AssertionError("production prctl seccomp argument filter changed")

def production_observation_mutation(launcher):
    if "_build_observed_result" not in launcher._coordinate_with_ops.__code__.co_names:
        raise AssertionError("production coordinator bypasses observed-result construction")
    names = set(tuple(launcher.RuntimeQualificationResult.__dataclass_fields__)[7:])
    cleanup_names = {"children_reaped", "descendants_reaped", "descriptors_restored",
                     "mounts_restored", "namespace_handles_released", "namespaces_released", "paths_restored"}
    tool = {name: True for name in names - cleanup_names}
    cleanup = {name: True for name in cleanup_names}
    if launcher._build_observed_result((tool, dict(tool)), cleanup) != {name: True for name in names}:
        raise AssertionError("complete production observation construction diverged")
    for changed in names:
        first, final = dict(tool), dict(cleanup)
        target = final if changed in cleanup_names else first
        target[changed] = False
        expect_typed_rejection(lambda _raw: launcher._build_observed_result((first, tool), final), b"",
                               launcher.RuntimeLauncherError, f"observation:{changed}")
        target.pop(changed)
        expect_typed_rejection(lambda _raw: launcher._build_observed_result((first, tool), final), b"",
                               launcher.RuntimeLauncherError, f"omission:{changed}")

def production_parser_contract(launcher):
    stat_record = b"7 (worker) S " + b" ".join([b"1"] * 49) + b"\n"
    maps_record = b"00400000-00401000 r-xp 00000000 08:01 123 /tool\n"
    status_record = launcher._status("child", 0, pid=7)
    for parser, accepted, hostile in (
        (lambda raw: launcher._parse_proc_stat(raw, 7), stat_record, stat_record.replace(b"7 ", b"8 ", 1)),
        (launcher._parse_maps, maps_record, maps_record.replace(b"r-xp", b"r-qp")),
        (lambda raw: launcher._parse_sandbox_status(raw, "child", 0), status_record, status_record[:-1] + b',"x":0}'),
    ):
        parser(accepted)
        expect_typed_rejection(parser, hostile, launcher.RuntimeLauncherError, "strict production parser")

def manifest():
    records = [json.loads(line) for line in MUTATIONS_PATH.read_text().splitlines()]
    header, *rows = records
    required = ("id", "production_method", "primitive_fault", "intended_code",
                "cleanup_domains", "sentinel")
    expected_header = {"type", "version", "acceptance_ids", "case_fields"}
    if set(header) != expected_header or header["type"] != "header":
        raise AssertionError("report manifest header is not closed")
    if tuple(header["case_fields"]) != required or any(set(row) != set(required) for row in rows):
        raise AssertionError("report manifest case contract changed")
    value = {"semantic": [], "encoding": []}
    for row in rows:
        fault = row["primitive_fault"]
        family = fault.get("family") if type(fault) is dict else None
        expected = {"family", "name", "schema"} if family == "semantic" else {"family", "name"}
        if family not in value or set(fault) != expected:
            raise AssertionError("report primitive fault is not closed")
        case = {**row, "primitive_fault": fault["name"]}
        if family == "semantic":
            case["schema"] = fault["schema"]
        value[family].append(case)
    identifiers = [row["id"] for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError("duplicate report case identity")
    if any(not row["production_method"] or not row["sentinel"] for row in rows):
        raise AssertionError("report case lacks a production branch sentinel")
    return value

def corpus(fixture):
    golden = json.loads(GOLDEN_PATH.read_bytes())
    rows = [{"id": "golden", "schema": True, "value": golden}]
    for case in fixture["semantic"]:
        rows.append({"id": case["id"], "schema": case["schema"],
                     "value": mutate(golden, case["primitive_fault"])})
    return rows

def production_objects(closure, golden):
    closures = []
    mappings = []
    identity = 100
    for tool_record in golden["tools"]:
        objects = []
        for record in tool_record["objects"]:
            generation = closure.SourceGeneration(
                8,
                identity,
                record["size"],
                1,
                1,
                stat.S_IFREG | 0o555,
                0,
                0,
            )
            identity += 1
            metadata = SimpleNamespace(
                interpreter=None,
                soname=record["soname"],
                needed=tuple(record["needed"]),
            )
            objects.append(closure.AuthenticatedObject(
                record["role"],
                "/held/object",
                900 + identity,
                generation,
                (),
                record["size"],
                record["sha256"],
                metadata,
            ))
        closures.append(closure.ResolvedToolClosure(
            tool_record["tool"], objects[0], objects[1], tuple(objects[2:])
        ))
        mapped = tuple((item["role"], item["sha256"]) for item in tool_record["objects"])
        mappings.append(closure.MappedToolClosure(
            tool_record["tool"], mapped, tool_record["mapping_sha256"]
        ))
    return tuple(closures), tuple(mappings)

def expect_typed_rejection(function, raw, error_type, label):
    try:
        function(raw)
    except error_type:
        return
    except BaseException as error:
        raise AssertionError(f"{label} raised untyped {type(error).__name__}") from error
    raise AssertionError(f"{label} was accepted")

def emit_schema_corpus():
    fixture = manifest()
    for row in corpus(fixture):
        print(json.dumps(row, sort_keys=True, separators=(",", ":")))


def parent():
    fixture = manifest()
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
    decoders = {schema_method.__code__, producer.__code__, consumer.__code__}
    encoders = {producer_reencode.__code__, consumer_reencode.__code__}
    if len(decoders) != 3 or len(encoders) != 2:
        raise AssertionError("three production report codec implementations collapsed")

    schema_holder = SimpleNamespace(_schema_bytes=SCHEMA_PATH.read_bytes())
    schema_calls = []
    def schema_gate(raw):
        schema_calls.append(raw)
        return schema_method(schema_holder, raw)
    admission = SimpleNamespace(_validate_tracked_schema=schema_gate)
    raw = GOLDEN_PATH.read_bytes()
    golden = json.loads(raw)
    closures, mappings = production_objects(closure, golden)
    constructed, constructed_value = closure._construct_report(
        closure._Ops(), admission, closures, mappings
    )
    if constructed != raw or constructed_value != golden or schema_calls != [raw]:
        raise AssertionError("actual three-codec production construction diverged from golden")
    producer_value = producer(raw)
    consumer_value = consumer(raw)
    schema_gate(raw)
    if producer_reencode(producer_value) != raw:
        raise AssertionError("producer re-encoder diverged")
    if consumer_reencode(consumer_value) != raw:
        raise AssertionError("consumer re-encoder diverged")
    if producer_value is consumer_value or producer_value != consumer_value:
        raise AssertionError("semantic codec values are not independent and equal")

    executed = []
    for row in corpus(fixture)[1:]:
        hostile = report_bytes(row["value"])
        if row["schema"]:
            schema_gate(hostile)
        else:
            expect_typed_rejection(
                schema_gate, hostile, launcher.RuntimeLauncherError, f"schema:{row['id']}"
            )
        expect_typed_rejection(
            producer, hostile, closure.RuntimeClosureError, f"producer:{row['id']}"
        )
        expect_typed_rejection(
            consumer, hostile, launcher.RuntimeLauncherError, f"consumer:{row['id']}"
        )
        executed.append(row["id"])
    for case in fixture["encoding"]:
        hostile = encoding_mutation(raw, case["primitive_fault"])
        expect_typed_rejection(
            schema_gate, hostile, launcher.RuntimeLauncherError, f"schema:{case['id']}"
        )
        expect_typed_rejection(
            producer, hostile, closure.RuntimeClosureError, f"producer:{case['id']}"
        )
        expect_typed_rejection(
            consumer, hostile, launcher.RuntimeLauncherError, f"consumer:{case['id']}"
        )
        executed.append(case["id"])
    declared = [case["id"] for case in fixture["semantic"] + fixture["encoding"]]
    if executed != declared:
        raise AssertionError("report manifest rows were not consumed exactly once")
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

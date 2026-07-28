#!/usr/bin/env python3
"""Actual report construction and three independent production validation paths."""

import copy
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


def manifest():
    value = json.loads(MUTATIONS_PATH.read_text())
    expected = {"version", "acceptance_ids", "case_fields", "semantic", "encoding"}
    if set(value) != expected:
        raise AssertionError("report manifest shape is not closed")
    fields = tuple(value["case_fields"])
    required = (
        "id",
        "production_method",
        "primitive_fault",
        "intended_code",
        "cleanup_domains",
        "sentinel",
    )
    if fields != required:
        raise AssertionError("report manifest case contract changed")
    semantic_shape = set(required) | {"schema"}
    if any(set(case) != semantic_shape for case in value["semantic"]):
        raise AssertionError("semantic report case is not closed")
    if any(set(case) != set(required) for case in value["encoding"]):
        raise AssertionError("encoding report case is not closed")
    cases = [*value["semantic"], *value["encoding"]]
    identifiers = [case["id"] for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError("duplicate report case identity")
    if any(not case["production_method"] or not case["sentinel"] for case in cases):
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
    producer = closure._producer_decode_report
    consumer = launcher._decode_report
    schema_method = launcher._SourceAdmission._validate_tracked_schema
    identities = {schema_method.__code__, producer.__code__, consumer.__code__}
    if len(identities) != 3:
        raise AssertionError("schema/producer/consumer implementation identity collapsed")
    producer_reencode = closure._producer_reencode_report
    if producer_reencode.__code__ is launcher._canonical.__code__:
        raise AssertionError("producer and consumer re-encoders share an implementation")

    schema_holder = SimpleNamespace(_schema_bytes=SCHEMA_PATH.read_bytes())
    schema_gate = lambda raw: schema_method(schema_holder, raw)
    admission = SimpleNamespace(_validate_tracked_schema=schema_gate)
    raw = GOLDEN_PATH.read_bytes()
    golden = json.loads(raw)
    closures, mappings = production_objects(closure, golden)
    constructed, constructed_value = closure._construct_report(
        closure._Ops(), admission, closures, mappings
    )
    if constructed != raw or constructed_value != golden:
        raise AssertionError("actual production report construction diverged from golden")
    producer_value = producer(raw)
    consumer_value = consumer(raw)
    schema_gate(raw)
    if producer_reencode(producer_value) != raw:
        raise AssertionError("producer re-encoder diverged")
    if launcher._canonical(consumer_value, True) != raw:
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

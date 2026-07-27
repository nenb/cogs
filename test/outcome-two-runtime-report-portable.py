#!/usr/bin/env python3
"""Independent producer/consumer report semantics and tracked-schema corpus."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 report tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
CLOSURE = REMOTE / "completion_trusted_runtime_closure.py"
LAUNCHER = REMOTE / "completion_trusted_runtime_launcher.py"
GOLDEN = ROOT / "test/fixtures/outcome-two/reports/runtime-closure-v1.canonical.jsonl"
MUTATIONS = ROOT / "test/fixtures/outcome-two/reports/mutations.json"
sys.path.insert(0, str(REMOTE))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def recompute(value):
    """Recompute every digest not deliberately mutated after this call."""
    for tool in value["tools"]:
        tool["closure_sha256"] = digest(tool["objects"])
        tool["mapping_sha256"] = digest([[item["role"], item["sha256"]]
                                         for item in tool["objects"]])
    digest_view = [{key: item for key, item in tool.items() if key != "mapping_sha256"}
                   for tool in value["tools"]]
    value["closure_sha256"] = digest(digest_view)
    return value


def report_bytes(value):
    return canonical(value) + b"\n"


def shuffled(value):
    if isinstance(value, dict):
        return {key: shuffled(value[key]) for key in reversed(tuple(value))}
    if isinstance(value, list):
        return [shuffled(item) for item in value]
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
            candidate["needed"] = ["bad name" if item == "libalpha.so.1" else item
                                     for item in candidate["needed"]]
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
        raise AssertionError(name)
    recompute(value)
    if name == "aggregate-digest":
        value["closure_sha256"] = "0" * 64
    elif name == "tool-closure-digest":
        tool["closure_sha256"] = "0" * 64
        digest_view = [{key: item for key, item in row.items() if key != "mapping_sha256"}
                       for row in value["tools"]]
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
    raise AssertionError(name)


def reject(function, raw, label):
    try:
        function(raw)
    except Exception:
        return
    raise AssertionError(f"{label} accepted by {function.__module__}.{function.__name__}")


def emit(mode):
    closure = load("completion_trusted_runtime_closure", CLOSURE)
    value = json.loads(GOLDEN.read_bytes())
    records = shuffled(value["tools"]) if mode == "reverse-keys" else value["tools"]
    sys.stdout.buffer.write(closure._canonical_report_for_tests(records))


def independent(mode):
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--emit", mode],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"},
        timeout=5, check=False,
    )
    if result.returncode != 0:
        raise AssertionError((mode, result.stderr))
    return result.stdout


def corpus():
    fixture = json.loads(MUTATIONS.read_text())
    golden = json.loads(GOLDEN.read_bytes())
    rows = [{"id": "golden", "schema": True, "value": golden}]
    rows.extend({"id": case["id"], "schema": case["schema"],
                 "value": mutate(golden, case["id"])} for case in fixture["semantic"])
    return rows


def emit_schema_corpus():
    for row in corpus():
        print(json.dumps(row, sort_keys=True, separators=(",", ":")))


def parent():
    closure = load("completion_trusted_runtime_closure", CLOSURE)
    launcher = load("completion_trusted_runtime_launcher", LAUNCHER)
    producer = closure._validate_report_bytes
    consumer = launcher._decode_report
    raw = GOLDEN.read_bytes()
    producer(raw)
    consumer(raw)
    if independent("normal") != raw or independent("reverse-keys") != raw:
        raise AssertionError("independent producer bytes diverged")
    fixture = json.loads(MUTATIONS.read_text())
    executed = []
    for row in corpus()[1:]:
        hostile = report_bytes(row["value"])
        reject(producer, hostile, row["id"])
        reject(consumer, hostile, row["id"])
        executed.append(row["id"])
    for name in fixture["encoding"]:
        hostile = encoding_mutation(raw, name)
        reject(producer, hostile, name)
        reject(consumer, hostile, name)
        executed.append(name)
    declared = [row["id"] for row in fixture["semantic"]] + fixture["encoding"]
    if executed != declared or len(executed) != len(set(executed)):
        raise AssertionError("report fixtures were not executed exactly once")
    prohibited = (b"/usr/", b"HOME", b"0x7", b"command_output", b'"pid"')
    if any(item in raw for item in prohibited):
        raise AssertionError("golden report disclosed prohibited metadata")
    print("Outcome 2 runtime report portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--emit":
        emit(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "--schema-corpus":
        emit_schema_corpus()
    elif len(sys.argv) == 1:
        parent()
    else:
        raise SystemExit(2)

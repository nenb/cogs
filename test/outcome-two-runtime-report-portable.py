#!/usr/bin/env python3
"""Portable canonical runtime-closure report and schema qualification."""

import copy
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
MODULE = REMOTE / "completion_trusted_runtime_closure.py"
sys.path.insert(0, str(REMOTE))
SCHEMA = ROOT / "schemas/trusted-runtime-closure-v1.json"
GOLDEN = ROOT / "test/fixtures/outcome-two/reports/runtime-closure-v1.canonical.json"
MUTATIONS = ROOT / "test/fixtures/outcome-two/reports/mutations.json"


def load_module():
    spec = importlib.util.spec_from_file_location("completion_trusted_runtime_closure", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def rejected(module, raw, label="hostile"):
    try:
        module._validate_report_bytes(raw)
    except module.RuntimeClosureError:
        return
    raise AssertionError(f"hostile closure report accepted: {label}")


def shuffled_keys(value):
    if isinstance(value, dict):
        return {key: shuffled_keys(value[key]) for key in reversed(tuple(value))}
    if isinstance(value, list):
        return [shuffled_keys(item) for item in value]
    return value


def emit(mode):
    module = load_module()
    value = json.loads(GOLDEN.read_bytes())
    records = value["tools"]
    if mode == "reverse-keys":
        records = shuffled_keys(records)
    sys.stdout.buffer.write(module._canonical_report_for_tests(records))


def independent(mode):
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--emit", mode],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"},
        timeout=5, check=False,
    )
    assert result.returncode == 0, (mode, result.stderr)
    return result.stdout


def semantic_mutation(value, name):
    hostile = copy.deepcopy(value)
    tool = hostile["tools"][0]
    object_ = tool["objects"][0]
    if name == "closure-digest": hostile["closure_sha256"] = "0" * 64
    elif name == "mapping-digest": tool["mapping_sha256"] = "0" * 64
    elif name == "tool-order": hostile["tools"][0], hostile["tools"][1] = hostile["tools"][1], hostile["tools"][0]
    elif name == "object-order": tool["objects"][2], tool["objects"][3] = tool["objects"][3], tool["objects"][2]
    elif name == "duplicate-needed": object_["needed"].append(object_["needed"][0])
    elif name == "missing-provider": object_["needed"] = ["libmissing.so.1"]
    elif name == "seal-profile": tool["seal_profile"] = "linux-memfd-exec-seals-v1"
    elif name == "sealed-executable": tool["sealed_executable"] = True
    elif name == "extra-field": tool["extra"] = False
    elif name == "prohibited-path": hostile["host_path"] = "/usr/lib/secret"
    elif name == "prohibited-environment": hostile["environment"] = {"HOME": "/secret"}
    elif name == "prohibited-address": hostile["mapping_address"] = "0x7fff"
    elif name == "prohibited-command-output": hostile["command_output"] = "secret"
    elif name == "prohibited-identifier": hostile["pid"] = 123
    else: raise AssertionError(name)
    return hostile


def encoding_mutation(raw, name):
    if name == "duplicate-key": return raw.replace(b"{", b'{"version":"duplicate",', 1)
    if name == "leading-whitespace": return b" " + raw
    if name == "pretty-json": return json.dumps(json.loads(raw), indent=2).encode() + b"\n"
    if name == "missing-lf": return raw[:-1]
    if name == "extra-lf": return raw + b"\n"
    if name == "invalid-utf8": return raw[:-1] + b"\xff\n"
    if name == "oversized": return b"{" + b" " * 131_072 + b"}\n"
    raise AssertionError(name)


def schema_contract():
    schema = json.loads(SCHEMA.read_text())
    assert schema["$schema"].endswith("2020-12/schema")
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["closure_sha256", "tools", "version"]
    assert schema["properties"]["version"]["const"] == "cogs.trusted-runtime-closure/v1"
    assert schema["properties"]["tools"]["minItems"] == schema["properties"]["tools"]["maxItems"] == 3
    for definition in ("object", "tool"):
        assert schema["$defs"][definition]["additionalProperties"] is False
    assert schema["$defs"]["object"]["required"] == ["needed", "role", "sha256", "size", "soname"]
    assert set(schema["$defs"]["tool"]["required"]) == {
        "closure_sha256", "mapping_sha256", "objects", "seal_profile", "sealed_executable", "tool",
    }


def parent():
    module = load_module()
    raw = GOLDEN.read_bytes()
    value = json.loads(raw)
    assert module._validate_report_bytes(raw) == raw
    assert independent("normal") == independent("normal") == raw
    assert independent("normal") == independent("reverse-keys")
    cases = json.loads(MUTATIONS.read_text())
    for name in cases["semantic"]:
        hostile = semantic_mutation(value, name)
        rejected(module, json.dumps(hostile, sort_keys=True, separators=(",", ":")).encode() + b"\n", name)
    for name in cases["encoding"]:
        rejected(module, encoding_mutation(raw, name), name)
    for key in ("closure_sha256", "tools", "version"):
        hostile = copy.deepcopy(value); del hostile[key]
        rejected(module, json.dumps(hostile, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    for key in tuple(value["tools"][0]):
        hostile = copy.deepcopy(value); del hostile["tools"][0][key]
        rejected(module, json.dumps(hostile, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    for key in tuple(value["tools"][0]["objects"][0]):
        hostile = copy.deepcopy(value); del hostile["tools"][0]["objects"][0][key]
        rejected(module, json.dumps(hostile, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    schema_contract()
    prohibited = (b"/usr/", b"HOME", b"0x7", b"command_output", b'"pid"')
    assert not any(item in raw for item in prohibited)
    print("Outcome 2 runtime report portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--emit":
        emit(sys.argv[2])
    elif len(sys.argv) == 1:
        parent()
    else:
        raise SystemExit(2)

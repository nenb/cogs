#!/usr/bin/env python3
"""Portable tests for the pure fixed completion fixture model."""

import dataclasses
import hashlib
import importlib.util
import inspect
import io
import json
from pathlib import Path
import struct
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy/aws-feasibility/remote/completion_fixtures.py"


def load_module():
    spec = importlib.util.spec_from_file_location("completion_fixtures_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fixture = load_module()
first = fixture.fixed_fixtures()
second = fixture.fixed_fixtures()
assert first == second
assert first.git.source.ustar == second.git.source.ustar
assert first.package.source.ustar == second.package.source.ustar

# Git source dimensions and the exact line algorithm.
git_records = first.git.source.records
assert len(git_records) == 514
assert git_records[0].path == "." and git_records[1].path == "files"
assert [record.path for record in git_records[2:]] == [f"files/file-{index:04d}.txt" for index in range(512)]
for index, record in enumerate(git_records[2:]):
    lines = record.content.splitlines(keepends=True)
    assert len(lines) == 128 and all(len(line) == 65 and line.endswith(b"\n") for line in lines)
    for line_index in range(128):
        seed = b"cogs-stage2-git-v1\0" + struct.pack(">HH", index, line_index)
        assert lines[line_index] == hashlib.sha256(seed).hexdigest().encode() + b"\n"
    assert record.size == 8320 and record.content_sha256 == hashlib.sha256(record.content).hexdigest()

for artifact in (first.git.source, first.package.source):
    assert artifact.records[0] == fixture.TreeRecord(".", "directory", 0o755, 0, 0, 1782172800, 0, None, None)
    assert artifact.ustar_sha256 == hashlib.sha256(artifact.ustar).hexdigest()
    assert len(artifact.ustar) % 512 == 0 and artifact.ustar.endswith(b"\0" * 1024)
    for record in artifact.records:
        assert (record.uid, record.gid, record.mtime) == (0, 0, 1782172800)
        assert record.mode == (0o755 if record.kind == "directory" else 0o644)


def parse_archive(artifact):
    with tarfile.open(fileobj=io.BytesIO(artifact.ustar), mode="r:") as archive:
        members = archive.getmembers()
        assert artifact.ustar[257:265] == b"ustar\0" + b"00"
        assert [member.name for member in members] == [record.path for record in artifact.records]
        for member, record in zip(members, artifact.records, strict=True):
            assert member.uid == member.gid == 0
            assert member.mtime == 1782172800 and member.mode == record.mode
            assert member.isdir() == (record.kind == "directory")
            if record.kind == "file":
                assert member.isfile() and member.size == record.size
                assert archive.extractfile(member).read() == record.content
        return members


git_members = parse_archive(first.git.source)
assert len(git_members) == 514 and len(first.git.source.ustar) == 4720640
assert first.git.source.ustar_sha256 == "06450642c9c6cd69b1e6f961ea085e2f873faa40431a34d7a35f1259ce4e2e63"

# Independently frame every Git SHA-1 object payload.
def oid(kind, content):
    framed = kind.encode() + b" " + str(len(content)).encode() + b"\0" + content
    return hashlib.sha1(framed, usedforsecurity=False).hexdigest()


blob_oids = [oid("blob", record.content) for record in git_records[2:]]
assert first.git.blob_oids == tuple(blob_oids) and len(set(first.git.blob_oids)) == 512
nested = b"".join(
    b"100644 file-" + f"{index:04d}".encode() + b".txt\0" + bytes.fromhex(blob_oid)
    for index, blob_oid in enumerate(blob_oids)
)
assert first.git.nested_tree_oid == oid("tree", nested) == "f8c8ab608d5973da85abb06c5100261dc14e8754"
root_tree = b"40000 files\0" + bytes.fromhex(first.git.nested_tree_oid)
assert first.git.root_tree_oid == oid("tree", root_tree) == "458e8769e643510ef5b6181beae8761fddc5ee28"
identity = b"Cogs Stage 2 <cogs-stage2> 1782172800 +0000"
expected_commit = (
    b"tree 458e8769e643510ef5b6181beae8761fddc5ee28\n"
    b"author " + identity + b"\ncommitter " + identity + b"\n\ncogs stage2 fixture v1\n"
)
assert first.git.commit == expected_commit
assert first.git.commit_oid == oid("commit", expected_commit) == "ca429a94b73caea0fc39164b8087cc1c63f43818"
assert first.git.branch == "refs/heads/main"
assert first.git.source.logical_digest == "2d24163a199bef07f97d0a0bc1d4a6ac7b7ee324df8f7fe5a252d2958543c3c9"

# The fixed mutation recipe has unambiguous payload and expected-postimage semantics.
assert len(first.git.mutations) == len(first.git.porcelain_rows) == 40
assert [item.operation for item in first.git.mutations] == ["append"] * 32 + ["create"] * 8
expected_rows = tuple(
    [f" M files/file-{index:04d}.txt".encode() for index in range(32)]
    + [f"?? untracked/file-{index:04d}.txt".encode() for index in range(8)]
)
assert first.git.porcelain_rows == expected_rows
assert first.git.porcelain == b"\n".join(expected_rows) + b"\n"
working = {record.path: record.content for record in git_records if record.kind == "file"}
for item in first.git.mutations:
    assert item.payload_sha256 == hashlib.sha256(item.payload).hexdigest()
    if item.operation == "append":
        assert item.path in working and item.payload == b"cogs-stage2-git-v1 modified\n"
        working[item.path] += item.payload
    else:
        assert item.operation == "create" and item.path not in working
        working[item.path] = item.payload
    assert hashlib.sha256(working[item.path]).hexdigest() == item.result_sha256
for index, item in enumerate(first.git.mutations[32:]):
    seed = b"cogs-stage2-git-v1\0" + struct.pack(">HH", 512, index)
    assert item.payload == hashlib.sha256(seed).hexdigest().encode() + b"\n"

# Package control, payload dimensions, source archive, and installed expectation.
package = first.package
assert package.control == (
    b"Package: cogs-stage2-fixture\nVersion: 1.0\nArchitecture: all\n"
    b"Maintainer: Cogs Stage 2 <cogs-stage2>\nDescription: Deterministic Cogs Stage 2 fixture\n"
)
assert b"Depends:" not in package.control and package.control.count(b"\n") == 5
payloads = [record for record in package.source.records if record.path.startswith("usr/share/cogs-stage2-fixture/payload-")]
assert len(payloads) == 256
assert [record.path for record in payloads] == [f"usr/share/cogs-stage2-fixture/payload-{index:04d}.bin" for index in range(256)]
for index, record in enumerate(payloads):
    expected = b"".join(
        hashlib.sha256(b"cogs-stage2-package-v1\0" + struct.pack(">HH", index, block)).digest()
        for block in range(128)
    )
    assert record.content == expected and record.size == 4096
package_members = parse_archive(package.source)
assert len(package_members) == 262 and len(package.source.ustar) == 1184256
assert package.source.ustar_sha256 == "21e6a9306b2ecf62f2a2a1137ac997b35d63e96a478af61da6762d985e920b68"
assert package.source.logical_digest == "03f9ce0491b29e2ffaf216e9d49bc0c382ad1cad808aa1ad53284c06185fce52"
installed = package.installed
assert (installed.package, installed.version, installed.architecture, installed.status) == (
    "cogs-stage2-fixture", "1.0", "all", "install ok installed"
)
assert installed.entry_count == 259 and len(installed.records) == 260
assert installed.regular_bytes == 256 * 4096
assert installed.logical_digest == "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2"
assert [record.path for record in installed.records[-256:]] == [record.path for record in payloads]

# Independently reconstruct canonical JSON-lines, including every Git recipe field.
def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"

stream = b"".join(
    canonical(
        {
            "version": "cogs.stage2-logical-tree/v1", "path": record.path, "kind": record.kind,
            "mode": record.mode, "uid": record.uid, "gid": record.gid, "mtime": record.mtime,
            "size": record.size, "regular_sha256": record.content_sha256,
        }
    )
    for record in git_records
)
parsed = [json.loads(line) for line in stream.splitlines()]
assert hashlib.sha256(stream).hexdigest() == first.git.source.logical_digest
metadata = {
    "version": "cogs-stage2-git-v1", "file_count": 512, "lines_per_file": 128,
    "branch": "refs/heads/main", "nested_tree_oid": first.git.nested_tree_oid,
    "root_tree_oid": first.git.root_tree_oid, "commit_oid": first.git.commit_oid,
    "commit": first.git.commit.decode(), "modified_count": 32, "untracked_count": 8,
}
recipe = b"".join(
    canonical(
        {
            "operation": item.operation, "path": item.path, "payload_sha256": item.payload_sha256,
            "result_sha256": item.result_sha256,
        }
    )
    for item in first.git.mutations
)
independent_logical = canonical(metadata) + stream + recipe
assert hashlib.sha256(independent_logical).hexdigest() == first.git.logical_digest
assert first.git.logical_digest == "73ccf2bce069d96d1dbd7e927e0fbd9205dcedfdb4a8ff104eb29e3f3e9e0b7c"
for field, changed in (("branch", "refs/heads/other"), ("file_count", 511), ("commit", metadata["commit"] + "!")):
    assert hashlib.sha256(canonical({**metadata, field: changed}) + stream + recipe).hexdigest() != first.git.logical_digest
changed_recipe = recipe.replace(first.git.mutations[0].result_sha256.encode(), b"0" * 64, 1)
assert hashlib.sha256(canonical(metadata) + stream + changed_recipe).hexdigest() != first.git.logical_digest
assert hashlib.sha256(fixture._tree_stream(package.source.records)).hexdigest() == package.source.logical_digest
assert len(parsed) == len(git_records) and parsed[0]["path"] == "."
changed_content = bytes([git_records[-1].content[0] ^ 1]) + git_records[-1].content[1:]
changed_record = dataclasses.replace(
    git_records[-1], content=changed_content, content_sha256=hashlib.sha256(changed_content).hexdigest()
)
changed_records = (*git_records[:-1], changed_record)
assert fixture._tree_digest(changed_records) != first.git.source.logical_digest
assert fixture._ustar(changed_records) != first.git.source.ustar
changed_path = dataclasses.replace(git_records[-1], path="files/file-0512.txt")
assert fixture._tree_digest((*git_records[:-1], changed_path)) != first.git.source.logical_digest
changed_archive = first.git.source.ustar[:-1025] + bytes([first.git.source.ustar[-1025] ^ 1]) + first.git.source.ustar[-1024:]
assert hashlib.sha256(changed_archive).hexdigest() != first.git.source.ustar_sha256
assert oid("commit", expected_commit[:-1] + b"!\n") != first.git.commit_oid
assert first.git.porcelain.replace(b" M", b"M ", 1) != first.git.porcelain
for field, value in (("mode", 0o600), ("uid", 1), ("mtime", 1782172801)):
    hostile = (*git_records[:-1], dataclasses.replace(git_records[-1], **{field: value}))
    try:
        fixture._tree_digest(hostile)
    except fixture.FixtureError:
        pass
    else:
        raise AssertionError(f"accepted changed {field}")
changed_control = package.control[:-1] + b"!\n"
control_record = next(record for record in package.source.records if record.path == "DEBIAN/control")
replacement = dataclasses.replace(
    control_record, content=changed_control, size=len(changed_control), content_sha256=hashlib.sha256(changed_control).hexdigest()
)
changed_source = tuple(replacement if record.path == replacement.path else record for record in package.source.records)
assert fixture._tree_digest(changed_source) != package.source.logical_digest

# The production boundary has one zero-argument build and no execution/acquisition seam.
assert tuple(inspect.signature(fixture.fixed_fixtures).parameters) == ()
source = MODULE_PATH.read_text()
for forbidden in (
    "subprocess", "socket", "urllib", "requests", "boto", "AWS", "cloud", "argparse", "sys.argv",
    "tarfile", "extractall", "chroot", "namespace", "dpkg-deb", ".deb", "PRIVATE KEY", "if __name__",
):
    assert forbidden not in source
assert "callback" not in source and "file_count:" not in source and "lines_per_file:" not in source

print("completion fixture model tests passed")

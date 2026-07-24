#!/usr/bin/env python3
"""Hostile portable and exact-plan tests for the fixed ELF runtime closure."""

import dataclasses
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


plan = load("completion_rootfs_plan", REMOTE / "completion_rootfs_plan.py")
closure = load("completion_runtime_closure_test", REMOTE / "completion_runtime_closure.py")


def elf(names=("libalpha.so.1",), interp=True, soname=None, extra_tags=(), extra_phdrs=(), tail=b""):
    """Construct the bounded profile without using a host ELF tool."""
    size = 1024
    raw = bytearray(size)
    base = 0x400000
    interp_raw = b"/lib64/ld-linux-x86-64.so.2\0"
    interp_offset = 0x180
    dynamic_offset = 0x200
    strings_offset = 0x380
    strings = bytearray(b"\0")
    name_offsets = []
    for name in names:
        name_offsets.append(len(strings))
        strings.extend(name if type(name) is bytes else name.encode("ascii"))
        strings.append(0)
    soname_offset = len(strings)
    if soname is not None:
        strings.extend(soname if type(soname) is bytes else soname.encode("ascii"))
        strings.append(0)
    raw[strings_offset : strings_offset + len(strings)] = strings
    tags = [(1, offset) for offset in name_offsets]
    if soname is not None:
        tags.append((14, soname_offset))
    tags.extend(((5, base + strings_offset), (10, len(strings))))
    tags.extend(extra_tags)
    tags.append((0, 0))
    dynamic = b"".join(struct.pack("<QQ", *item) for item in tags)
    raw[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
    if interp:
        raw[interp_offset : interp_offset + len(interp_raw)] = interp_raw
    phdrs = [(1, 5, 0, base, 0, size, size, 0x1000)]
    if interp:
        phdrs.append((3, 4, interp_offset, base + interp_offset, 0, len(interp_raw), len(interp_raw), 1))
    phdrs.append((2, 6, dynamic_offset, base + dynamic_offset, 0, len(dynamic), len(dynamic), 8))
    phdrs.extend(extra_phdrs)
    ident = b"\x7fELF\x02\x01\x01\0" + b"\0" * 8
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 3, 62, 1, 0, 64, 0, 0, 64, 56, len(phdrs), 0, 0, 0)
    raw[:64] = header
    for index, phdr in enumerate(phdrs):
        struct.pack_into("<IIQQQQQQ", raw, 64 + index * 56, *phdr)
    return bytes(raw) + tail


def rejected(raw):
    try:
        closure._elf(raw)
    except closure.RuntimeClosureError:
        return
    raise AssertionError("hostile ELF accepted")


valid = elf()
assert closure._elf(valid) == ("/lib64/ld-linux-x86-64.so.2", None, ("libalpha.so.1",))
assert closure._elf(elf(interp=False, soname="libself.so")) == (None, "libself.so", ("libalpha.so.1",))
assert closure._elf(elf(("libz.so.1", "libc.so.6")))[2] == ("libz.so.1", "libc.so.6")
assert closure._elf(elf(("libfixed_name++.so.1-2",)))[2] == ("libfixed_name++.so.1-2",)
closure._require_root_interpreter("library", {"executable"}, None)
try:
    closure._require_root_interpreter("executable", {"executable"}, None)
except closure.RuntimeClosureError:
    pass
else:
    raise AssertionError("executable root without PT_INTERP accepted")

# Header identity, complete table bounds, profile, and truncation/overflow.
for offset, value in (
    (0, 0), (4, 1), (5, 2), (6, 0), (7, 4), (8, 1),
    (16, 1), (18, 3), (20, 2), (48, 1), (52, 63), (54, 55), (56, 0),
):
    hostile = bytearray(valid)
    hostile[offset] = value
    rejected(bytes(hostile))
for length in (0, 1, 63, 64, 120, 500, 1023):
    rejected(valid[:length])
for offset, value, form in ((32, 2**64 - 32, "Q"), (58, 4097, "H"), (40, 2**64 - 32, "Q")):
    hostile = bytearray(valid)
    struct.pack_into("<" + form, hostile, offset, value)
    rejected(bytes(hostile))
# A declared section table must itself be exact and bounded.
hostile = bytearray(valid)
struct.pack_into("<Q", hostile, 40, 1000)
struct.pack_into("<HHH", hostile, 58, 64, 1, 0)
rejected(bytes(hostile))
hostile = bytearray(valid)
struct.pack_into("<Q", hostile, 40, 64)
struct.pack_into("<HHH", hostile, 58, 64, 1, 0)
rejected(bytes(hostile))
hostile = bytearray(valid)
struct.pack_into("<HHH", hostile, 58, 64, 1, 0)
rejected(bytes(hostile))

# Program segments reject truncation, overflow, overlap, bad alignment and mappings.
def phmut(index, field_offset, value):
    hostile = bytearray(valid)
    struct.pack_into("<Q", hostile, 64 + index * 56 + field_offset, value)
    return bytes(hostile)


for candidate in (
    phmut(0, 32, 2048),             # LOAD filesz
    phmut(0, 40, 512),              # filesz > memsz
    phmut(0, 48, 3),                # non-power alignment
    phmut(1, 16, 0x500180),         # INTERP not mapped
    phmut(2, 16, 0x500200),         # DYNAMIC not mapped
    phmut(2, 32, 17),               # partial dynamic entry
):
    rejected(candidate)
base = 0x400000
rejected(elf(extra_phdrs=((1, 4, 0x100, base + 0x100, 0, 0x100, 0x100, 1),)))
rejected(elf(extra_phdrs=((2, 6, 0x200, base + 0x200, 0, 64, 64, 8),)))
rejected(elf(extra_phdrs=((3, 4, 0x180, base + 0x180, 0, 32, 32, 1),)))

# Interpreter, dynamic tags, exact termination, string tables, and names.
hostile = bytearray(valid)
hostile[0x180] = ord("x")
rejected(bytes(hostile))
hostile = bytearray(valid)
hostile[0x180 + len(b"/lib64/ld-linux-x86-64.so.2")] = ord("x")
rejected(bytes(hostile))
for tag in (15, 29, 0x6FFFFEFA, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF):
    rejected(elf(extra_tags=((tag, 1),)))
assert closure._elf(elf(extra_tags=((0x6FFFFFFB, 0x08000001),)))[2] == ("libalpha.so.1",)
rejected(elf(extra_tags=((0x6FFFFFFB, 0x800),)))
rejected(elf(extra_tags=((0x6FFFFFFB, 1), (0x6FFFFFFB, 1))))
rejected(elf(extra_tags=((0x6FFFFFFB, 0x80000000),)))
rejected(elf((b"bad/name.so",)))
rejected(elf((b"bad\\name.so",)))
rejected(elf((b"bad\x1fname.so",)))
for token_name in (b"lib$ORIGIN.so", b"$LIB", b"$PLATFORM"):
    rejected(elf((token_name,)))
    rejected(elf(soname=token_name))
rejected(elf((b"libsame.so", b"libsame.so")))
rejected(elf((b"",)))
for bad_soname in (b"bad/name.so", b"bad\\name.so", b"bad\x1fname.so", b""):
    rejected(elf(soname=bad_soname))
rejected(elf(soname="libself.so", extra_tags=((14, 1),)))
hostile = bytearray(elf(soname="libunterminated.so"))
end = hostile.index(b"libunterminated.so\0") + len(b"libunterminated.so")
hostile[end] = ord("x")
rejected(bytes(hostile))
hostile = bytearray(valid)
# DT_STRTAB address, DT_STRSZ, and DT_NULL are the final three entries here.
struct.pack_into("<Q", hostile, 0x200 + 16 + 8, 0xFFFFFFFFFFFFFFF0)
rejected(bytes(hostile))
hostile = bytearray(valid)
struct.pack_into("<Q", hostile, 0x200 + 32 + 8, 2**32)
rejected(bytes(hostile))
hostile = bytearray(valid)
struct.pack_into("<Q", hostile, 0x200 + 48, 1)
rejected(bytes(hostile))
hostile = bytearray(valid)
struct.pack_into("<Q", hostile, 0x200 + 48 + 8, 123)
rejected(bytes(hostile))

# Immutable graph resolution follows only authorized symlink/hardlink records.
def entry(path, kind="file", content=b"ELF", target=None, source="oci-layer"):
    digest = hashlib.sha256(content).hexdigest() if kind == "file" else None
    record = SimpleNamespace(
        path=path, kind=kind, resolved_link_path=target if kind == "symlink" else None,
        hardlink_target=target if kind == "hardlink" else None, archive_size=len(content) if kind == "file" else 0,
        content_sha256=digest, mode=0o755,
    )
    return SimpleNamespace(record=record, source=source, content=lambda: memoryview(content))


graph = {
    "lib": entry("lib", "symlink", b"", "usr/lib"),
    "usr/lib": entry("usr/lib", "directory", b""),
    "usr/lib/x86_64-linux-gnu/libok.so": entry("usr/lib/x86_64-linux-gnu/libok.so"),
    "copy": entry("copy", "hardlink", b"", "usr/lib/x86_64-linux-gnu/libok.so"),
}
assert closure._regular(graph, "lib/x86_64-linux-gnu/libok.so")[0] == "usr/lib/x86_64-linux-gnu/libok.so"
assert closure._regular(graph, "copy")[0] == "usr/lib/x86_64-linux-gnu/libok.so"
for hostile_graph, requested in (
    ({"a": entry("a", "symlink", b"", "b"), "b": entry("b", "symlink", b"", "a")}, "a"),
    ({"a": entry("a", "symlink", b"", "../escape"), "../escape": entry("../escape")}, "a"),
    ({"a": entry("a", "directory", b"")}, "a"),
    ({"a": entry("a", "hardlink", b"", "missing")}, "a"),
):
    try:
        closure._regular(hostile_graph, requested)
    except closure.RuntimeClosureError:
        pass
    else:
        raise AssertionError("hostile graph accepted")
wrong = entry("wrong", content=b"actual")
wrong.record.content_sha256 = "0" * 64
try:
    closure._regular({"wrong": wrong}, "wrong")
except closure.RuntimeClosureError:
    pass
else:
    raise AssertionError("wrong content accepted")
library_raw = elf((), interp=False, soname="libdup.so")
ambiguous = {
    "lib/x86_64-linux-gnu/libdup.so": entry("lib/x86_64-linux-gnu/libdup.so", content=library_raw),
    "usr/lib/x86_64-linux-gnu/libdup.so": entry(
        "usr/lib/x86_64-linux-gnu/libdup.so", content=library_raw + b"other"
    ),
}
try:
    closure._library(ambiguous, "libdup.so")
except closure.RuntimeClosureError:
    pass
else:
    raise AssertionError("ambiguous library accepted")
for candidate_soname in (None, "libother.so"):
    mismatch = {
        "lib/x86_64-linux-gnu/libdup.so": entry(
            "lib/x86_64-linux-gnu/libdup.so",
            content=elf((), interp=False, soname=candidate_soname),
        )
    }
    try:
        closure._library(mismatch, "libdup.so")
    except closure.RuntimeClosureError:
        pass
    else:
        raise AssertionError("missing or mismatched SONAME accepted")
identities = {}
closure._claim_soname(identities, "one", "libidentity.so")
closure._claim_soname(identities, "one", "libidentity.so")
try:
    closure._claim_soname(identities, "two", "libidentity.so")
except closure.RuntimeClosureError:
    pass
else:
    raise AssertionError("duplicate closure SONAME accepted")
# A malformed candidate is not silently ignored in favor of another directory.
malformed = dict(ambiguous)
malformed["lib/x86_64-linux-gnu/libdup.so"] = entry("bad", "directory", b"")
try:
    closure._library(malformed, "libdup.so")
except closure.RuntimeClosureError:
    pass
else:
    raise AssertionError("nonregular candidate accepted")

def real_exact_cache_test():
    """Load all 16 fixed artifacts; absence or drift is an explicit failure."""
    authority = plan.load_verified_build_inputs()
    first = closure.fixed_runtime_closure(authority)
    assert first.object_count == len(first.records) == 35
    expected_hash = "4c11dee4e0cba15c7a4bf7ef76937796abbdebf7a93b395ef47b14659a50b850"
    assert first.manifest_sha256 == expected_hash
    assert first.source_names == ("oci-layer",) + plan.PACKAGE_ORDER
    assert set(record.source for record in first.records) == set(first.source_names)
    paths = tuple(record.path for record in first.records)
    assert paths == tuple(sorted(paths, key=str.encode))
    assert len(set(paths)) == 35
    assert "usr/lib/x86_64-linux-gnu/libnss_files.so.2" in paths
    assert "usr/lib/x86_64-linux-gnu/libtinfo.so.6.5" in paths
    assert all(record.version == closure.RECORD_VERSION for record in first.records)
    assert all(len(record.needed) == len(record.resolved) == len(set(record.needed)) for record in first.records)
    sonames = tuple(record.soname for record in first.records if record.soname is not None)
    assert len(sonames) == len(set(sonames))
    by_path = {record.path: record for record in first.records}
    for root_path in closure._ROOTS[:-1]:
        canonical = closure._regular(closure._entries(authority), root_path)[0]
        assert by_path[canonical].interpreter == "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
    for record in first.records:
        assert all(by_path[path].soname == name for name, path in zip(record.needed, record.resolved))
    stream = b"".join(
        json.dumps(
            dataclasses.asdict(record), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        + b"\n"
        for record in first.records
    )
    assert hashlib.sha256(stream).hexdigest() == first.manifest_sha256

    # Enumeration order is irrelevant; source and content identity are not.
    original_revalidate = closure.revalidate_build_inputs
    try:
        closure.revalidate_build_inputs = lambda foreign: dataclasses.replace(foreign)
        reversed_authority = dataclasses.replace(
            authority,
            plan=dataclasses.replace(authority.plan, entries=tuple(reversed(authority.plan.entries))),
        )
        assert closure.fixed_runtime_closure(reversed_authority) == first
        entries = list(authority.plan.entries)
        index = next(
            i for i, item in enumerate(entries) if item.source == "libwrap0" and item.record.kind == "file"
        )
        entries[index] = dataclasses.replace(entries[index], source="oci-layer")
        changed_plan = dataclasses.replace(authority.plan, entries=tuple(entries))
        changed_authority = dataclasses.replace(authority, plan=changed_plan)
        try:
            closure.fixed_runtime_closure(changed_authority)
        except closure.RuntimeClosureError:
            pass
        else:
            raise AssertionError("changed source accepted")
    finally:
        closure.revalidate_build_inputs = original_revalidate
    changed_hash = stream.replace(first.records[0].content_sha256.encode(), b"0" * 64, 1)
    assert hashlib.sha256(changed_hash).hexdigest() != first.manifest_sha256
    return first


def main(argv):
    if not argv:
        print("completion runtime closure synthetic tests passed (functional-only; exact cache not checked)")
        return 0
    if argv != ["--real"]:
        print("usage: aws-stage2-completion-runtime-closure.py [--real]", file=sys.stderr)
        return 2
    try:
        result = real_exact_cache_test()
    except Exception:
        print("completion runtime closure real exact-cache test failed", file=sys.stderr)
        raise
    print(
        "completion runtime closure real exact-cache passed: "
        f"objects={result.object_count} manifest_sha256={result.manifest_sha256} "
        f"sources={len(result.source_names)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""Pure fixed ELF runtime closure over the immutable Stage 2 rootfs plan."""

from dataclasses import asdict, dataclass
import hashlib
import json
import struct

from completion_rootfs_plan import (
    PACKAGE_ORDER,
    PlannedEntry,
    RootfsBuildInputs,
    revalidate_build_inputs,
)

RECORD_VERSION = "cogs.stage2-completion-runtime-object/v1"
_ROOTS = (
    "usr/bin/git",
    "usr/sbin/sshd",
    "usr/lib/openssh/sshd-auth",
    "usr/lib/openssh/sshd-session",
    "usr/bin/dpkg",
    "usr/bin/dpkg-deb",
    "usr/lib/git-core/git",
    "usr/bin/bash",
    "usr/lib/x86_64-linux-gnu/libnss_files.so.2",
)
_SEARCH = ("lib/x86_64-linux-gnu", "usr/lib/x86_64-linux-gnu", "lib64", "usr/lib64")
_INTERP = "/lib64/ld-linux-x86-64.so.2"

# DT_RPATH, DT_RUNPATH, DT_CONFIG, DT_DEPAUDIT, DT_AUDIT, DT_AUXILIARY, and DT_FILTER.
_FORBIDDEN_DYNAMIC_TAGS = {15, 29, 0x6FFFFEFA, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF}
_DT_FLAGS_1 = 0x6FFFFFFB
_DF_1_NODEFLIB = 0x800
_DF_1_KNOWN = 0x7FFFFFFF
_LIBRARY_NAME_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-"
_U64 = (1 << 64) - 1

class RuntimeClosureError(Exception):
    pass

class _Missing(RuntimeClosureError):
    pass

def _fail(condition):
    if not condition:
        raise RuntimeClosureError()

@dataclass(frozen=True)
class ClosureRecord:
    version: str
    path: str
    source: str
    mode: int
    size: int
    content_sha256: str
    interpreter: str | None
    soname: str | None
    needed: tuple[str, ...]
    resolved: tuple[str, ...]

@dataclass(frozen=True)
class ClosureResult:
    records: tuple[ClosureRecord, ...]
    manifest_sha256: str
    object_count: int
    source_names: tuple[str, ...]

def _span(start, size, maximum):
    _fail(type(start) is int and type(size) is int)
    _fail(0 <= start <= _U64 and 0 <= size <= _U64)
    _fail(start <= _U64 - size and start + size <= maximum)
    return start, start + size

def _elf(raw):
    _fail(type(raw) in {bytes, memoryview} and 64 <= len(raw) <= (1 << 31))
    raw = memoryview(raw)
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    ident, kind, machine, version = header[:4]
    phoff, shoff = header[5:7]
    flags = header[7]
    ehsize, phsize, phnum, shsize, shnum, shindex = header[8:]
    _fail(ident[:7] == b"\x7fELF\x02\x01\x01" and ident[7] in {0, 3})
    _fail(ident[8:] == b"\0" * 8 and kind in {2, 3} and machine == 62 and version == 1)
    _fail(flags == 0 and ehsize == 64 and phsize == 56 and 0 < phnum <= 256)
    no_sections = shnum == shoff == shsize == shindex == 0
    _fail(no_sections or (shsize == 64 and 0 < shnum <= 4096 and shindex < shnum))
    section_span = _span(shoff, shnum * shsize, len(raw)) if shnum else None
    start, end = _span(phoff, phnum * phsize, len(raw))
    _fail(start >= ehsize and (section_span is None or section_span[0] >= ehsize))
    _fail(section_span is None or section_span[1] <= start or end <= section_span[0])
    loads = []
    dynamic = []
    interpreters = []
    for offset in range(start, end, phsize):
        fields = struct.unpack_from("<IIQQQQQQ", raw, offset)
        ptype, _flags, file_offset, address, _physical, filesz, memsz, align = fields
        _span(file_offset, filesz, len(raw))
        _fail(filesz <= memsz and (align == 0 or align & (align - 1) == 0))
        _fail(align in {0, 1} or file_offset % align == address % align)
        _fail(address <= _U64 - memsz)
        segment = (address, address + memsz, file_offset, filesz)
        if ptype == 1:
            _fail(memsz and filesz)
            loads.append(segment)
        elif ptype == 2:
            dynamic.append(segment)
        elif ptype == 3:
            interpreters.append(segment)
    _fail(loads and len(dynamic) == 1 and len(interpreters) <= 1)
    for index, left in enumerate(loads):
        for right in loads[index + 1 :]:
            _fail(left[1] <= right[0] or right[1] <= left[0])
            _fail(left[2] + left[3] <= right[2] or right[2] + right[3] <= left[2])

    def mapped(address, size):
        _span(address, size, _U64)
        offsets = []
        for virtual, _end, file_offset, filesz in loads:
            if virtual <= address and address + size <= virtual + filesz:
                offsets.append(file_offset + address - virtual)
        _fail(len(offsets) == 1)
        return offsets[0]

    interpreter = None
    if interpreters:
        address, _end, offset, size = interpreters[0]
        _fail(1 < size <= 256 and mapped(address, size) == offset)
        value = bytes(raw[offset : offset + size])
        _fail(value.endswith(b"\0") and b"\0" not in value[:-1])
        _fail(all(32 <= byte <= 126 for byte in value[:-1]))
        interpreter = value[:-1].decode("ascii")
        _fail(interpreter == _INTERP)
    address, _end, offset, size = dynamic[0]
    _fail(16 <= size <= 65536 and size % 16 == 0 and mapped(address, size) == offset)
    tags = []
    terminated = False
    for cursor in range(offset, offset + size, 16):
        tag, value = struct.unpack_from("<QQ", raw, cursor)
        if terminated:
            _fail((tag, value) == (0, 0))
        elif tag == 0:
            _fail(value == 0)
            terminated = True
        else:
            _fail(tag not in _FORBIDDEN_DYNAMIC_TAGS)
            tags.append((tag, value))
    _fail(terminated)
    flags_1 = [value for tag, value in tags if tag == _DT_FLAGS_1]
    _fail(len(flags_1) <= 1)
    _fail(not flags_1 or flags_1[0] & ~_DF_1_KNOWN == 0 and not flags_1[0] & _DF_1_NODEFLIB)
    string_tables = [value for tag, value in tags if tag == 5]
    string_sizes = [value for tag, value in tags if tag == 10]
    _fail(len(string_tables) == len(string_sizes) == 1 and 0 < string_sizes[0] <= len(raw))
    string_offset = mapped(string_tables[0], string_sizes[0])
    strings = bytes(raw[string_offset : string_offset + string_sizes[0]])

    def name_at(name_offset):
        _fail(name_offset < len(strings))
        name_end = strings.find(b"\0", name_offset)
        _fail(name_offset < name_end < len(strings) and name_end - name_offset <= 255)
        name_raw = strings[name_offset:name_end]
        _fail(all(byte in _LIBRARY_NAME_BYTES for byte in name_raw))
        return name_raw.decode("ascii")

    needed = [name_at(value) for tag, value in tags if tag == 1]
    _fail(len(needed) == len(set(needed)))
    sonames = [name_at(value) for tag, value in tags if tag == 14]
    _fail(len(sonames) <= 1)
    return interpreter, sonames[0] if sonames else None, tuple(needed)

def _entries(authority):
    _fail(type(authority) is RootfsBuildInputs)
    entries = {}
    for entry in authority.plan.entries:
        _fail(type(entry) is PlannedEntry and entry.record.path not in entries)
        entries[entry.record.path] = entry
    return entries

def _regular(entries, requested):
    _fail(type(requested) is str and requested and not requested.startswith("/"))
    current = requested
    seen = set()
    for _unused in range(65):
        _fail(current not in seen)
        seen.add(current)
        parts = current.split("/")
        _fail(all(part not in {"", ".", ".."} for part in parts))
        for index in range(1, len(parts) + 1):
            entry = entries.get("/".join(parts[:index]))
            if entry is not None and entry.record.kind == "symlink":
                target = entry.record.resolved_link_path
                _fail(type(target) is str and target in entries)
                current = "/".join((target, *parts[index:]))
                break
        else:
            entry = entries.get(current)
            if entry is None:
                raise _Missing()
            if entry.record.kind == "hardlink":
                _fail(type(entry.record.hardlink_target) is str)
                current = entry.record.hardlink_target
                continue
            _fail(entry.record.kind == "file" and entry.record.content_sha256 is not None)
            raw = entry.content()
            digest = hashlib.sha256(raw).hexdigest()
            _fail(len(raw) == entry.record.archive_size and digest == entry.record.content_sha256)
            return current, entry, raw
    raise RuntimeClosureError()

def _require_root_interpreter(path, executable_roots, declared_interpreter):
    _fail(path not in executable_roots or declared_interpreter == _INTERP)

def _claim_soname(identities, path, soname):
    if soname is not None:
        _fail(soname not in identities or identities[soname] == path)
        identities[soname] = path

def _library(entries, name):
    candidates = []
    for directory in _SEARCH:
        try:
            candidate = _regular(entries, f"{directory}/{name}")
        except _Missing:
            continue
        _fail(_elf(candidate[2])[1] == name)
        if candidate[0] not in {item[0] for item in candidates}:
            candidates.append(candidate)
    _fail(len(candidates) == 1)
    return candidates[0]

def fixed_runtime_closure(authority: RootfsBuildInputs) -> ClosureResult:
    fresh = revalidate_build_inputs(authority)
    _fail(type(fresh) is RootfsBuildInputs and fresh is not authority)
    entries = _entries(fresh)
    root_paths = tuple(_regular(entries, path)[0] for path in _ROOTS)
    executable_roots = set(root_paths[:-1])
    _fail(len(executable_roots) == 8 and root_paths[-1] not in executable_roots)
    pending = list(root_paths)
    parsed = {}
    soname_paths = {}
    while pending:
        path = pending.pop(0)
        if path in parsed:
            continue
        resolved_path, entry, raw = _regular(entries, path)
        declared_interpreter, soname, needed = _elf(raw)
        _require_root_interpreter(resolved_path, executable_roots, declared_interpreter)
        _claim_soname(soname_paths, resolved_path, soname)
        interpreter = None
        if declared_interpreter is not None:
            interpreter = _regular(entries, _INTERP[1:])[0]
        dependencies = tuple(_library(entries, name)[0] for name in needed)
        parsed[resolved_path] = (entry, interpreter, soname, needed, dependencies)
        pending.extend(dependencies)
        if interpreter is not None:
            pending.append(interpreter)
    records = []
    for path in sorted(parsed, key=lambda value: value.encode("utf-8")):
        entry, interpreter, soname, needed, dependencies = parsed[path]
        record = entry.record
        records.append(
            ClosureRecord(
                RECORD_VERSION, path, entry.source, record.mode, record.archive_size,
                record.content_sha256, interpreter, soname, needed, dependencies,
            )
        )
    result_records = tuple(records)
    expected_sources = ("oci-layer",) + PACKAGE_ORDER
    _fail(len(result_records) == 35)
    _fail({item.source for item in result_records} == set(expected_sources))
    stream = b"".join(
        json.dumps(asdict(item), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        + b"\n"
        for item in result_records
    )
    return ClosureResult(result_records, hashlib.sha256(stream).hexdigest(), 35, expected_sources)

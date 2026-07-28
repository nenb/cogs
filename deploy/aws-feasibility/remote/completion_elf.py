"""Pure, bounded parser for the fixed Linux x86-64 ELF profile."""
from __future__ import annotations
from dataclasses import dataclass
import struct

__all__ = ("ElfMetadata", "ElfParseError", "parse_elf64")

_MAX_FILE_SIZE = 128 * 1024 * 1024
_MAX_PROGRAM_HEADERS = 256
_MAX_SECTION_HEADERS = 4096
_MAX_DYNAMIC_SIZE = 64 * 1024
_MAX_INTERPRETER_SIZE = 256
_MAX_NAME_SIZE = 255
_MAX_NEEDED = 128
_PAGE_SIZE = 4096
_PAGE_MASK = _PAGE_SIZE - 1
_U64_MAX = (1 << 64) - 1

_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_INTERP = 3
_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_STRSZ = 10
_DT_SONAME = 14
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6FFFFFFB
_DF_KNOWN = 0x1F
_DF_1_KNOWN = 0x7FFFFFFF
_DF_1_NODEFLIB = 0x800
_INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
_NAME_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-"

# Search paths, runtime-loaded audit objects, and dependency substitution are forbidden.
_FORBIDDEN_DYNAMIC_TAGS = frozenset(
    {15, 29, 0x6FFFFEFA, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF}
)
# The parser understands standard SysV/GNU metadata used by the fixed amd64 tools.
# Tags in this set that are not consumed below are deliberately ignored as relocation,
# hash, versioning, initialization, or architecture metadata.
_SUPPORTED_DYNAMIC_TAGS = frozenset(
    set(range(1, 15))
    | set(range(16, 29))
    | {30, 32, 33, 34, 35, 36, 37}
    | {0x6FFFFEF5, 0x6FFFFFF0}
    | set(range(0x6FFFFFF9, 0x70000000))
    | {0x70000000, 0x70000001, 0x70000003}
)


class ElfParseError(Exception):
    """The input is not in the accepted fixed ELF64 profile."""


@dataclass(frozen=True)
class ElfMetadata:
    """Immutable dependency metadata authenticated by the caller's byte source."""

    interpreter: str | None
    soname: str | None
    needed: tuple[str, ...]


@dataclass(frozen=True)
class _Load:
    """One ordered Linux load mapping, including its rounded page extents."""

    virtual_start: int
    virtual_end: int
    file_start: int
    file_end: int
    virtual_page_start: int
    memory_page_end: int
    file_page_start: int
    file_page_end: int
    bss_start: int | None

    @property
    def delta(self) -> int:
        return self.file_page_start - self.virtual_page_start

    @property
    def virtual_file_page_end(self) -> int:
        return self.virtual_page_start + self.file_page_end - self.file_page_start

    @property
    def file_identity_end(self) -> int:
        if self.bss_start is not None:
            return self.bss_start
        return self.virtual_file_page_end


def _require(condition: bool) -> None:
    if not condition:
        raise ElfParseError()


def _span(start: int, size: int, limit: int) -> tuple[int, int]:
    _require(0 <= start <= _U64_MAX)
    _require(0 <= size <= _U64_MAX)
    _require(start <= _U64_MAX - size)
    end = start + size
    _require(end <= limit)
    return start, end


def _page_start(value: int) -> int:
    return value & ~_PAGE_MASK


def _page_end(value: int) -> int:
    rounded = (value + _PAGE_MASK) & ~_PAGE_MASK
    _require(rounded <= _U64_MAX)
    return rounded


def _parse_elf64(data: bytes) -> ElfMetadata:
    _require(type(data) is bytes)
    _require(64 <= len(data) <= _MAX_FILE_SIZE)

    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    ident, elf_type, machine, version = header[:4]
    program_offset, section_offset = header[5:7]
    flags = header[7]
    header_size, program_size, program_count = header[8:11]
    section_size, section_count, section_names = header[11:]

    _require(ident[:7] == b"\x7fELF\x02\x01\x01")
    _require(ident[7] in {0, 3} and ident[8:] == b"\0" * 8)
    _require(elf_type in {2, 3} and machine == 62 and version == 1)
    _require(flags == 0 and header_size == 64 and program_size == 56)
    _require(0 < program_count <= _MAX_PROGRAM_HEADERS)
    _require(program_offset % 8 == 0)

    no_sections = section_offset == section_size == section_count == section_names == 0
    valid_sections = (
        section_offset % 8 == 0
        and section_size == 64
        and 0 < section_count <= _MAX_SECTION_HEADERS
        and section_names < section_count
    )
    _require(no_sections or valid_sections)

    program_start, program_end = _span(
        program_offset, program_count * program_size, len(data)
    )
    _require(program_start >= header_size)
    section_span = None
    if section_count:
        section_span = _span(section_offset, section_count * section_size, len(data))
        _require(section_span[0] >= header_size)
        _require(section_span[1] <= program_start or program_end <= section_span[0])

    loads = []
    dynamic_segments = []
    interpreter_segments = []
    for offset in range(program_start, program_end, program_size):
        fields = struct.unpack_from("<IIQQQQQQ", data, offset)
        kind, segment_flags, file_offset, address = fields[:4]
        file_size, memory_size, alignment = fields[5:]
        _, file_end = _span(file_offset, file_size, len(data))
        _require(segment_flags & ~7 == 0)
        _require(file_size <= memory_size)
        _require(alignment == 0 or alignment & (alignment - 1) == 0)
        _require(alignment in {0, 1} or file_offset % alignment == address % alignment)
        _, memory_end = _span(address, memory_size, _U64_MAX)
        segment = (address, memory_end, file_offset, file_end)
        if kind == _PT_LOAD:
            _require(file_size > 0 and memory_size > 0)
            _require(alignment >= _PAGE_SIZE)
            _require(file_offset % _PAGE_SIZE == address % _PAGE_SIZE)
            load = _Load(
                address,
                memory_end,
                file_offset,
                file_end,
                _page_start(address),
                _page_end(memory_end),
                _page_start(file_offset),
                _page_end(file_end),
                address + file_size if file_size < memory_size else None,
            )
            _require(load.virtual_file_page_end <= load.memory_page_end)
            if loads:
                _require(loads[-1].virtual_page_start < load.virtual_page_start)
                _require(loads[-1].file_page_start <= load.file_page_start)
            loads.append(load)
        elif kind == _PT_DYNAMIC:
            _require(file_size == memory_size)
            dynamic_segments.append(segment)
        elif kind == _PT_INTERP:
            _require(file_size == memory_size)
            interpreter_segments.append(segment)

    _require(loads and len(dynamic_segments) == 1)
    _require(len(interpreter_segments) <= 1)
    for index, left in enumerate(loads):
        for right in loads[index + 1 :]:
            virtual_start = max(left.virtual_page_start, right.virtual_page_start)
            virtual_end = min(left.memory_page_end, right.memory_page_end)
            if virtual_start < virtual_end:
                _require(left.delta == right.delta)
                _require(virtual_end <= left.file_identity_end)
                _require(virtual_end <= right.file_identity_end)
            file_start = max(left.file_page_start, right.file_page_start)
            file_end = min(left.file_page_end, right.file_page_end)
            if file_start < file_end:
                _require(left.delta == right.delta)

    def mapped(address: int, size: int) -> int:
        _, end = _span(address, size, _U64_MAX)
        offsets = set()
        for load in loads:
            declared_file_end = load.virtual_start + load.file_end - load.file_start
            if load.virtual_start <= address and end <= declared_file_end:
                offsets.add(load.file_start + address - load.virtual_start)
        _require(len(offsets) == 1)
        return offsets.pop()

    interpreter = None
    if interpreter_segments:
        address, _memory_end, offset, file_end = interpreter_segments[0]
        size = file_end - offset
        _require(1 < size <= _MAX_INTERPRETER_SIZE)
        _require(mapped(address, size) == offset)
        raw_interpreter = data[offset:file_end]
        _require(raw_interpreter.endswith(b"\0"))
        _require(b"\0" not in raw_interpreter[:-1])
        _require(all(32 <= byte <= 126 for byte in raw_interpreter[:-1]))
        interpreter = raw_interpreter[:-1].decode("ascii")
        _require(interpreter == _INTERPRETER)

    address, _memory_end, dynamic_offset, dynamic_end = dynamic_segments[0]
    dynamic_size = dynamic_end - dynamic_offset
    _require(16 <= dynamic_size <= _MAX_DYNAMIC_SIZE)
    _require(dynamic_size % 16 == 0)
    _require(mapped(address, dynamic_size) == dynamic_offset)

    tags = []
    terminated = False
    for offset in range(dynamic_offset, dynamic_end, 16):
        tag, value = struct.unpack_from("<QQ", data, offset)
        if terminated:
            _require((tag, value) == (_DT_NULL, 0))
        elif tag == _DT_NULL:
            _require(value == 0)
            terminated = True
        else:
            _require(tag not in _FORBIDDEN_DYNAMIC_TAGS)
            _require(tag in _SUPPORTED_DYNAMIC_TAGS)
            tags.append((tag, value))
    _require(terminated)

    values_by_tag = {}
    for tag, value in tags:
        values_by_tag.setdefault(tag, []).append(value)
    for tag, values in values_by_tag.items():
        if tag != _DT_NEEDED:
            _require(len(values) == 1)

    flags_values = values_by_tag.get(_DT_FLAGS, [])
    _require(not flags_values or flags_values[0] & ~_DF_KNOWN == 0)
    flags_1_values = values_by_tag.get(_DT_FLAGS_1, [])
    if flags_1_values:
        flags_1 = flags_1_values[0]
        _require(flags_1 & ~_DF_1_KNOWN == 0)
        _require(flags_1 & _DF_1_NODEFLIB == 0)

    string_tables = values_by_tag.get(_DT_STRTAB, [])
    string_sizes = values_by_tag.get(_DT_STRSZ, [])
    _require(len(string_tables) == len(string_sizes) == 1)
    string_size = string_sizes[0]
    _require(0 < string_size <= len(data))
    string_offset = mapped(string_tables[0], string_size)
    _, string_end = _span(string_offset, string_size, len(data))
    _require(data[string_offset] == 0)

    def name_at(relative_offset: int) -> str:
        _require(relative_offset < string_size)
        start = string_offset + relative_offset
        limit = min(start + _MAX_NAME_SIZE + 1, string_end)
        end = data.find(b"\0", start, limit)
        _require(start < end < string_end)
        raw_name = data[start:end]
        _require(all(byte in _NAME_BYTES for byte in raw_name))
        return raw_name.decode("ascii")

    needed_offsets = values_by_tag.get(_DT_NEEDED, [])
    _require(len(needed_offsets) <= _MAX_NEEDED)
    needed = tuple(name_at(offset) for offset in needed_offsets)
    _require(len(needed) == len(set(needed)))
    soname_offsets = values_by_tag.get(_DT_SONAME, [])
    soname = name_at(soname_offsets[0]) if soname_offsets else None
    return ElfMetadata(interpreter=interpreter, soname=soname, needed=needed)


def parse_elf64(data: bytes) -> ElfMetadata:
    """Parse bytes without path, descriptor, environment, or host discovery."""

    try:
        return _parse_elf64(data)
    except ElfParseError:
        raise
    except (OverflowError, struct.error, UnicodeDecodeError):
        raise ElfParseError() from None

"""Read-only structural preflight for fixed Stage 2 Debian package archives."""

from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import tarfile
import unicodedata


class ArchivePreflightError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise ArchivePreflightError()


@dataclass(frozen=True)
class ArchiveRecord:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    mtime: int
    size: int
    link_target: str | None


@dataclass(frozen=True)
class _RawMember:
    name: str
    linkname: str
    kind: str
    mode: int
    uid: int
    gid: int
    mtime: int
    size: int
    data_offset: int
    pax: tuple[tuple[str, str], ...]


def _identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_fixed_package(path, row):
    path = Path(path)
    before = os.lstat(path)
    _fail(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1)
    _fail(stat.S_IMODE(before.st_mode) == 0o400 and before.st_size == row["size"])
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    chunks = []
    digest = hashlib.sha256()
    total = 0
    try:
        _fail(_identity(os.fstat(descriptor)) == _identity(before))
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, row["size"] + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            _fail(total <= row["size"])
            chunks.append(chunk)
            digest.update(chunk)
    finally:
        os.close(descriptor)
    _fail(_identity(os.lstat(path)) == _identity(before))
    _fail(total == row["size"] and digest.hexdigest() == row["sha256"])
    return b"".join(chunks)


def _ar_number(field, base, maximum):
    _fail(type(field) is bytes and field)
    terminator = field.find(b" ")
    _fail(terminator > 0 and field[terminator:] == b" " * (len(field) - terminator))
    core = field[:terminator]
    allowed = b"01234567" if base == 8 else b"0123456789"
    _fail(all(byte in allowed for byte in core))
    value = int(core, base)
    _fail(value <= maximum)
    return value


def _tar_octal(field, maximum):
    _fail(type(field) is bytes and field)
    terminator = next((index for index, byte in enumerate(field) if byte in b"\0 "), -1)
    _fail(terminator > 0 and all(byte in b"\0 " for byte in field[terminator:]))
    core = field[:terminator]
    _fail(all(byte in b"01234567" for byte in core))
    value = int(core, 8)
    _fail(value <= maximum)
    return value


def _ar_members(raw):
    _fail(type(raw) is bytes and raw.startswith(b"!<arch>\n"))
    offset = 8
    members = []
    while offset < len(raw):
        _fail(len(members) < 4 and offset + 60 <= len(raw))
        header = raw[offset : offset + 60]
        _fail(header[58:60] == b"`\n")
        try:
            name_field = header[:16].decode("ascii")
        except UnicodeDecodeError as error:
            raise ArchivePreflightError() from error
        name = name_field.rstrip(" ")
        _fail(name and " " not in name and not name.startswith(("/", "#1/")))
        if name.endswith("/"):
            name = name[:-1]
        _fail(name and "/" not in name and name not in {".", ".."})
        _ar_number(header[16:28], 10, 2**63 - 1)
        _ar_number(header[28:34], 10, 2**31 - 1)
        _ar_number(header[34:40], 10, 2**31 - 1)
        _ar_number(header[40:48], 8, 0o177777)
        size = _ar_number(header[48:58], 10, len(raw))
        start = offset + 60
        end = start + size
        _fail(end <= len(raw))
        members.append((name, raw[start:end]))
        offset = end
        if size % 2:
            _fail(offset < len(raw) and raw[offset : offset + 1] == b"\n")
            offset += 1
    _fail(offset == len(raw) and len(members) == 3)
    _fail(members[0] == ("debian-binary", b"2.0\n"))
    _fail(re.fullmatch(r"control\.tar(?:\.gz|\.xz)?", members[1][0]) is not None)
    _fail(re.fullmatch(r"data\.tar(?:\.gz|\.xz)?", members[2][0]) is not None)
    return tuple(members)


def _decompress_tar(name, raw, maximum):
    import lzma
    import zlib

    _fail(type(raw) is bytes and type(maximum) is int and maximum >= 0)
    compressed_magic = (b"\x1f\x8b", b"\xfd7zXZ\0", b"\x28\xb5\x2f\xfd", b"BZh")
    if name.endswith(".tar"):
        _fail(not raw.startswith(compressed_magic) and len(raw) <= maximum)
        return raw
    if name.endswith(".tar.gz"):
        _fail(raw.startswith(compressed_magic[0]))
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decoder_error = zlib.error
    elif name.endswith(".tar.xz"):
        _fail(raw.startswith(compressed_magic[1]))
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        decoder_error = (lzma.LZMAError, EOFError)
    else:
        raise ArchivePreflightError()
    chunks = []
    total = 0
    try:
        for offset in range(0, len(raw), 1024 * 1024):
            _fail(not decoder.eof)
            pending = raw[offset : offset + 1024 * 1024]
            while pending or (hasattr(decoder, "needs_input") and not decoder.needs_input and not decoder.eof):
                output = decoder.decompress(pending, maximum + 1 - total)
                pending = b""
                total += len(output)
                _fail(total <= maximum and not decoder.unused_data)
                if hasattr(decoder, "unconsumed_tail"):
                    _fail(not decoder.unconsumed_tail)
                chunks.append(output)
        _fail(decoder.eof and not decoder.unused_data)
    except decoder_error as error:
        raise ArchivePreflightError() from error
    return b"".join(chunks)


def _text(raw):
    nul = raw.find(b"\0")
    if nul >= 0:
        _fail(not raw[nul:].strip(b"\0"))
        raw = raw[:nul]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArchivePreflightError() from error


def _safe_text(value, maximum):
    _fail(type(value) is str and value and unicodedata.normalize("NFC", value) == value)
    _fail("\\" not in value and len(value.encode("utf-8")) <= maximum)
    _fail(all(ord(character) >= 32 and not unicodedata.category(character).startswith("C") for character in value))


def _pseudo_name(header):
    value = _header_name(header)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ArchivePreflightError() from error
    _fail(value and len(encoded) <= 255 and not value.startswith("/") and "\\" not in value)
    parts = [part for part in value.split("/") if part not in {"", "."}]
    _fail(parts and ".." not in parts and all(len(part) <= 255 for part in parts))


def _pax_records(raw):
    _fail(0 < len(raw) <= 65536)
    offset = 0
    values = {}
    while offset < len(raw):
        space = raw.find(b" ", offset)
        _fail(space > offset)
        length_raw = raw[offset:space]
        _fail(length_raw.isdigit() and not length_raw.startswith(b"0"))
        end = offset + int(length_raw)
        _fail(end <= len(raw) and raw[end - 1 : end] == b"\n")
        record = raw[space + 1 : end - 1]
        _fail(b"=" in record)
        key_raw, value_raw = record.split(b"=", 1)
        try:
            key = key_raw.decode("ascii")
            value = value_raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ArchivePreflightError() from error
        _fail(key in {"path", "linkpath"} and key not in values and value)
        _fail(len(key_raw) <= 32 and len(value_raw) <= 4096)
        values[key] = value
        offset = end
    _fail(offset == len(raw))
    return values


def _gnu_text(raw):
    _fail(1 < len(raw) <= 65536 and raw.endswith(b"\0") and b"\0" not in raw[:-1])
    return _text(raw[:-1])


def _header_name(header):
    name = _text(header[:100])
    prefix = _text(header[345:500])
    return f"{prefix}/{name}" if prefix else name


def _raw_tar_frames(raw, bounds):
    _fail(type(raw) is bytes and raw and len(raw) % 512 == 0)
    zero = b"\0" * 512
    offset = 0
    physical = 0
    members = []
    pax = None
    long_name = None
    long_link = None
    extension_order = []
    while offset < len(raw) and raw[offset : offset + 512] != zero:
        physical += 1
        _fail(physical <= 2 * bounds["max_entries"] + 20 and offset + 512 <= len(raw))
        header = raw[offset : offset + 512]
        expected = _tar_octal(header[148:156], 512 * 255)
        _fail(sum(header[:148]) + 8 * 32 + sum(header[156:]) == expected)
        _fail((header[257:263], header[263:265]) in {(b"ustar\0", b"00"), (b"ustar ", b" \0")})
        mode = _tar_octal(header[100:108], 0o7777)
        uid = _tar_octal(header[108:116], 2**31 - 1)
        gid = _tar_octal(header[116:124], 2**31 - 1)
        size = _tar_octal(header[124:136], bounds["max_regular_bytes"])
        mtime = _tar_octal(header[136:148], 2**63 - 1)
        kind_byte = header[156:157]
        kind_byte = b"0" if kind_byte == b"\0" else kind_byte
        start = offset + 512
        end = start + size
        padded = start + ((size + 511) // 512) * 512
        _fail(end <= len(raw) and padded <= len(raw) and not raw[end:padded].strip(b"\0"))
        body = raw[start:end]
        offset = padded
        if kind_byte in {b"x", b"g", b"L", b"K"}:
            _pseudo_name(header)
            _fail(size <= 65536 and kind_byte != b"g")
            if kind_byte == b"x":
                _fail(pax is None and not extension_order)
                pax = _pax_records(body)
            elif kind_byte == b"L":
                _fail(pax is None and long_name is None and not extension_order)
                long_name = _gnu_text(body)
                extension_order.append("L")
            else:
                _fail(pax is None and long_link is None and extension_order in ([], ["L"]))
                long_link = _gnu_text(body)
                extension_order.append("K")
            continue
        kinds = {b"0": "file", b"1": "hardlink", b"2": "symlink", b"5": "directory"}
        _fail(kind_byte in kinds)
        name = (pax or {}).get("path", long_name if long_name is not None else _header_name(header))
        link = (pax or {}).get("linkpath", long_link if long_link is not None else _text(header[157:257]))
        _fail("linkpath" not in (pax or {}) or kind_byte in {b"1", b"2"})
        members.append(
            _RawMember(name, link, kinds[kind_byte], mode, uid, gid, mtime, size, start, tuple((pax or {}).items()))
        )
        _fail(len(members) <= bounds["max_entries"])
        pax = None
        long_name = None
        long_link = None
        extension_order = []
    _fail(pax is None and long_name is None and long_link is None and not extension_order)
    terminal = (len(raw) - offset) // 512
    _fail(2 <= terminal <= 20 and raw[offset:] == zero * terminal)
    return tuple(members)


def _normalize_path(value, kind, bounds):
    _safe_text(value, bounds["max_path_bytes"])
    if value == "./":
        _fail(kind == "directory")
        return None
    if value.startswith("./"):
        value = value[2:]
        _fail(not value.startswith("./"))
    _fail(not value.startswith("/") and value)
    if kind == "directory" and value.endswith("/"):
        value = value[:-1]
    parts = value.split("/")
    _fail(all(part not in {"", ".", ".."} for part in parts))
    _fail(all(len(part.encode("utf-8")) <= bounds["max_component_bytes"] for part in parts))
    _fail(all(not part.startswith(".wh.") for part in parts))
    return "/".join(parts)


def _normalize_symlink(path, target, bounds):
    _safe_text(target, bounds["max_path_bytes"])
    _fail(not target.startswith("/"))
    result = path.split("/")[:-1]
    for part in target.split("/"):
        _fail(part != "" and len(part.encode("utf-8")) <= bounds["max_component_bytes"])
        if part == ".":
            continue
        if part == "..":
            _fail(result)
            result.pop()
        else:
            result.append(part)
    _fail(result)
    normalized = "/".join(result)
    _safe_text(normalized, bounds["max_path_bytes"])
    return normalized


def _semantic_tar_records(raw, frames, bounds, control):
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", encoding="utf-8", errors="strict") as archive:
            _fail(not archive.pax_headers)
            infos = tuple(archive)
    except (tarfile.TarError, UnicodeError, ValueError) as error:
        raise ArchivePreflightError() from error
    _fail(len(infos) == len(frames))
    records = []
    seen = set()
    regular_total = 0
    control_bytes = None
    root_seen = False
    for frame, info in zip(frames, infos, strict=True):
        raw_path = _normalize_path(frame.name, frame.kind, bounds)
        if raw_path is None:
            _fail(info.name in {".", "./"})
            path = None
        else:
            path = _normalize_path(info.name, frame.kind, bounds)
            _fail(path == raw_path)
        _fail(info.linkname == frame.linkname and info.size == frame.size)
        _fail(info.mode == frame.mode and info.uid == frame.uid and info.gid == frame.gid and info.mtime == frame.mtime)
        _fail(tuple(info.pax_headers.items()) == frame.pax and not info.sparse)
        semantic_kind = "file" if info.isfile() else "directory" if info.isdir() else "symlink" if info.issym() else "hardlink" if info.islnk() else None
        _fail(semantic_kind == frame.kind)
        if path is None:
            _fail(not root_seen)
            root_seen = True
            continue
        _fail(path not in seen)
        seen.add(path)
        _fail(frame.kind == "file" or frame.size == 0)
        link_target = None
        if frame.kind == "symlink":
            link_target = _normalize_symlink(path, info.linkname, bounds)
        elif frame.kind == "hardlink":
            link_target = _normalize_path(info.linkname, "file", bounds)
            _fail(link_target is not None)
        if frame.kind == "file":
            _fail(frame.size <= bounds["max_file_bytes"])
            regular_total += frame.size
            _fail(regular_total <= bounds["max_regular_bytes"])
        if control:
            _fail(frame.kind in {"file", "directory"})
            if path == "control":
                _fail(frame.kind == "file" and control_bytes is None)
                control_bytes = raw[frame.data_offset : frame.data_offset + frame.size]
        records.append(ArchiveRecord(path, frame.kind, frame.mode, frame.uid, frame.gid, frame.mtime, frame.size, link_target))
    by_path = {record.path: record for record in records}
    for record in records:
        if record.kind == "hardlink":
            target = by_path.get(record.link_target)
            _fail(target is not None and target.kind == "file")
    _fail(not control or control_bytes is not None)
    return tuple(records), control_bytes


def _preflight_tar(raw, bounds, control=False):
    frames = _raw_tar_frames(raw, bounds)
    return _semantic_tar_records(raw, frames, bounds, control)


def _control_stanza(raw, expected):
    _fail(type(raw) is bytes and raw.endswith(b"\n") and b"\r" not in raw and len(raw) <= 1024 * 1024)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArchivePreflightError() from error
    _fail(all(character in "\n\t" or 32 <= ord(character) < 127 or ord(character) >= 160 for character in text))
    fields = {}
    last = None
    ended = False
    for line in text.splitlines():
        _fail(len(line.encode("utf-8")) <= 131072)
        if not line:
            ended = True
            continue
        _fail(not ended)
        if line[0] in " \t":
            _fail(last is not None)
            fields[last] += "\n" + line[1:]
            continue
        _fail(":" in line)
        name, value = line.split(":", 1)
        _fail(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", name) is not None and name not in fields)
        _fail(value.startswith(" "))
        fields[name] = value[1:]
        last = name
    _fail(
        fields.get("Package") == expected["name"]
        and fields.get("Version") == expected["version"]
        and fields.get("Architecture") == expected["architecture"]
    )


def preflight_deb_bytes(raw, expected, bounds):
    members = _ar_members(raw)
    control_raw = _decompress_tar(members[1][0], members[1][1], bounds["max_regular_bytes"])
    _, control = _preflight_tar(control_raw, bounds, control=True)
    _control_stanza(control, expected)
    data_raw = _decompress_tar(members[2][0], members[2][1], bounds["max_regular_bytes"])
    records, _ = _preflight_tar(data_raw, bounds)
    return records


def verify_package_archives(contract, cache):
    cache = Path(cache)
    _fail(cache.name == "cache")
    for row in contract["packages"]:
        raw = _read_fixed_package(cache / row["cache_name"], row)
        preflight_deb_bytes(raw, row, contract["bounds"])

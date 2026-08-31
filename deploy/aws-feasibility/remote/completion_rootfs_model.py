"""Shared immutable rootfs plan model, independent of producer inputs."""

from dataclasses import dataclass
import sys

sys.dont_write_bytecode = True

from completion_archive_preflight import ArchiveRoot, MaterialRecord, PreflightedTar

SOURCE_DATE_EPOCH = 1782172800
ROOT_POLICY = ArchiveRoot("directory", 0o755, 0, 0, SOURCE_DATE_EPOCH, 0)


class RootfsModelError(Exception):
    pass


def _require(condition):
    if not condition:
        raise RootfsModelError()


@dataclass(frozen=True)
class EntryIdentity:
    kind: str
    mode: int
    uid: int
    gid: int
    mtime: int
    archive_size: int
    link_text: str | None
    resolved_link_path: str | None
    hardlink_target: str | None
    content_sha256: str | None


@dataclass(frozen=True)
class PlannedEntry:
    source: str
    owner: PreflightedTar | None
    record: MaterialRecord
    generated_content: bytes | None = None

    def content(self):
        _require(self.record.kind == "file")
        if self.generated_content is not None:
            _require(len(self.generated_content) == self.record.archive_size)
            return memoryview(self.generated_content)
        _require(self.owner is not None)
        return self.owner.content(self.record)


@dataclass(frozen=True)
class Transition:
    path: str
    action: str
    expected: EntryIdentity | None
    result: PlannedEntry | None


@dataclass(frozen=True)
class RootfsPlan:
    root: ArchiveRoot
    source_order: tuple[str, ...]
    entries: tuple[PlannedEntry, ...]
    transitions: tuple[Transition, ...]

"""Pure descriptor-generation and fixed child-fd mapping primitives.

These values are bookkeeping, not Python capabilities.  Durable command intent
in ``completion_kata_operation`` is the authority for inheriting a descriptor.
"""
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import os
import stat

CLIENT_KEY = "CLIENT_KEY"
KNOWN_HOSTS = "KNOWN_HOSTS"
ROLE_TARGETS = {CLIENT_KEY: 200, KNOWN_HOSTS: 201}
MAX_INPUT = 65_536


class FdMapError(Exception):
    pass


@dataclass(frozen=True)
class FdIdentity:
    mount_id: int | None
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class InheritedBinding:
    role: str
    source_fd: int
    target_fd: int
    identity: FdIdentity
    content_sha256: str


def identity(descriptor):
    value = os.fstat(descriptor)
    mount_id = None
    try:
        with open(f"/proc/self/fdinfo/{descriptor}", "r", encoding="ascii") as source:
            rows = [row for row in source.read(4096).splitlines() if row.startswith("mnt_id:\t")]
        prefix = "mnt_id:\t"
        if len(rows) != 1 or not rows[0][len(prefix):].isdigit():
            raise FdMapError("invalid descriptor mount identity")
        mount_id = int(rows[0][len(prefix):])
    except FileNotFoundError:
        # Portable identity remains explicitly incomplete. It cannot be encoded
        # as a durable production generation without real fdinfo.
        mount_id = None
    return FdIdentity(
        mount_id, value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def _digest_regular(descriptor, expected):
    if (not stat.S_ISREG(expected.mode) or expected.nlink != 1
            or not 0 <= expected.size <= MAX_INPUT):
        raise FdMapError("invalid inherited object")
    digest = hashlib.sha256()
    offset = 0
    while offset < expected.size:
        part = os.pread(descriptor, min(16_384, expected.size - offset), offset)
        if not part:
            raise FdMapError("short inherited object")
        digest.update(part)
        offset += len(part)
    if identity(descriptor) != expected:
        raise FdMapError("inherited object changed")
    return digest.hexdigest()


def _input_routes():
    seal, states = object(), {}

    class InputOwner:
        __slots__ = ()
        def __new__(cls, key=None):
            if key is not seal:
                raise FdMapError("sealed input owner")
            return super().__new__(cls)

    def bind_inputs(client_fd, known_hosts_fd, expected_client, expected_known_hosts):
        """Bind exact SSH inputs behind the historical one-use owner API."""
        if (type(client_fd) is not int or type(known_hosts_fd) is not int
                or client_fd < 0 or known_hosts_fd < 0 or client_fd == known_hosts_fd
                or not isinstance(expected_client, FdIdentity)
                or not isinstance(expected_known_hosts, FdIdentity)):
            raise FdMapError("invalid fixed inputs")
        rows = []
        for role, descriptor, expected in (
            (CLIENT_KEY, client_fd, expected_client),
            (KNOWN_HOSTS, known_hosts_fd, expected_known_hosts),
        ):
            if identity(descriptor) != expected:
                raise FdMapError("input identity mismatch")
            rows.append(InheritedBinding(
                role, descriptor, ROLE_TARGETS[role], expected,
                _digest_regular(descriptor, expected),
            ))
        if (rows[0].identity.device, rows[0].identity.inode) == (
            rows[1].identity.device, rows[1].identity.inode,
        ):
            raise FdMapError("roles share one underlying object")
        owner = InputOwner(seal)
        states[owner] = (tuple(rows), False)
        return owner

    def claim(targets, owner):
        state = states.get(owner)
        if (type(owner) is not InputOwner or state is None or state[1]
                or type(targets) is not tuple or targets != (200, 201)):
            raise FdMapError("invalid input claim")
        rows = revalidate(state[0])
        states[owner] = (state[0], True)
        return rows

    return InputOwner, bind_inputs, claim


InputOwner, bind_inputs, claim = _input_routes()
make_input_owner_for_tests = bind_inputs

del _input_routes


def revalidate(bindings):
    """Recheck exact generations and bytes immediately before child release."""
    if type(bindings) is not tuple:
        raise FdMapError("invalid inherited bindings")
    if not bindings:
        return bindings
    if (tuple(row.role for row in bindings) != (CLIENT_KEY, KNOWN_HOSTS)
            or tuple(row.target_fd for row in bindings) != (200, 201)):
        raise FdMapError("invalid inherited bindings")
    for row in bindings:
        if (not isinstance(row, InheritedBinding)
                or identity(row.source_fd) != row.identity
                or _digest_regular(row.source_fd, row.identity) != row.content_sha256):
            raise FdMapError("inherited descriptor replaced")
    return bindings


def relocate_internals(descriptors, reserved=(0, 1, 2, 3, 198, 200, 201)):
    """Move colliding child-private fds before stdio or inherited mapping."""
    if (type(descriptors) is not tuple or type(reserved) is not tuple
            or any(type(item) is not int or item < 0 for item in descriptors + reserved)
            or len(set(descriptors)) != len(descriptors)):
        raise OSError(errno.EINVAL, "invalid child descriptors")
    observed = tuple(identity(item) for item in descriptors)
    relocated = list(descriptors)
    created = []
    try:
        floor = max(reserved, default=2) + 1
        for index, descriptor in enumerate(descriptors):
            if descriptor in reserved:
                duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, floor)
                created.append(duplicate)
                if identity(duplicate) != observed[index]:
                    raise OSError(errno.ESTALE, "child descriptor relocation mismatch")
                relocated[index] = duplicate
        for index, descriptor in enumerate(descriptors):
            if relocated[index] != descriptor:
                os.close(descriptor)
        if any(value in reserved for value in relocated):
            raise OSError(errno.ESTALE, "child descriptor remains reserved")
        for descriptor, expected in zip(relocated, observed):
            if identity(descriptor) != expected:
                raise OSError(errno.ESTALE, "child descriptor changed")
        created.clear()
        return tuple(relocated)
    finally:
        for descriptor in created:
            try:
                os.close(descriptor)
            except OSError:
                pass


def install(bindings):
    """Install exact targets, verify them, and close every non-target original."""
    try:
        revalidate(bindings)
    except FdMapError as error:
        raise OSError(errno.ESTALE, str(error)) from error
    temporaries = []
    try:
        floor = max((row.target_fd for row in bindings), default=2) + 1
        for row in bindings:
            temporary = fcntl.fcntl(row.source_fd, fcntl.F_DUPFD_CLOEXEC, floor)
            temporaries.append((temporary, row))
            if identity(temporary) != row.identity:
                raise OSError(errno.ESTALE, "inherited descriptor duplicate mismatch")
        for temporary, row in temporaries:
            os.dup2(temporary, row.target_fd, inheritable=True)
            if identity(row.target_fd) != row.identity or not os.get_inheritable(row.target_fd):
                raise OSError(errno.ESTALE, "inherited descriptor target mismatch")
        targets = {row.target_fd for row in bindings}
        for row in bindings:
            if row.source_fd not in targets:
                os.close(row.source_fd)
        for row in bindings:
            if identity(row.target_fd) != row.identity:
                raise OSError(errno.ESTALE, "inherited target changed while closing originals")
        for temporary, _row in temporaries:
            os.close(temporary)
        temporaries.clear()
    finally:
        for temporary, _row in temporaries:
            try:
                os.close(temporary)
            except OSError:
                pass

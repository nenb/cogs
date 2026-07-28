"""Collision-safe, role-sealed inherited descriptor mapping."""
from dataclasses import dataclass
import errno
import fcntl
import os

CLIENT_KEY = "CLIENT_KEY"
KNOWN_HOSTS = "KNOWN_HOSTS"
ROLE_TARGETS = {CLIENT_KEY: 200, KNOWN_HOSTS: 201}


class FdMapError(Exception):
    pass


@dataclass(frozen=True)
class FdIdentity:
    device: int
    inode: int
    mode: int
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


def identity(descriptor):
    value = os.fstat(descriptor)
    return FdIdentity(value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                      value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _routes():
    seal, states = object(), {}

    class InputOwner:
        __slots__ = ()
        def __new__(cls, key=None):
            if key is not seal:
                raise FdMapError("sealed input owner")
            return super().__new__(cls)

    def make(client_fd, known_hosts_fd, expected_client, expected_known_hosts):
        if (type(client_fd) is not int or type(known_hosts_fd) is not int
                or client_fd < 0 or known_hosts_fd < 0 or client_fd == known_hosts_fd
                or type(expected_client) is not FdIdentity
                or type(expected_known_hosts) is not FdIdentity):
            raise FdMapError("invalid sealed inputs")
        observed_client = identity(client_fd)
        observed_hosts = identity(known_hosts_fd)
        if observed_client != expected_client or observed_hosts != expected_known_hosts:
            raise FdMapError("input identity mismatch")
        if (observed_client.device, observed_client.inode) == (observed_hosts.device, observed_hosts.inode):
            raise FdMapError("roles share one underlying object")
        value = InputOwner(seal)
        states[value] = ((client_fd, expected_client), (known_hosts_fd, expected_known_hosts), False)
        return value

    def claim(targets, owner):
        state = states.get(owner)
        if (type(owner) is not InputOwner or state is None or state[2]
                or type(targets) is not tuple or targets != (200, 201)):
            raise FdMapError("invalid input claim")
        rows = []
        for role, (descriptor, bound) in zip((CLIENT_KEY, KNOWN_HOSTS), state[:2]):
            if identity(descriptor) != bound:
                raise FdMapError("input replaced or changed")
            rows.append(InheritedBinding(role, descriptor, ROLE_TARGETS[role], bound))
        if len({row.source_fd for row in rows}) != 2:
            raise FdMapError("duplicate input descriptor")
        states[owner] = (state[0], state[1], True)
        return tuple(rows)

    return make, claim


make_input_owner_for_tests, claim = _routes()
del _routes


def relocate_internals(descriptors, reserved=(0, 1, 2, 200, 201)):
    """Move colliding child-private fds before any stdio or inherited mapping."""
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
    if type(bindings) is not tuple:
        raise OSError(errno.EINVAL, "invalid inherited bindings")
    temporaries = []
    try:
        if (tuple(row.role for row in bindings) != (CLIENT_KEY, KNOWN_HOSTS)
                or tuple(row.target_fd for row in bindings) != (200, 201)
                or len({row.source_fd for row in bindings}) != len(bindings)):
            raise OSError(errno.EINVAL, "invalid inherited roles")
        floor = max((row.target_fd for row in bindings), default=2) + 1
        for row in bindings:
            if type(row) is not InheritedBinding or identity(row.source_fd) != row.identity:
                raise OSError(errno.ESTALE, "inherited descriptor replaced")
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

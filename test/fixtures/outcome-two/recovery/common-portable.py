"""Portable integrated-common issuer fault driver for recovery acceptance."""

import errno
from types import MethodType, SimpleNamespace


def run_issuer_fault(common, kernel, context, patched, vnode_type, process_type, crash_type):
    """Reach the integrated fixed issuer while keeping its process model portable."""
    registry = common.FdRegistry(kernel.close)
    issuer = common.SystemCommonOps(registry)
    cut = kernel.spec["cut"]
    digest = kernel.production_result["source_set_sha256"]

    def held_sources(_self, _context, _root):
        if cut in {"issuer-source-open", "issuer-source-read", "issuer-source-fstat"}:
            kernel.hit(cut)
            kernel.events.append("issuer:child-loop")
            raise OSError(errno.EIO, f"modeled {cut}")
        paths = (*common.SOURCE_PATHS, f"scripts/native-qualification/{common.DRIVERS[context.job]}")
        held = {}
        for path in paths:
            lease = registry.adopt(
                kernel.allocate("file", vnode_type("file", b"source", f"held:{path}")),
                f"held:{path}",
            )
            held[path] = SimpleNamespace(raw=b"source", lease=lease, oid="0" * 40)
        return held, digest

    def capsule(_self, _context, _held, _digest):
        return b"admission", b"capsule"

    def sealed(_self, _raw, purpose):
        if cut in {"issuer-memfd", "issuer-write", "issuer-fsync"}:
            kernel.hit(cut)
            kernel.events.append("issuer:child-loop")
            raise OSError(errno.EIO, f"modeled {cut}")
        return registry.adopt(kernel.allocate("file", vnode_type("file", role=purpose)), purpose)

    def pipe(_self, left, right):
        if cut == "issuer-pipe":
            kernel.hit(cut)
            kernel.events.append("issuer:child-loop")
            raise OSError(errno.EMFILE, "modeled issuer pipe")
        return (
            registry.adopt(kernel.allocate("file", vnode_type("file", role=left)), left),
            registry.adopt(kernel.allocate("file", vnode_type("file", role=right)), right),
        )

    issuer._admit_sources = MethodType(held_sources, issuer)
    issuer._capsule = MethodType(capsule, issuer)
    issuer._sealed = MethodType(sealed, issuer)
    issuer._pipe = MethodType(pipe, issuer)
    issuer._decode_cli = MethodType(lambda _self, _raw: dict(kernel.production_result), issuer)
    process = process_type(800)
    process.live = False
    process.exited.set()
    kernel.processes[process.pid] = process
    reads = {}
    output_raw = common._canonical(kernel.production_result, True)

    def issuer_fork():
        if cut == "issuer-fork":
            kernel.hit(cut)
            kernel.events.append("issuer:child-loop")
            raise OSError(errno.EAGAIN, "modeled issuer fork")
        kernel.events.append("issuer:child-loop")
        return process.pid

    def issuer_pidfd(pid, flags=0):
        del pid, flags
        if cut == "issuer-pidfd":
            kernel.hit(cut)
            kernel.events.append("issuer:child-loop")
            raise OSError(errno.EIO, "modeled issuer pidfd")
        return kernel.allocate("pidfd", process)

    def issuer_write(fd, raw):
        role = kernel.fds[fd][1].role
        if role == "launcher-gate" and cut == "issuer-gate-write":
            kernel.hit(cut)
            kernel.events.append("issuer:child-loop")
            return 0
        return kernel.write(fd, raw)

    def issuer_read(fd, size):
        role = kernel.fds[fd][1].role
        if role == "launcher-output" and cut in {"issuer-output-read", "issuer-output-eof", "issuer-crash"}:
            kernel.hit(cut)
            kernel.events.append("issuer:child-loop")
            if cut == "issuer-crash":
                raise crash_type("modeled issuer crash")
            raise OSError(errno.EIO, f"modeled {cut}")
        if role == "launcher-output" and not reads.get(fd):
            reads[fd] = True
            return output_raw[:size]
        return b""

    def issuer_reap(pid, pidfd):
        del pid, pidfd
        if cut == "issuer-waitpid":
            kernel.hit(cut)
            kernel.events.append("issuer:child-loop")
            raise common.QualificationError("modeled issuer exact waitpid")
        process.reaped = True
        return 0

    original_close = kernel.close
    def issuer_close(fd):
        role = kernel.fds[fd][1].role if fd in kernel.fds and kernel.fds[fd][0] in {"file", "directory", "socket"} else ""
        original_close(fd)
        if role == "held-launcher" and kernel.hit("issuer-close") == "after-error":
            kernel.events.append("issuer:child-loop")
            raise OSError(errno.EIO, "modeled issuer close after effect")

    with patched(
        common.os,
        fork=issuer_fork,
        pidfd_open=issuer_pidfd,
        write=issuer_write,
        read=issuer_read,
        set_blocking=lambda fd, blocking: None,
    ), patched(
        common.select, select=lambda readers, writers, errors, timeout=0: (list(readers), [], []),
    ), patched(common, _bounded_reap=issuer_reap), patched(registry, _closer=issuer_close):
        return issuer.run_fixed_operation(context, context.job)

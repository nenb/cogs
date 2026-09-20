#!/usr/bin/env python3
"""Private one-shot AWS full-cycle tracer; never an evidence producer."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

# GetCommandInvocation returns only the first 8,000 stderr characters.
_MAX_DIAGNOSTIC_BYTES = 7_500
_written = 0
_var_lib_baseline: tuple[str, ...] | None = None
_cgroup_stress_announced = False


def _var_lib_names() -> tuple[str, ...]:
    return tuple(sorted(os.listdir("/var/lib")))


def _emit(event: str, **fields: object) -> None:
    global _written
    if event in {"owner-call-start", "owner-call-passed"} and _written >= 3_500:
        return
    value = {"version": "cogs.stage2-aws-full-cycle-trace/v1", "event": event, **fields}
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    if _written + len(raw) > _MAX_DIAGNOSTIC_BYTES:
        return
    offset = 0
    while offset < len(raw):
        count = os.write(2, raw[offset:])
        if count <= 0:
            raise OSError("trace stderr made no progress")
        offset += count
    _written += len(raw)


def _exception(error: BaseException) -> None:
    rendered = "".join(traceback.TracebackException.from_exception(
        error, limit=30, compact=True).format())
    _emit("exception", exception_type=type(error).__name__,
          message=str(error)[:1000], traceback=rendered[-4000:])


def _write_stdout(raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        count = os.write(1, raw[offset:])
        if count <= 0:
            raise OSError("trace receipt stdout made no progress")
        offset += count


class _TracingOwners:
    """Delegate unchanged owner calls while recording only boundaries and failures."""

    def __init__(self, target: object):
        self._target = target

    def __getattr__(self, name: str):
        value = getattr(self._target, name)
        if not callable(value):
            return value

        def traced(*args, **kwargs):
            _emit("owner-call-start", owner_call=name)
            previous_umask = None
            if name in {"create_inputs", "stage_runtime"}:
                previous_umask = os.umask(0o022)
                _emit("diagnostic-hotpatch", owner_call=name, umask="0022")
            try:
                result = value(*args, **kwargs)
            except BaseException as error:
                _emit("owner-call-failed", owner_call=name,
                      exception_type=type(error).__name__, message=str(error)[:1000])
                _exception(error)
                raise
            finally:
                if previous_umask is not None:
                    os.umask(previous_umask)
            if name == "acquire_rootfs":
                global _var_lib_baseline
                _var_lib_baseline = _var_lib_names()
            _emit("owner-call-passed", owner_call=name)
            return result

        return traced


def main() -> None:
    if sys.argv != [sys.argv[0]]:
        raise SystemExit(64)
    mode_path = Path("/root/cogs-stage2-cycle-mode")
    mode = mode_path.read_text(encoding="ascii").strip()
    if mode not in {"full", "readiness"}:
        raise RuntimeError("invalid diagnostic cycle mode")
    module_root = Path(
        "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote")
    if not module_root.is_dir():
        raise RuntimeError("fixed remote module root is unavailable")
    sys.path.insert(0, str(module_root))
    import completion_cycle_evidence as evidence
    import completion_kata_coordinator as coordinator
    import completion_kata_network as network
    import completion_kata_process as process
    import completion_rootfs_fs as rootfs_fs

    original_revalidate_chain = rootfs_fs._revalidate_chain

    def traced_revalidate_chain(chain, control, parent_delta=None):
        try:
            return original_revalidate_chain(chain, control, parent_delta)
        except BaseException:
            fresh = None
            opened = []
            try:
                def generation_delta(expected, observed):
                    fields = ("mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
                    changed = {field: [getattr(expected, field), getattr(observed, field)]
                               for field in fields
                               if getattr(expected, field) != getattr(observed, field)}
                    if expected.key != observed.key:
                        changed["key"] = [
                            [expected.key.mount_id, expected.key.device,
                             expected.key.inode, expected.key.kind],
                            [observed.key.mount_id, observed.key.device,
                             observed.key.inode, observed.key.kind]]
                    return changed

                fresh = rootfs_fs._open_root_node(control)
                changed = generation_delta(chain.anchor.generation, fresh.generation)
                if changed:
                    _emit("rootfs-generation-mismatch", path="/", changed=changed)
                parent, parts = fresh, []
                for component in chain.components:
                    expected = component.node.generation
                    if (parent_delta is not None
                            and expected.key == parent_delta.after.generation.key):
                        expected = parent_delta.after.generation
                    node = rootfs_fs._open_path_node(
                        parent, component.name, expected.key.kind, control)
                    opened.append(node)
                    parts.append(component.name.text)
                    changed = generation_delta(expected, node.generation)
                    if changed:
                        path = "/" + "/".join(parts)
                        details = {}
                        if path == "/var/lib" and _var_lib_baseline is not None:
                            current = _var_lib_names()
                            details = {
                                "added_names": sorted(set(current) - set(_var_lib_baseline)),
                                "removed_names": sorted(set(_var_lib_baseline) - set(current)),
                            }
                        _emit("rootfs-generation-mismatch",
                              path=path, changed=changed, **details)
                        break
                    parent = node
            except BaseException as trace_error:
                _emit("rootfs-generation-trace-failed",
                      exception_type=type(trace_error).__name__)
            finally:
                for node in reversed(opened):
                    try:
                        rootfs_fs._close_node(node)
                    except BaseException:
                        pass
                if fresh is not None:
                    try:
                        rootfs_fs._close_node(fresh)
                    except BaseException:
                        pass
            raise

    rootfs_fs._revalidate_chain = traced_revalidate_chain
    original_causal_proof = network.prove_causal_network

    def traced_causal_proof(before, after, guest):
        try:
            return original_causal_proof(before, after, guest)
        except BaseException:
            try:
                first, second = network._counter_map(before), network._counter_map(after)
                names = (*network.CAUSAL_POSITIVE_SENSORS,
                         *network.CAUSAL_MONOTONIC_SENSORS,
                         *network.CAUSAL_ZERO_SENSORS)
                _emit("causal-network-deltas", deltas=[
                    [name, second[name].packets - first[name].packets,
                     second[name].bytes - first[name].bytes]
                    for name in names])
            except BaseException as trace_error:
                _emit("causal-network-trace-failed",
                      exception_type=type(trace_error).__name__)
            raise

    network.prove_causal_network = traced_causal_proof
    original_prepare_cgroup = process._prepare_cgroup

    def traced_prepare_cgroup(context, daemon_profile=None):
        global _cgroup_stress_announced
        if daemon_profile is not None and daemon_profile.runtime_leaf_name is not None:
            if not _cgroup_stress_announced:
                _emit("diagnostic-hotpatch", owner_call="cgroup-race-stress",
                      delay_milliseconds=3000)
                _cgroup_stress_announced = True
            time.sleep(3)
        try:
            return original_prepare_cgroup(context, daemon_profile)
        except BaseException:
            if daemon_profile is not None:
                try:
                    base_fd, base = process._directory_identity(process.CGROUP_BASE)
                    try:
                        leaves = sorted(process._cgroup_leaf_names(base_fd))
                    finally:
                        os.close(base_fd)
                    expected_leaves = [daemon_profile.leaf_name]
                    if daemon_profile.runtime_leaf_name is not None:
                        expected_leaves.append(daemon_profile.runtime_leaf_name)
                    daemon_generation = None
                    runtime_generation = None
                    try:
                        daemon_generation = process._cgroup_generation(
                            daemon_profile.cgroup_path)
                    except BaseException as error:
                        daemon_generation = ["error", type(error).__name__]
                    if daemon_profile.runtime_leaf_name is not None:
                        try:
                            runtime_generation = process._cgroup_generation(
                                process.CGROUP_BASE + "/" + daemon_profile.runtime_leaf_name)
                        except BaseException as error:
                            runtime_generation = ["error", type(error).__name__]
                    _emit("cgroup-baseline-mismatch",
                          expected_base=list(daemon_profile.base_generation),
                          actual_base=list(process._generation_tuple(base)),
                          expected_leaves=sorted(expected_leaves),
                          actual_leaves=leaves,
                          expected_daemon=list(daemon_profile.leaf_generation),
                          actual_daemon=daemon_generation,
                          runtime_generation=runtime_generation)
                except BaseException as trace_error:
                    _emit("cgroup-baseline-trace-failed",
                          exception_type=type(trace_error).__name__)
            raise

    process._prepare_cgroup = traced_prepare_cgroup
    coordinator._owners = _TracingOwners(coordinator._owners)

    fwupd_states = {}
    for unit in ("fwupd-refresh.timer", "fwupd-refresh.service", "fwupd.service"):
        loaded = subprocess.run(
            ("/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit),
            check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=30).stdout.strip()
        if loaded == "not-found":
            fwupd_states[unit] = "not-found"
            continue
        masked = subprocess.run(
            ("/usr/bin/systemctl", "mask", "--runtime", "--now", unit),
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, timeout=30)
        if masked.returncode != 0:
            raise RuntimeError("failed to quiesce fwupd unit: " + unit)
        active = subprocess.run(
            ("/usr/bin/systemctl", "is-active", unit), check=False,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=30).stdout.strip()
        if active in {"active", "activating", "reloading", "deactivating"}:
            raise RuntimeError("fwupd unit remained active: " + unit)
        fwupd_states[unit] = active
    _emit("diagnostic-hotpatch", owner_call="host-preparation",
          fwupd_units=fwupd_states)
    forwarding_path = "/proc/sys/net/ipv4/ip_forward"

    def read_forwarding() -> bytes:
        descriptor = os.open(forwarding_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            return os.read(descriptor, 8)
        finally:
            os.close(descriptor)

    def write_forwarding(value: bytes) -> None:
        descriptor = os.open(forwarding_path, os.O_WRONLY | os.O_CLOEXEC)
        try:
            if os.write(descriptor, value) != len(value):
                raise OSError("short ip_forward write")
        finally:
            os.close(descriptor)

    previous_forwarding = read_forwarding()
    if previous_forwarding not in {b"0\n", b"1\n"}:
        raise RuntimeError("unexpected ip_forward value")
    write_forwarding(b"1\n")
    if read_forwarding() != b"1\n":
        raise RuntimeError("ip_forward hotpatch did not apply")
    _emit("diagnostic-hotpatch", owner_call="full-cycle",
          ip_forward_before=previous_forwarding.decode("ascii").strip(),
          ip_forward_during="1")
    _emit("cycle-start", mode=mode)
    try:
        receipt = (coordinator._run_fixed_full_cycle() if mode == "full"
                   else coordinator._run_fixed_readiness_cycle())
    finally:
        write_forwarding(previous_forwarding)
    _emit("cycle-passed", mode=mode)
    _write_stdout(evidence._consume_cycle_receipt(receipt))


def cli() -> None:
    try:
        main()
    except SystemExit:
        raise
    except BaseException as error:
        _emit("full-cycle-failed", exception_type=type(error).__name__,
              message=str(error)[:1000])
        _exception(error)
        raise SystemExit(2) from None


if __name__ == "__main__":
    cli()

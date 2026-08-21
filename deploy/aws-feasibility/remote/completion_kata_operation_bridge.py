"""Narrow mutable operation/input/rootfs composition for the fixed coordinator.

No pathname, command, deadline, callback, retry, or fallback enters this module.
Static custody remains the only source of source identity; all filesystem effects
remain in the existing operation, input, and retained-rootfs owners.
"""
import time

import completion_kata_admission as admission
import completion_kata_inputs as inputs
import completion_kata_operation as operation
import completion_rootfs_fs as fs
import completion_rootfs_lease as rootfs


class OperationBridgeError(Exception):
    pass


def _require(condition, message="fixed mutable operation bridge"):
    if not condition:
        raise OperationBridgeError(message)


def _routes():
    seal = object()
    states = {}
    issued = False

    class _Bridge:
        __slots__ = ()
        def __new__(cls, key=None):
            _require(key is seal, "sealed mutable operation bridge")
            return super().__new__(cls)

    def state(bridge, lifecycle):
        _require(type(bridge) is _Bridge and bridge in states)
        current = states[bridge]
        bound = current.get("lifecycle")
        _require(bound is None or bound is lifecycle, "lifecycle bridge swap")
        current["lifecycle"] = lifecycle
        return current

    def approval(lifecycle):
        binding = admission._static_custody_binding(lifecycle.static_custody)
        _require(type(binding) is dict)
        return fs.SourceApproval(binding["source_head"], binding["source_manifest_sha256"])

    def control():
        return fs.OperationControl(time.monotonic_ns() + operation.JOURNAL_TOTAL_NS,
                                   lambda: False)

    def open_chain(current):
        if current.get("chain") is None:
            current["control"] = control()
            current["chain"] = operation._open_base_chain(current["control"])
        return current["chain"].components[-1].node

    def acquire(bridge, lifecycle):
        current = state(bridge, lifecycle)
        _require(current.get("lease") is None and current.get("authority") is None)
        source, outer = approval(lifecycle), control()
        lease = rootfs._acquire(source, outer)
        authority = None
        try:
            authority = operation._open_fixed_operation()
            current.update({"approval": source, "lease": lease, "authority": authority})
            open_chain(current)
            rootfs._begin_kata_operation(
                authority, lease, source, current["control"])
            return lease
        except BaseException as error:
            if authority is not None:
                try: authority.close()
                except BaseException as close_error:
                    raise BaseExceptionGroup("operation begin/close failure", (error, close_error))
            raise

    def open_operation(bridge, lifecycle):
        current = state(bridge, lifecycle)
        _require(current.get("lease") is lifecycle.rootfs)
        return operation._claim_production_operation(current["authority"])

    def open_existing(bridge, lifecycle):
        current = state(bridge, lifecycle)
        _require(current.get("authority") is None)
        authority = operation._open_fixed_operation()
        try:
            cleanup = operation._claim_production_cleanup_operation(authority)
            current.update({"authority": authority, "cleanup": cleanup})
            open_chain(current)
            return cleanup
        except BaseException as error:
            authority.close()
            raise error

    def create_inputs(bridge, lifecycle):
        current = state(bridge, lifecycle)
        completion = open_chain(current)
        owner = inputs._compose_production_inputs(
            current["authority"], completion, current["control"], lifecycle.executables)
        current["inputs"] = owner
        owner.create()
        return owner

    def remove_inputs(bridge, lifecycle):
        current = state(bridge, lifecycle)
        owner = current.get("inputs")
        if owner is not None:
            return owner.remove()
        cleanup = inputs._compose_production_input_cleanup(
            current.get("cleanup", lifecycle.operation), open_chain(current), current["control"])
        current["input_cleanup"] = cleanup
        return cleanup.continue_cleanup()

    def prepare_release(bridge, lifecycle):
        current = state(bridge, lifecycle)
        cleanup = current.get("cleanup")
        if cleanup is None:
            cleanup = operation._claim_production_cleanup_operation(current["authority"])
            current["cleanup"] = cleanup
        return cleanup.prepare_rootfs_release()

    def authorize_release(bridge, lifecycle):
        current = state(bridge, lifecycle)
        held = current.get("lease") or lifecycle.rootfs
        if held is None:
            held = rootfs._reopen_kata_reserved(
                current["cleanup"].reserve_rootfs(), current["control"])
        _require(type(held) is rootfs.RetainedRootfsLease and held.disposition == "held")
        authorization = rootfs._authorize_kata_release(
            current["cleanup"].reserve_rootfs_release(), held, current["control"])
        rootfs._close_preserving(held.retained)
        current["authorization"] = authorization
        return authorization

    def remove_rootfs(bridge, lifecycle):
        current = state(bridge, lifecycle)
        held, authorization = rootfs._recover_kata_release(
            current["cleanup"], current["control"])
        current["released"] = held
        return authorization

    def retire(bridge, lifecycle):
        current = state(bridge, lifecycle)
        retired = operation._retire_production_operation(
            current["cleanup"], lifecycle.final_baselines)
        current["retired"] = retired
        return retired

    def remove_operation(bridge, lifecycle):
        current = state(bridge, lifecycle)
        retired = operation._remove_retired_operation(current["cleanup"])
        _require(retired.raw == current["retired"].raw)
        current["authority"].close()
        current["authority"] = None
        chain, current["chain"] = current.get("chain"), None
        if chain is not None:
            fs._close_chain(chain)
        return retired

    def abandon(bridge, lifecycle):
        """Preserve the durable leased operation when assignment was interrupted."""
        current = state(bridge, lifecycle)
        held = current.get("lease") or lifecycle.rootfs
        _require(type(held) is rootfs.RetainedRootfsLease
                 and held.disposition == "held")
        errors = []
        try: rootfs._close_preserving(held.retained)
        except BaseException as error: errors.append(error)
        authority, current["authority"] = current.get("authority"), None
        if authority is not None:
            try: authority.close()
            except BaseException as error: errors.append(error)
        chain, current["chain"] = current.get("chain"), None
        if chain is not None:
            try: fs._close_chain(chain)
            except BaseException as error: errors.append(error)
        if errors: raise BaseExceptionGroup("pre-open preservation failure", errors)
        return "durable-operation-preserved"

    def recover_pending(bridge, lifecycle):
        import completion_kata_process as process
        current = state(bridge, lifecycle)
        authority = current.get("cleanup", lifecycle.operation)
        if operation._has_recovery_command(authority):
            return process._recover_pending_production(authority)
        return operation._durable_phase(authority)

    def issue():
        nonlocal issued
        _require(not issued, "mutable operation bridge already issued")
        issued = True
        value = _Bridge(seal)
        states[value] = {"lifecycle": None, "authority": None, "chain": None}
        return value

    return (issue, acquire, open_operation, open_existing, create_inputs,
            remove_inputs, prepare_release, authorize_release, remove_rootfs,
            retire, remove_operation, abandon, recover_pending)


(_take_operation_bridge, _acquire_rootfs, _open_operation, _open_existing_operation,
 _create_inputs, _remove_inputs, _prepare_rootfs_release, _authorize_rootfs_release,
 _remove_rootfs, _retire_operation, _remove_operation, _abandon_prepared_rootfs,
 _recover_pending) = _routes()
del _routes

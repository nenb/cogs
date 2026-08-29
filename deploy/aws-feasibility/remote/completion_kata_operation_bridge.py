"""Narrow mutable operation/input/rootfs composition for the fixed coordinator.

No pathname, command, deadline, callback, retry, or fallback enters this module.
Static custody remains the only source of source identity; all filesystem effects
remain in the existing operation, input, and retained-rootfs owners.
"""
import time

import completion_kata_inputs as inputs
import completion_kata_preparation_bridge as preparation
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

    def control():
        return fs.OperationControl(time.monotonic_ns() + operation.JOURNAL_TOTAL_NS,
                                   lambda: False)

    def open_chain(current):
        if current.get("chain") is None:
            current["control"] = control()
            current["chain"] = operation._open_base_chain(current["control"])
        return current["chain"].components[-1].node

    def acquire(bridge, lifecycle):
        """Acquire only through preparation's verified SourceApproval/custody realm."""
        current = state(bridge, lifecycle)
        _require(current.get("lease") is None and current.get("authority") is None)
        source = preparation._fixed_source_approval(lifecycle.static_custody)
        _require(source is lifecycle.source_approval,
                 "preparation SourceApproval identity differs")
        lease = preparation._acquire_fixed_rootfs(lifecycle.static_custody)
        _require(type(source) is fs.SourceApproval
                 and type(lease) is rootfs.RetainedRootfsLease
                 and lease.disposition == "held")
        current.update({"approval": source, "lease": lease, "begin_attempted": False})
        return lease

    def open_operation(bridge, lifecycle):
        current = state(bridge, lifecycle)
        _require(current.get("lease") is lifecycle.rootfs
                 and current.get("approval") is lifecycle.source_approval
                 and current.get("authority") is None)
        authority = operation._open_fixed_operation()
        current["authority"] = authority
        current["begin_attempted"] = True
        try:
            open_chain(current)
            rootfs._begin_kata_operation(
                authority, lifecycle.rootfs, lifecycle.source_approval,
                current["control"])
            return operation._claim_production_operation(authority)
        except BaseException as error:
            # A failed begin may already have durable state. Preserve it for the
            # cleanup-only entry; never reinterpret it as an unassigned lease.
            errors = [error]
            try: rootfs._close_preserving(lifecycle.rootfs.retained)
            except BaseException as close_error: errors.append(close_error)
            try: authority.close()
            except BaseException as close_error: errors.append(close_error)
            current["authority"] = None
            current["begin_preserved"] = True
            chain, current["chain"] = current.get("chain"), None
            if chain is not None:
                try: fs._close_chain(chain)
                except BaseException as close_error: errors.append(close_error)
            if len(errors) == 1: raise
            raise BaseExceptionGroup("operation begin preservation failure", errors)

    def open_existing(bridge, lifecycle):
        """Read-only classification; unadmitted state never becomes production."""
        current = state(bridge, lifecycle)
        _require(current.get("authority") is None
                 and type(lifecycle.source_approval) is fs.SourceApproval)
        authority = operation._open_fixed_operation_recovery()
        try:
            status = authority.status()
            if status == "preserve":
                raise OperationBridgeError("operation recovery classification preserved")
            if status in {"infrastructure-absent", "infrastructure-subset",
                          "infrastructure-complete"}:
                prestage = operation._claim_pre_admission_cleanup(
                    authority, lifecycle.source_approval)
                current.update({"authority": authority, "prestage": prestage,
                                "reconstructed_phase": status})
                return None
            _require(status == "exact")
            identity = authority.reconstruction_identity()
            phase = identity["phase"]
            try:
                cleanup = (operation._claim_production_retired_operation(authority)
                           if phase == "RETIRED" else
                           operation._claim_production_recovery_operation(authority))
            except operation.OperationError:
                prestage = operation._claim_pre_admission_cleanup(
                    authority, lifecycle.source_approval)
                current.update({"authority": authority, "prestage": prestage,
                                "reconstructed_phase": phase})
                return None
            current.update({"authority": authority, "cleanup": cleanup,
                            "reconstructed_phase": phase})
            open_chain(current)
            return cleanup
        except BaseException as error:
            authority.close()
            current["authority"] = None
            raise error

    def recover_preproduction(bridge, lifecycle):
        current = state(bridge, lifecycle)
        prestage = current.get("prestage")
        _require(prestage is not None and lifecycle.operation is None
                 and current.get("cleanup") is None)
        if current.get("control") is None: current["control"] = control()
        try:
            receipt = rootfs._recover_unadmitted_kata_operation(
                prestage.reserve_prestage_rootfs_release(),
                lifecycle.source_approval, current["control"])
            _require(receipt is None or rootfs._is_prestage_cleanup_receipt(receipt))
            current["prestage_receipt"] = receipt
            return receipt
        finally:
            prestage.close()
            current["prestage"] = None
            current["authority"] = None

    def reconstruct_rootfs(bridge, lifecycle):
        """Reopen only the lease named by both exact durable ledgers."""
        current = state(bridge, lifecycle)
        cleanup = current.get("cleanup")
        _require(cleanup is lifecycle.operation)
        identity = cleanup.reconstruction_identity()
        phase = identity["phase"]
        if phase == "UNCERTAIN":
            raise OperationBridgeError("uncertain operation is preserved")
        if (identity["rootfs_leased"] is None and phase != "ROOTFS_ACQUIRE_INTENT"
                or phase in {
                "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
                "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}):
            return None
        permit = operation._reconstruct_rootfs_permit(cleanup)
        held = rootfs._reopen_kata_reserved(permit, current["control"])
        _require(held.reference.token == identity["rootfs_token"]
                 and held.disposition == "held")
        current["lease"] = held
        return held

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
        phase = operation._durable_phase(lifecycle.operation)
        if phase in {"INPUT_REMOVED", "ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED",
                     "ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}:
            return phase
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
        phase = operation._durable_phase(cleanup)
        if phase in {"ROOTFS_RELEASE_READY", "ROOTFS_RELEASE_AUTHORIZED"}:
            return cleanup.prepare_rootfs_release()
        if phase != "INPUT_REMOVED": return phase
        return cleanup.prepare_rootfs_release()

    def authorize_release(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(current["cleanup"])
        if phase != "ROOTFS_RELEASE_READY": return phase
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
        phase = operation._durable_phase(current["cleanup"])
        if phase != "ROOTFS_RELEASE_AUTHORIZED": return phase
        held, authorization = rootfs._recover_kata_release(
            current["cleanup"], current["control"])
        current["released"] = held
        return authorization

    def retire(bridge, lifecycle):
        current = state(bridge, lifecycle)
        phase = operation._durable_phase(current["cleanup"])
        if phase not in {"ROOTFS_ABSENT", "FINAL_BASELINES", "RETIRE_INTENT", "RETIRED"}:
            return phase
        retired = operation._resume_retire_production_operation(
            current["cleanup"], lifecycle.final_baselines)
        import completion_local_evidence as evidence
        typed = evidence._RetiredJournalOwnerResult(retired.raw)
        current["retired"] = retired
        current["typed_retired"] = typed
        return typed

    def remove_operation(bridge, lifecycle):
        current = state(bridge, lifecycle)
        if operation._durable_phase(current["cleanup"]) != "RETIRED":
            return operation._durable_phase(current["cleanup"])
        retired = operation._remove_retired_operation(current["cleanup"])
        _require(retired.raw == current["retired"].raw
                 == current["typed_retired"].raw)
        current["authority"].close()
        current["authority"] = None
        chain, current["chain"] = current.get("chain"), None
        if chain is not None:
            fs._close_chain(chain)
        return retired

    def abandon(bridge, lifecycle):
        """Abandon only unbegun preparation; preserve any attempted operation."""
        current = state(bridge, lifecycle)
        held = current.get("lease") or lifecycle.rootfs
        _require(type(held) is rootfs.RetainedRootfsLease
                 and held.disposition == "held")
        if not current.get("begin_attempted"):
            return preparation._abandon_fixed_rootfs(lifecycle.static_custody, held)
        if current.get("begin_preserved"):
            return "durable-operation-preserved"
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
        states[value] = {"lifecycle": None, "authority": None, "chain": None,
                         "prestage": None}
        return value

    return (issue, acquire, open_operation, open_existing, recover_preproduction,
            reconstruct_rootfs, create_inputs, remove_inputs, prepare_release,
            authorize_release, remove_rootfs, retire, remove_operation, abandon,
            recover_pending)


(_take_operation_bridge, _acquire_rootfs, _open_operation, _open_existing_operation,
 _recover_preproduction, _reconstruct_rootfs, _create_inputs, _remove_inputs,
 _prepare_rootfs_release, _authorize_rootfs_release,
 _remove_rootfs, _retire_operation, _remove_operation, _abandon_prepared_rootfs,
 _recover_pending) = _routes()
del _routes

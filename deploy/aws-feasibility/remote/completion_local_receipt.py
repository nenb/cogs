"""Transactional custody closure for sealed owner execution evidence.

The evidence type and producer are closure-private; no report or journal bytes
can enter this receipt module's issuance surface.
"""
import hashlib

import completion_kata_admission as admission
import completion_local_evidence as owner_evidence


class LocalReceiptError(Exception):
    pass


def _require(condition, message="exact owner-issued local receipt required"):
    if not condition:
        raise LocalReceiptError(message)


def _new_local_receipt_routes(custody_binding, custody_close):
    """Build an isolated realm; alternate realms cannot mint production receipts."""
    _require(callable(custody_binding) and callable(custody_close),
             "custody operations required")
    (take_producer, associated_custody, prepare_evidence,
     commit_evidence, discard_evidence) = owner_evidence._new_owner_evidence_routes()
    seal, receipts = object(), {}
    issuer_taken = False
    issuance_attempted = False

    class _LocalReceipt:
        __slots__ = ()

        def __new__(cls, key=None):
            _require(key is seal, "sealed local result receipt")
            return super().__new__(cls)

    def close_all(targets):
        errors = []
        seen = set()
        for target in targets:
            identity = id(target)
            if identity in seen:
                continue
            seen.add(identity)
            try:
                custody_close(target)
            except BaseException as error:
                errors.append(error)
        return errors

    def fail_transaction(custody, evidence, primary, associated=None):
        discard_evidence(evidence)
        targets = [custody]
        if associated is not None:
            targets.append(associated)
        errors = close_all(targets)
        causes = [primary, *errors]
        cause = causes[0] if len(causes) == 1 else BaseExceptionGroup(
            "local receipt transaction failed", causes)
        raise LocalReceiptError("local receipt transaction failed; nothing minted") from cause

    def issue(custody, evidence):
        nonlocal issuance_attempted
        associated = None
        if issuance_attempted:
            fail_transaction(custody, evidence,
                             LocalReceiptError("local receipt issuance already attempted"))
        issuance_attempted = True
        try:
            associated = associated_custody(evidence)
            bindings = custody_binding(custody)
            raw, digest = prepare_evidence(custody, evidence, bindings)
            _require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == digest)
        except BaseException as error:
            fail_transaction(custody, evidence, error, associated)
        close_errors = close_all((custody,))
        if close_errors:
            discard_evidence(evidence)
            cause = close_errors[0] if len(close_errors) == 1 else BaseExceptionGroup(
                "execution custody close failed", close_errors)
            raise LocalReceiptError("custody close failed; nothing minted") from cause
        try:
            commit_evidence(evidence)
            receipt = _LocalReceipt(seal)
            receipts[receipt] = (raw, digest)
        except BaseException as error:
            discard_evidence(evidence)
            raise LocalReceiptError("receipt commit failed; nothing minted") from error
        return receipt

    def take_issuer():
        nonlocal issuer_taken
        _require(not issuer_taken, "local receipt issuer already taken")
        issuer_taken = True
        return issue

    def consume(receipt):
        state = receipts.pop(receipt, None)
        _require(type(receipt) is _LocalReceipt and state is not None)
        raw, digest = state
        _require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == digest)
        return raw

    return take_producer, take_issuer, consume


(_take_owner_evidence_producer, _take_local_receipt_issuer,
 _consume_local_receipt) = _new_local_receipt_routes(
     admission._execution_custody_binding, admission._abort_execution_custody)

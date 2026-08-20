import hashlib
import completion_kata_admission as admission
class LocalReceiptError(Exception): pass
def _require(condition, message='exact owner-issued local receipt required'):
    if not condition:
        raise LocalReceiptError(message)
def _receipt_routes():
    (seal, evidence_states, receipts) = (object(), {}, {}); issuer_taken = False
    class _OwnerExecutionEvidence:
        __slots__ = ()
        def __new__(cls, key=None):
            _require(key is seal, 'sealed owner execution evidence')
            return super().__new__(cls)
    class _LocalReceipt:
        __slots__ = ()
        def __new__(cls, key=None):
            _require(key is seal, 'sealed local result receipt')
            return super().__new__(cls)
    def issue(custody, evidence):
        state = evidence_states.pop(evidence, None); _require(type(evidence) is _OwnerExecutionEvidence and state is not None); binding = admission._execution_custody_binding(custody); _require(state['bindings'] == binding); raw = state['report_raw']; _require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == state['report_sha256']); receipt = _LocalReceipt(seal); receipts[receipt] = (raw, state['report_sha256']); admission._abort_execution_custody(custody)
        return receipt
    def take_issuer():
        nonlocal issuer_taken
        _require(not issuer_taken, 'local receipt issuer already taken'); issuer_taken = True
        return issue
    def consume(receipt):
        state = receipts.pop(receipt, None); _require(type(receipt) is _LocalReceipt and state is not None); (raw, digest) = state; _require(hashlib.sha256(raw).hexdigest() == digest)
        return raw
    return (take_issuer, consume)
(_take_local_receipt_issuer, _consume_local_receipt) = _receipt_routes(); del _receipt_routes

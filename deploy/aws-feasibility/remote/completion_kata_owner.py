"""Shared exact-type helpers for fixed Stage 2 Kata owner capabilities."""


def _reject(error_type, message):
    if message is None:
        raise error_type()
    raise error_type(message)


def sealed_type(name, seal, error_type, message=None, bases=(object,)):
    def construct(cls, key=None):
        if key is not seal:
            _reject(error_type, message)
        return object.__new__(cls)

    return type(name, bases, {"__slots__": (), "__new__": construct})


class Registry:
    def __init__(self, name, error_type, message=None, bases=(object,), sealed_message=None):
        self._error = error_type, message
        self._states = {}
        self.kind = sealed_type(name, self, error_type, sealed_message or message, bases)

    def issue(self, state):
        value = self.kind(self)
        self._states[value] = state
        return value

    def require(self, value):
        if type(value) is not self.kind or value not in self._states:
            _reject(*self._error)
        return self._states[value]

    def pop(self, value):
        state = self.require(value)
        del self._states[value]
        return state

    def items(self):
        return tuple(self._states.items())

"""Producer-only historical 16-input runtime closure entry."""
from completion_rootfs_plan import PACKAGE_ORDER, RootfsBuildInputs, revalidate_build_inputs
from completion_runtime_closure import _fail, _fixed_runtime_closure


def fixed_runtime_closure(authority):
    _fail(type(authority) is RootfsBuildInputs)
    return _fixed_runtime_closure(
        authority, revalidate_build_inputs, ("oci-layer",) + PACKAGE_ORDER)

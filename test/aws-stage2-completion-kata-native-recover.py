#!/usr/bin/env python3
"""Fresh-interpreter recovery half of the root Linux transaction crash gate."""
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch

if len(sys.argv) not in {2, 3}:
    raise RuntimeError("exact completion path and optional process identity required")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_kata_operation as operation
import completion_kata_process as process
import completion_rootfs_fs as fs

completion = Path(sys.argv[1])
reported = None if len(sys.argv) == 2 else tuple(int(item) for item in sys.argv[2].split(":"))
if reported is not None and len(reported) != 2:
    raise RuntimeError("invalid process identity")

def chain_factory(control):
    anchor = fs._open_root_node(control)
    chain = fs.HeldChain(anchor, ())
    parent = anchor
    try:
        for raw in completion.parts[1:]:
            name = fs._name(raw)
            node = fs._open_path_node(parent, name, "directory", control)
            chain = fs.HeldChain(chain.anchor, chain.components + (fs.ChainComponent(name, node),))
            parent = node
        return chain
    except BaseException as error:
        fs._close_chain(chain, error)

with patch.object(operation, "_open_base_chain", side_effect=chain_factory):
    authority = operation._open_fixed_operation()
    intent, preexec, _terminal = authority.recovery_command()
    if preexec is not None:
        reported = (preexec["pid"], preexec["proc_start_time"])
    process._recover_pending_fixed(authority)
    authority.close()

leaf = f"{process.CGROUP_BASE}/{intent['operation_token']}-{intent['command_serial']}"
if os.path.exists(leaf) or os.path.exists(process.CGROUP_BASE):
    raise AssertionError("recovery left cgroup residue")
if reported is not None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        observation = process._observe_proc(reported[0])
        if observation.kind is process.ObservationKind.ABSENT:
            break
        if observation.kind is process.ObservationKind.EXACT and observation.row[4] != reported[1]:
            break
        time.sleep(0.005)
    else:
        raise AssertionError("recovery left exact process residue")

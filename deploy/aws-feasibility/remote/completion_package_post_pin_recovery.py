#!/usr/bin/env python3
"""Fixed cleanup-only recovery for non-authoritative host post-pin reproduction."""

import os
from pathlib import Path
import sys

from completion_workload_owner import WorkloadError, recover_owned_root

POST_PIN_ROOT = Path("/tmp/cogs-stage2-workload-post-pin-v1")


def main():
    if len(sys.argv) != 1:
        os.write(2, b"completion host recovery failed: invocation\n")
        return 1
    try:
        recover_owned_root(POST_PIN_ROOT, "host-post-pin")
        os.write(1, b'{"result":"recovered","version":"cogs.stage2-workload-recovery-result/v1"}\n')
        return 0
    except BaseException as error:
        category = error.category if isinstance(error, WorkloadError) else "failed"
        try:
            os.write(2, b"completion host recovery failed: " + category.encode("ascii") + b"\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

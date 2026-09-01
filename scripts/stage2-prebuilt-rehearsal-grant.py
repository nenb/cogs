#!/usr/bin/env python3
"""Issue one fixed, non-cloud rehearsal grant for each real coordinator route."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

REMOTE = Path("/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote")
CONTROL_ROOT = Path("/var/lib/cogs/stage2-completion-v1/control")
CONTROL_PATH = CONTROL_ROOT / "stage2-local-static-control-v2.json"
GRANT_ROOT = Path("/var/lib/cogs/stage2-completion-v1/cycle-authority-v1")
GRANT_PATH = GRANT_ROOT / "grant.json"
POSITIVE = re.compile(r"[1-9][0-9]*")
sys.path.insert(0, str(REMOTE))
import completion_kata_preparation as preparation


class RehearsalGrantError(Exception):
    pass


def require(condition):
    if not condition:
        raise RehearsalGrantError()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def digest(domain, raw):
    return hashlib.sha256(domain + b"\0" + raw).hexdigest()


def read_fixed(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o400 and before.st_nlink == 1
                and 0 < before.st_size <= maximum)
        chunks, total = [], 0
        while total <= maximum:
            part = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                 item.st_gid, item.st_nlink, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        require(len(raw) == before.st_size and identity(before) == identity(after))
        return raw
    finally:
        os.close(descriptor)


def binding():
    control_raw = read_fixed(CONTROL_PATH, preparation.MAX_CONTROL_BYTES)
    control = preparation.load_control(control_raw)
    members = {}
    for row in control.value["members"]:
        members[row["name"]] = read_fixed(CONTROL_ROOT / row["name"], row["size"])
    envelope, _runtime, _contracts = preparation.validate_control_members(control, members)
    return {
        "implementation_revision": control.value["implementation"]["revision"],
        "control_revision": control.value["producer"]["control_revision"],
        "static_control_sha256": hashlib.sha256(control_raw).hexdigest(),
        "rootfs_descriptor_sha256": envelope.value["rootfs"]["prebuilt_descriptor_sha256"],
    }


def grant_value(route, run_id, fixed):
    require(route in {"full", "readiness"} and type(run_id) is str
            and POSITIVE.fullmatch(run_id) is not None and type(fixed) is dict
            and set(fixed) == {"implementation_revision", "control_revision",
                               "static_control_sha256", "rootfs_descriptor_sha256"})
    require(all(type(fixed[name]) is str and len(fixed[name]) == size
                and set(fixed[name]) <= set("0123456789abcdef")
                for name, size in (("implementation_revision", 40),
                                   ("control_revision", 40),
                                   ("static_control_sha256", 64),
                                   ("rootfs_descriptor_sha256", 64))))
    batch_input = canonical({"run_id": int(run_id), **fixed})
    fields = {
        "batch_commitment": digest(b"cogs.stage2-prebuilt-rehearsal-batch/v1", batch_input),
        "ordinal": 1 if route == "full" else 2,
        "mode": route,
        **fixed,
        "ami_commitment": digest(b"cogs.stage2-prebuilt-rehearsal-no-provider/v1", batch_input),
        "plan_sha256": digest(b"cogs.stage2-prebuilt-rehearsal-plan/v1",
                              batch_input + route.encode("ascii")),
    }
    fields["grant_commitment"] = digest(
        b"cogs.stage2-cycle-launch-grant/v1", canonical(fields)[:-1])
    return {"version": "cogs.stage2-cycle-launch-grant/v1", **fields}


def issue(route):
    require(os.geteuid() == 0 and sys.argv == [sys.argv[0], route]
            and not GRANT_ROOT.exists())
    value = grant_value(route, os.environ.get("COGS_STAGE2_REHEARSAL_RUN_ID", ""), binding())
    raw = canonical(value)
    GRANT_ROOT.mkdir(mode=0o700)
    os.chown(GRANT_ROOT, 0, 0)
    descriptor = os.open(GRANT_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            require(written > 0)
            view = view[written:]
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(GRANT_ROOT, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    output = f"cogs-stage2-{route}-rehearsal-grant-issued\n".encode("ascii")
    require(sys.stdout.buffer.write(output) == len(output))


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 2)
        issue(sys.argv[1])
    except (OSError, RehearsalGrantError, preparation.PreparationError):
        raise SystemExit(2)

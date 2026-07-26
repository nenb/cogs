#!/usr/bin/env python3
"""Observation-only invoker for the workflow-bound native Linux C1 gate."""

import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_FILE = ".github/workflows/ci.yml"
INVOKER_FILE = "test/aws-stage2-completion-rootfs-builder-native.py"
NATIVE_TEST_FILE = "test/aws-stage2-completion-rootfs-builder.py"
BUILDER_TEST = ROOT / NATIVE_TEST_FILE
SUDO = Path("/usr/bin/sudo")
PYTHON = Path("/usr/bin/python3")
NAMESPACES = ("pid", "mnt", "user", "cgroup")
EXPECTED_FIELDS = (
    "REPOSITORY", "WORKFLOW_FILE", "JOB", "EVENT", "ACTION", "RUN_ID", "RUN_ATTEMPT",
    "ENVELOPE_SHA", "EVENT_MERGE_SHA", "WORKFLOW_REF", "WORKFLOW_SHA", "BASE_SHA",
    "PR_NUMBER", "HEAD_REPOSITORY", "HEAD_SHA", "CHECKED_OUT_SHA", "WORKFLOW_BLOB_DIGEST",
)
GITHUB_FIELDS = (
    "CI", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS",
    "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_JOB",
    "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_SHA",
    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
)
PRESERVED_FIELDS = GITHUB_FIELDS + tuple(f"COGS_C1_EXPECTED_{name}" for name in EXPECTED_FIELDS)
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
DECIMAL_PATTERN = re.compile(r"[1-9][0-9]*")


def require(value, message):
    if not value:
        raise RuntimeError(f"native Linux C1 invoker: {message}")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def encoded(value):
    return base64.b64encode(canonical(value)).decode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def pairs(rows):
    value = {}
    for key, item in rows:
        require(key not in value, "duplicate event field")
        value[key] = item
    return value


def read_json(path):
    raw = path.read_bytes()
    require(0 < len(raw) <= 1_048_576, "missing or oversized event")
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _value: require(False, "event constant"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("native Linux C1 invoker: malformed event") from error


def git(*arguments, input_bytes=None):
    result = subprocess.run(
        ["/usr/bin/git", *arguments], cwd=ROOT, input=input_bytes, capture_output=True, check=False,
    )
    require(result.returncode == 0, f"git observation failed: {arguments[0]}")
    return result.stdout


def expected_values():
    values = {name.lower(): os.environ.get(f"COGS_C1_EXPECTED_{name}", "")
              for name in EXPECTED_FIELDS}
    require(all(values.values()), "missing expected workflow metadata")
    return values


def nested(value, *keys):
    for key in keys:
        require(type(value) is dict and key in value, "missing event observation")
        value = value[key]
    return value


def validate_revision_domains(envelope_sha, event_merge_sha, head_sha, base_sha, workflow_sha,
                              checked_out_sha):
    for name, value in (("envelope", envelope_sha), ("event merge", event_merge_sha)):
        require(SHA_PATTERN.fullmatch(value) is not None, f"malformed {name} revision")
        require(value not in {head_sha, base_sha},
                f"{name} revision collapsed into source domain")
    values = (head_sha, base_sha, workflow_sha, checked_out_sha)
    require(all(SHA_PATTERN.fullmatch(value) is not None for value in values),
            "malformed source or workflow revision domain")
    require(head_sha != base_sha, "head and base source revisions collapsed")
    require(checked_out_sha == head_sha, "checked-out source revision differs")
    require(workflow_sha in {envelope_sha, head_sha} and workflow_sha != base_sha,
            "workflow revision is outside the execution/source domains")


def validate_synthetic_context(envelope_sha, event_merge_sha, github_sha, event_payload_merge_sha):
    require(envelope_sha == github_sha, "envelope revision differs from GitHub SHA context")
    require(event_merge_sha == event_payload_merge_sha,
            "event merge revision differs from event payload context")


def workflow_observations():
    expected = expected_values()
    fixed = {
        "repository": "nenb/cogs", "workflow_file": WORKFLOW_FILE, "job": "quality",
        "event": "pull_request",
    }
    require(all(expected[name] == value for name, value in fixed.items()),
            "fixed workflow identity mismatch")
    require(expected["action"] in {"opened", "reopened", "synchronize"},
            "unexpected pull request action")
    for name in ("run_id", "run_attempt", "pr_number"):
        require(DECIMAL_PATTERN.fullmatch(expected[name]) is not None, f"malformed {name}")
    validate_revision_domains(
        expected["envelope_sha"], expected["event_merge_sha"], expected["head_sha"],
        expected["base_sha"], expected["workflow_sha"], expected["checked_out_sha"],
    )
    require(re.fullmatch(r"[0-9a-f]{64}", expected["workflow_blob_digest"]) is not None,
            "malformed workflow blob digest")
    require(expected["head_repository"] == expected["repository"],
            "pull request head repository mismatch")
    workflow_ref_pattern = re.escape(f'{expected["repository"]}/{WORKFLOW_FILE}@refs/') + r".+"
    require(re.fullmatch(workflow_ref_pattern, expected["workflow_ref"]) is not None,
            "workflow ref mismatch")

    fixed_environment = {
        "GITHUB_ACTIONS": "true", "CI": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24",
        "GITHUB_WORKFLOW": "CI", "GITHUB_JOB": "quality",
        "GITHUB_REPOSITORY": expected["repository"], "GITHUB_EVENT_NAME": expected["event"],
        "GITHUB_SHA": expected["envelope_sha"], "GITHUB_RUN_ID": expected["run_id"],
        "GITHUB_RUN_ATTEMPT": expected["run_attempt"],
        "GITHUB_WORKFLOW_REF": expected["workflow_ref"],
        "GITHUB_WORKFLOW_SHA": expected["workflow_sha"],
    }
    require(all(os.environ.get(name) == value for name, value in fixed_environment.items()),
            "GitHub runner observation mismatch")
    event_path = Path(os.environ.get("GITHUB_EVENT_PATH", ""))
    require(event_path.is_absolute() and event_path.is_file(), "event observation unavailable")
    event = read_json(event_path)
    event_pairs = {
        "action": nested(event, "action"), "pr_number": nested(event, "number"),
        "repository": nested(event, "repository", "full_name"),
        "event_merge_sha": nested(event, "pull_request", "merge_commit_sha"),
        "base_sha": nested(event, "pull_request", "base", "sha"),
        "head_repository": nested(event, "pull_request", "head", "repo", "full_name"),
        "head_sha": nested(event, "pull_request", "head", "sha"),
    }
    validate_synthetic_context(
        expected["envelope_sha"], expected["event_merge_sha"],
        os.environ.get("GITHUB_SHA", ""), str(event_pairs["event_merge_sha"]),
    )
    for name, value in event_pairs.items():
        require(str(value) == expected[name], f"event {name} mismatch")

    head = git("rev-parse", "--verify", "HEAD").decode().strip()
    require(head == expected["head_sha"], "checked-out HEAD mismatch")
    require(git("diff", "--quiet", "HEAD", "--") == b"", "tracked source changed after checkout")
    workflow_bytes = (ROOT / WORKFLOW_FILE).read_bytes()
    require(git("show", f"HEAD:{WORKFLOW_FILE}") == workflow_bytes,
            "workflow bytes differ from source head")
    file_hash = hashlib.sha256(workflow_bytes).digest()
    workflow_blob_digest = hashlib.sha256(file_hash).hexdigest()
    require(workflow_blob_digest == expected["workflow_blob_digest"],
            "reviewed workflow blob digest mismatch")

    source_files = (
        WORKFLOW_FILE, INVOKER_FILE, NATIVE_TEST_FILE,
        "deploy/aws-feasibility/remote/completion_rootfs_builder.py",
        "deploy/aws-feasibility/remote/completion_rootfs_fs.py",
        "deploy/aws-feasibility/remote/completion_rootfs_ledger.py",
    )
    blobs = {}
    for path in source_files:
        source_bytes = (ROOT / path).read_bytes()
        require(git("show", f"HEAD:{path}") == source_bytes, f"{path} differs from source head")
        blobs[path] = git("rev-parse", f"HEAD:{path}").decode().strip()
        require(SHA_PATTERN.fullmatch(blobs[path]) is not None, f"malformed blob for {path}")

    envelope = {
        "repository": expected["repository"], "workflow_file": expected["workflow_file"],
        "job": expected["job"], "event": expected["event"], "action": expected["action"],
        "run_id": expected["run_id"], "run_attempt": expected["run_attempt"],
        "envelope_sha": expected["envelope_sha"],
        "event_merge_sha": expected["event_merge_sha"],
        "workflow_ref": expected["workflow_ref"], "workflow_sha": expected["workflow_sha"],
        "base_sha": expected["base_sha"],
        "pull_request_number": expected["pr_number"],
    }
    source = {
        "head_repository": expected["head_repository"], "source_sha": expected["head_sha"],
        "checked_out_sha": head, "reviewed_implementation_sha": head,
        "workflow_source_sha": head, "invoker_source_sha": head,
        "native_test_source_sha": head,
        "workflow_blob_digest": expected["workflow_blob_digest"],
        "workflow_file_sha256": file_hash.hex(), "git_blobs": blobs,
    }
    require(all(envelope[name] not in {source["source_sha"], envelope["base_sha"]}
                for name in ("envelope_sha", "event_merge_sha")),
            "execution and source domains are not distinct")
    return {"execution_envelope": envelope, "source": source,
            "runner_environment": fixed_environment}


def mount_root(pid):
    rows = []
    for line in Path(f"/proc/{pid}/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[4] == "/" and "-" in fields:
            separator = fields.index("-")
            rows.append(fields[:6] + fields[separator + 1:separator + 4])
    require(len(rows) == 1, "ambiguous root mount")
    fields = rows[0]
    return {
        "mount_id": fields[0], "parent_id": fields[1], "major_minor": fields[2],
        "mount_root": fields[3], "mount_point": fields[4], "mount_options": fields[5],
        "fs_type": fields[6], "source_sha256": hashlib.sha256(fields[7].encode()).hexdigest(),
        "super_options": fields[8],
    }


def local_observations():
    """Collect namespace-local observations; these never establish host authority."""
    require(sys.platform == "linux", "Linux required")
    markers = ("/.dockerenv", "/.containerenv", "/run/.containerenv", "/run/systemd/container")
    require(not any(Path(path).exists() for path in markers), "container marker present")
    cgroups = Path("/proc/self/cgroup").read_bytes() + Path("/proc/1/cgroup").read_bytes()
    require(not any(token in cgroups.lower() for token in
                    (b"docker", b"kubepods", b"containerd", b"libpod", b"podman", b"lxc")),
            "container cgroup present")
    namespaces = {}
    for name in NAMESPACES:
        current = os.stat(f"/proc/self/ns/{name}")
        initial = os.stat(f"/proc/1/ns/{name}")
        namespaces[name] = [current.st_dev, current.st_ino]
        require(namespaces[name] == [initial.st_dev, initial.st_ino], f"nested {name} namespace")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    nspid = [int(value) for value in status.get("NSpid", "").split()]
    require(nspid == [os.getpid()], "nested or malformed PID namespace")
    require(Path("/proc/self/uid_map").read_text().split() == ["0", "0", "4294967295"],
            "non-initial user UID map")
    require(Path("/proc/self/gid_map").read_text().split() == ["0", "0", "4294967295"],
            "non-initial user GID map")
    root = os.stat("/")
    init_root = os.stat("/proc/1/root")
    require((root.st_dev, root.st_ino) == (init_root.st_dev, init_root.st_ino),
            "visible init does not share the observed root")
    own_mount = mount_root("self")
    require(own_mount == mount_root("1"), "visible init root mount differs")
    require(own_mount["mount_root"] == own_mount["mount_point"] == "/", "changed root")
    require(own_mount["fs_type"] not in {"overlay", "aufs", "fuse.lxcfs", "9p"},
            "container root filesystem")
    cgroup_mounts = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()
                     if " - cgroup2 " in line]
    require(len(cgroup_mounts) == 1 and cgroup_mounts[0][3] == "/", "non-root cgroup observation")
    kernel = os.uname()
    return {
        "classification": "observation-only", "version": 2, "namespaces": namespaces,
        "kernel": {"sysname": kernel.sysname, "release": kernel.release, "machine": kernel.machine},
        "nspid_depth": len(nspid), "root_identity": [root.st_dev, root.st_ino],
        "root_mount": own_mount,
        "cgroup2": [cgroup_mounts[0][0], cgroup_mounts[0][2], cgroup_mounts[0][3]],
    }


def privileged(expected_uid, expected_gid, expected_digest):
    require(os.geteuid() == 0 and expected_uid > 0 and expected_gid >= 0, "invalid privilege transition")
    sudo_uid, sudo_gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    sudo_user, sudo_command = os.environ.get("SUDO_USER"), os.environ.get("SUDO_COMMAND")
    require(sudo_uid is not None and sudo_gid is not None and sudo_user and sudo_command,
            "missing sudo provenance")
    require(int(sudo_uid) == expected_uid and int(sudo_gid) == expected_gid, "sudo caller mismatch")
    caller = pwd.getpwnam(sudo_user)
    require((caller.pw_uid, caller.pw_gid) == (expected_uid, expected_gid), "sudo account mismatch")
    require(str(PYTHON) in sudo_command and str(Path(__file__).resolve()) in sudo_command and
            expected_digest in sudo_command, "sudo command readback mismatch")
    raw = sys.stdin.buffer.read(32769)
    require(0 < len(raw) <= 32768, "missing or oversized invoker observations")
    try:
        parent = json.loads(base64.b64decode(raw, validate=True), object_pairs_hook=pairs,
                            parse_constant=lambda _value: require(False, "invoker constant"))
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("native Linux C1 invoker: malformed invoker observations") from error
    require(type(parent) is dict and digest(parent) == expected_digest,
            "invoker observations digest mismatch")
    child_workflow = workflow_observations()
    child_local = local_observations()
    require(parent == {"workflow": child_workflow, "local_values": child_local},
            "parent/child observations differ")
    result = subprocess.run(
        [str(PYTHON), str(BUILDER_TEST), "--native-linux-c1"], cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, text=True, capture_output=True,
        timeout=900, check=False,
    )
    require(result.returncode == 0, f"native route failed: {result.stderr[-1000:]}")
    try:
        native_test = json.loads(result.stdout.strip(), object_pairs_hook=pairs)
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("native Linux C1 invoker: malformed native test observation") from error
    source_sha = child_workflow["source"]["source_sha"]
    require(native_test == {
        "classification": "observation-only", "source_sha": source_sha,
        "observations": ["counter-3-2-0", "descriptor-continuity", "exact-baseline-recovery",
                         "uncertain-state-preservation"],
    }, "native test observation mismatch")
    print(json.dumps({
        "classification": "observation-only", "context": "workflow-bound-native-c1",
        **child_workflow, "local_values": child_local,
        "sudo": {"caller_uid": expected_uid, "parent_child_equal": True,
                 "provenance": "observed"},
        "native_test": native_test,
    }, sort_keys=True, separators=(",", ":")))


def invoke_workflow():
    require(os.geteuid() != 0 and os.getuid() == os.geteuid(),
            "must begin as an unprivileged caller")
    workflow = workflow_observations()
    local_values = local_observations()
    sudo_stat = SUDO.lstat()
    require(stat.S_ISREG(sudo_stat.st_mode) and sudo_stat.st_uid == sudo_stat.st_gid == 0,
            "sudo is not a root-owned regular file")
    require(sudo_stat.st_mode & 0o111 and not sudo_stat.st_mode & 0o022, "unsafe sudo mode")
    python_stat = PYTHON.stat()
    require(stat.S_ISREG(python_stat.st_mode) and python_stat.st_uid == python_stat.st_gid == 0 and
            python_stat.st_mode & 0o111 and not python_stat.st_mode & 0o022,
            "fixed system Python unavailable or unsafe")
    package = {"workflow": workflow, "local_values": local_values}
    package_digest = digest(package)
    preserve = "--preserve-env=" + ",".join(PRESERVED_FIELDS)
    command = [str(SUDO), "-n", preserve, "--", str(PYTHON), str(Path(__file__).resolve()),
               "--privileged", str(os.geteuid()), str(os.getegid()), package_digest]
    result = subprocess.run(command, cwd=ROOT, input=encoded(package), text=True, capture_output=True,
                            timeout=960, check=False)
    require(result.returncode == 0, f"sudo child failed: {result.stderr[-1000:]}")
    try:
        observation = json.loads(result.stdout.strip(), object_pairs_hook=pairs)
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("native Linux C1 invoker: malformed privileged observation") from error
    require(observation.get("classification") == "observation-only" and
            observation.get("execution_envelope") == workflow["execution_envelope"] and
            observation.get("source") == workflow["source"] and
            observation.get("local_values") == local_values and
            observation.get("sudo", {}).get("parent_child_equal") is True,
            "privileged observation readback mismatch")
    print(result.stdout, end="")


def portable_tests():
    envelope_sha, event_merge_sha = "a" * 40, "d" * 40
    source_sha, base_sha = "b" * 40, "c" * 40
    equal_values = (envelope_sha, envelope_sha, source_sha, base_sha, source_sha, source_sha)
    unequal_values = (envelope_sha, event_merge_sha, source_sha, base_sha, envelope_sha, source_sha)
    validate_revision_domains(*equal_values)
    validate_synthetic_context(envelope_sha, envelope_sha, envelope_sha, envelope_sha)
    validate_revision_domains(*unequal_values)
    validate_synthetic_context(envelope_sha, event_merge_sha, envelope_sha, event_merge_sha)

    def rejected_domains(*values):
        try:
            validate_revision_domains(*values)
        except RuntimeError:
            return
        raise AssertionError("invalid revision domains accepted")

    def rejected_context(*values):
        try:
            validate_synthetic_context(*values)
        except RuntimeError:
            return
        raise AssertionError("substituted synthetic context accepted")

    rejected_domains("", event_merge_sha, source_sha, base_sha, source_sha, source_sha)
    rejected_domains(envelope_sha, "", source_sha, base_sha, source_sha, source_sha)
    rejected_domains("A" * 40, event_merge_sha, source_sha, base_sha, source_sha, source_sha)
    rejected_domains(envelope_sha, "malformed", source_sha, base_sha, source_sha, source_sha)
    for collapsed in (source_sha, base_sha):
        rejected_domains(collapsed, event_merge_sha, source_sha, base_sha, source_sha, source_sha)
        rejected_domains(envelope_sha, collapsed, source_sha, base_sha, source_sha, source_sha)
    rejected_domains(envelope_sha, event_merge_sha, source_sha, source_sha, source_sha, source_sha)
    rejected_domains(envelope_sha, event_merge_sha, source_sha, base_sha, base_sha, source_sha)
    rejected_domains(envelope_sha, event_merge_sha, source_sha, base_sha, event_merge_sha,
                     source_sha)
    rejected_domains(envelope_sha, event_merge_sha, source_sha, base_sha, source_sha, base_sha)
    rejected_domains(envelope_sha, event_merge_sha, source_sha, base_sha, source_sha, envelope_sha)
    rejected_context(envelope_sha, event_merge_sha, "", event_merge_sha)
    rejected_context(envelope_sha, event_merge_sha, envelope_sha, "")
    rejected_context(envelope_sha, event_merge_sha, event_merge_sha, event_merge_sha)
    rejected_context(envelope_sha, event_merge_sha, envelope_sha, envelope_sha)
    rejected_context(envelope_sha, event_merge_sha, event_merge_sha, envelope_sha)
    rejected_context(envelope_sha, event_merge_sha, source_sha, event_merge_sha)
    rejected_context(envelope_sha, event_merge_sha, envelope_sha, base_sha)
    local = {"classification": "observation-only", "context": "unit-supplied"}
    require(local["classification"] == "observation-only", "local classification changed")
    print("native C1 envelope/source domain portable tests passed")


def local_manual():
    print(json.dumps({
        "classification": "observation-only", "context": "local-manual",
        "local_values": {"classification": "observation-only", "status": "not-collected"},
        "workflow_authority": "unavailable",
    }, sort_keys=True, separators=(",", ":")))


if sys.argv == [sys.argv[0]]:
    local_manual()
elif sys.argv == [sys.argv[0], "--workflow-bound"]:
    invoke_workflow()
elif sys.argv == [sys.argv[0], "--portable-tests"]:
    portable_tests()
elif len(sys.argv) == 5 and sys.argv[1] == "--privileged":
    privileged(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
else:
    raise SystemExit("usage: aws-stage2-completion-rootfs-builder-native.py [--workflow-bound|--portable-tests]")

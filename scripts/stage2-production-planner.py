#!/usr/bin/env python3
"""Fixed read-only AWS/OpenTofu producer for seven production plan bytes.

This module is inert on import. Its CLI is reserved for the separately authorized
planning workflow; ordinary tests inspect it or use fake subprocess seams only.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import runpy
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time

_DIAGNOSTIC = b"stage2-production-planner: owner.failed\n"


def _fail():
    try: os.write(2, _DIAGNOSTIC)
    except BaseException: pass
    raise SystemExit(2) from None


try:
    ROOT = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
    import completion_campaign_production as production
    retirement = runpy.run_path(str(ROOT / "scripts/stage2-revision-retirement.py"))
except BaseException:
    if __name__ == "__main__": _fail()
    raise

AWS = Path("/usr/local/bin/aws")
TOFU_SHA256 = "e11e783ab8ee0a029da32c2ab1817952121208d0ae9d6cf2d91fa0687f573a88"
MAX = 32 * 1024 * 1024
PACKAGE_MAX_FILES = 64
PACKAGE_MAX_BYTES = 1024 * 1024 * 1024
PACKAGE_PREFIX = "registry.opentofu.org/hashicorp/aws/6.54.0/linux_amd64"
PACKAGE_MANIFEST = "provider-package.json"
PACKAGE_ARCHIVE = "provider-package.tar"
PACKAGE_ARCHIVE_DIGEST = "provider-package.tar.sha256"


class PlanningError(Exception): pass


def require(value):
    if not value: raise PlanningError()


def eligible(revisions, runs=(), artifacts=()):
    try:
        retirement["select"](tuple(revisions), runs=tuple(str(value) for value in runs),
                             artifacts=tuple(str(value) for value in artifacts))
    except (TypeError, ValueError) as error: raise PlanningError() from error


def package_eligible(package, expected=()):
    try: production.qualification_source_bindings(package)
    except production.ProductionCampaignError as error: raise PlanningError() from error
    revisions = tuple(package[name] for name in (
        "implementation_revision", "control_revision", "qualification_revision"))
    require(not expected or tuple(expected) == revisions)


def pairs(rows):
    value = {}
    for key, item in rows:
        require(type(key) is str and key not in value); value[key] = item
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def _read_regular(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= maximum)
        chunks, total = [], 0
        while total <= maximum:
            part = os.read(descriptor, min(65536, maximum + 1 - total))
            if not part: break
            chunks.append(part); total += len(part)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                 item.st_gid, item.st_nlink, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        raw = b"".join(chunks)
        require(len(raw) == before.st_size and identity(before) == identity(after))
        return raw
    finally: os.close(descriptor)


def read(path, maximum=MAX):
    raw = _read_regular(path, maximum)
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise PlanningError() from error
    require(type(value) is dict and canonical(value) == raw)
    return raw, value


def eligibility(path, expected=()):
    _raw, package = read(path)
    package_eligible(package, expected)


def provider_package(root):
    """Return the complete, ordinary provider package as a bounded manifest."""
    root = Path(root)
    seen, files, total = set(), [], 0
    def visit(directory, prefix=""):
        nonlocal total
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not directory.is_symlink()
                and stat.S_IMODE(info.st_mode) <= 0o755)
        for entry in sorted(directory.iterdir(), key=lambda path: path.name):
            name = prefix + entry.name
            require(name not in seen and "/" not in entry.name and entry.name not in {"", ".", ".."})
            seen.add(name); info = entry.lstat()
            require(info.st_nlink == 1 and not entry.is_symlink())
            require(not stat.S_ISDIR(info.st_mode))
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= PACKAGE_MAX_BYTES)
            raw = _read_regular(entry, PACKAGE_MAX_BYTES)
            total += len(raw); require(len(files) < PACKAGE_MAX_FILES and total <= PACKAGE_MAX_BYTES)
            files.append({"name": name, "mode": stat.S_IMODE(info.st_mode),
                          "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    visit(root)
    executable = [row for row in files if row["name"].startswith("terraform-provider-aws")
                  and row["mode"] & 0o111]
    require(len(executable) == 1 and len(files) >= 2)
    return {"version": "cogs.stage2-opentofu-provider-package/v1",
            "prefix": PACKAGE_PREFIX, "root_mode": stat.S_IMODE(root.lstat().st_mode),
            "file_count": len(files), "total_bytes": total, "files": files,
            "provider_path": executable[0]["name"], "provider_binary_sha256": executable[0]["sha256"]}


def copy_provider_package(source, destination, manifest):
    require(provider_package(source) == manifest and not destination.exists())
    destination.mkdir(mode=manifest["root_mode"])
    for row in manifest["files"]:
        target = destination / row["name"]
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        raw = _read_regular(source / row["name"], PACKAGE_MAX_BYTES)
        require(len(raw) == row["size"] and hashlib.sha256(raw).hexdigest() == row["sha256"])
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, row["mode"])
        try: require(os.write(fd, raw) == len(raw)); os.fsync(fd)
        finally: os.close(fd)
        os.chmod(target, row["mode"])
    require(provider_package(destination) == manifest)


def _bounded_process(arguments, timeout, environment):
    handled = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set(handled))
    previous_handlers = {}
    process, selector, unblocked = None, None, False
    interrupted_state = [False]
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    def interrupted(_number, _frame):
        interrupted_state[0] = True
        if process is not None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
    try:
        for number in handled: previous_handlers[number] = signal.signal(number, interrupted)
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=ROOT / "deploy/aws-feasibility", env=environment,
            close_fds=True, start_new_session=True)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask); unblocked = True
        selector = selectors.DefaultSelector()
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            require(stream is not None); selector.register(stream, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise subprocess.TimeoutExpired(arguments, timeout)
            events = selector.select(remaining)
            if not events: raise subprocess.TimeoutExpired(arguments, timeout)
            for key, _mask in events:
                part = os.read(key.fd, 65536)
                if not part: selector.unregister(key.fileobj); continue
                buffers[key.data].extend(part)
                require(len(buffers["stdout"]) <= MAX and len(buffers["stderr"]) <= 65536)
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if interrupted_state[0]: raise PlanningError()
        try: os.killpg(process.pid, 0)
        except ProcessLookupError: pass
        else: raise PlanningError()
        return bytes(buffers["stdout"]), bytes(buffers["stderr"]), returncode
    except BaseException:
        signal.pthread_sigmask(signal.SIG_BLOCK, set(handled))
        for number in previous_handlers: signal.signal(number, signal.SIG_IGN)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask); unblocked = True
        if process is not None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=10)
            settlement_deadline = time.monotonic() + 5
            while True:
                try: os.killpg(process.pid, 0)
                except ProcessLookupError: break
                if time.monotonic() >= settlement_deadline: raise PlanningError()
                time.sleep(0.01)
        raise
    finally:
        if selector is not None: selector.close()
        if not unblocked: signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        for number, handler in previous_handlers.items(): signal.signal(number, handler)
        if interrupted_state[0]: raise PlanningError()


def run(arguments, timeout, environment, parse=False):
    raw_output, stderr, returncode = _bounded_process(arguments, timeout, environment)
    require(returncode == 0 and not stderr)
    if not parse: return raw_output
    raw = raw_output if raw_output.endswith(b"\n") else raw_output + b"\n"
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise PlanningError() from error
    require(type(value) is dict); return value


def cycle_paths(plans, ordinal):
    """Allocate one non-reusable local-backend namespace for a staged cycle."""
    require(type(ordinal) is int and 1 <= ordinal <= 7)
    prefix = f"{ordinal:02d}"
    paths = {
        "tf_data_dir": plans / f"{prefix}.tf-data",
        "state_path": plans / f"{prefix}.terraform.tfstate",
        "plan_path": plans / f"{prefix}.tfplan",
        "plan_json_path": plans / f"{prefix}.plan.json",
        "stage_path": plans / f"{prefix}.staged-plan.json",
        "variables_path": plans / f"{prefix}.tfvars.json",
    }
    # A planning output is single-attempt custody.  No old local cache, state,
    # plan, or path-binding receipt can be adopted by a different cycle.
    require(all(not path.exists() and not path.is_symlink() for path in paths.values()))
    paths["tf_data_dir"].mkdir(mode=0o700)
    return paths


def stage_plan(paths, ordinal, batch, plan, shown):
    require(plan == paths["plan_path"] and paths["tf_data_dir"].is_dir()
            and paths["state_path"].parent == plan.parent
            and plan.is_file() and paths["plan_json_path"].is_file())
    value = {
        "version": "cogs.stage2-local-staged-plan/v1",
        "ordinal": ordinal, "batch_commitment": batch,
        "tf_data_dir": paths["tf_data_dir"].name,
        "state_path": paths["state_path"].name,
        "plan_path": plan.name, "plan_json_path": paths["plan_json_path"].name,
        "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "plan_json_sha256": hashlib.sha256(canonical(shown)).hexdigest(),
    }
    value["path_identity"] = hashlib.sha256(
        b"cogs.stage2-local-plan-path/v1\0" + canonical(value)[:-1]).hexdigest()
    raw = canonical(value)
    fd = os.open(paths["stage_path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try: require(os.write(fd, raw) == len(raw)); os.fsync(fd)
    finally: os.close(fd)
    require(read(paths["stage_path"])[1] == value)
    return value


def main(arguments):
    require(len(arguments) == 5 and os.environ.get("COGS_STAGE2_AWS_PLAN_AUTHORIZATION") ==
            "authorize-read-only-stage2-production-planning")
    package_raw, package = read(arguments[0]); control_raw, control = read(arguments[1])
    descriptor_raw, descriptor = read(arguments[2], 8192)
    tofu = Path(arguments[3]); output = Path(arguments[4])
    require(package.get("version") == "cogs.stage2-pre-aws-qualification-package/v5"
            and package.get("authority") == "non-aws-prerequisite-evidence-only"
            and package.get("cycle_count") == 7 and package.get("workload_measurements") == 21
            and package.get("claims", {}).get("formal_non_aws_qualification_passed") is True
            and package.get("claims", {}).get("aws_authorized") is False
            and package.get("claims", {}).get("provider_executed") is False
            and package.get("claims", {}).get("aws_executed") is False
            and package.get("claims", {}).get("promotion_authorized") is False
            and control.get("version") == "cogs.stage2-local-static-control-package/v2"
            and descriptor.get("version") == "cogs.stage2-prebuilt-rootfs-descriptor/v1")
    package_eligible(package)
    bindings = package["source_bindings"]; producer = descriptor["producer"]
    # The immutable runtime member is authenticated by the exact control bytes,
    # never by a local execution mapping or qualification QEMU identity.
    runtime_members = [row for row in control.get("members", ())
                       if type(row) is dict and row.get("kind") == "runtime-manifest"]
    require(len(runtime_members) == 1
            and runtime_members[0].get("name") == "stage2-local-runtime-manifest-v3.json"
            and runtime_members[0].get("sha256") == bindings["runtime_manifest_sha256"])
    require(re.fullmatch(r"[0-9a-f]{40}", package["qualification_revision"]) is not None
            and bindings["rootfs_descriptor_sha256"] == hashlib.sha256(descriptor_raw).hexdigest()
            and producer["revision"] == package["implementation_revision"] == bindings["source_head"]
            and control.get("producer", {}).get("control_revision") == package["control_revision"]
            and producer["source_manifest_sha256"] == bindings["source_manifest_sha256"]
            and producer["package_manifest_sha256"] == bindings["rootfs_package_manifest_sha256"]
            and producer["provenance_sha256"] == bindings["rootfs_provenance_sha256"]
            and producer["publication_receipt_sha256"] ==
                bindings["rootfs_publication_receipt_sha256"]
            and package["source_manifest_sha256"] == bindings["source_manifest_sha256"]
            and package["static_control_sha256"] == hashlib.sha256(control_raw).hexdigest()
            and package["rootfs_descriptor_sha256"] == hashlib.sha256(descriptor_raw).hexdigest()
            and package["cycle_artifact_custody"]["workflow_run"]["head_sha"] ==
                package["qualification_revision"]
            and type(package["static_control_observation"]["run_id"]) is int
            and package["static_control_observation"]["run_id"] > 0
            and type(package["static_control_observation"]["artifact_id"]) is int
            and package["static_control_observation"]["artifact_id"] > 0
            and re.fullmatch(r"sha256:[0-9a-f]{64}", package["static_control_observation"]
                             ["artifact_archive_digest"]) is not None)
    require(hashlib.sha256(tofu.read_bytes()).hexdigest() == TOFU_SHA256)
    environment = {key: os.environ[key] for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN")}
    environment.update({"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
        "PATH": "/usr/local/bin:/usr/bin:/bin", "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-east-1", "AWS_PAGER": "",
        "AWS_EC2_METADATA_DISABLED": "true", "TF_IN_AUTOMATION": "1"})
    aws_path = AWS.resolve(); aws_before = aws_path.stat()
    aws_sha256 = hashlib.sha256(aws_path.read_bytes()).hexdigest()
    caller = run((str(AWS), "--region", "us-east-1", "sts", "get-caller-identity",
        "--output", "json", "--no-cli-pager"), 60, environment, True)
    account = caller.get("Account"); arn = caller.get("Arn")
    require(type(account) is str and re.fullmatch(r"[0-9]{12}", account) is not None
            and type(arn) is str)
    match = re.fullmatch(r"arn:aws:sts::[0-9]{12}:assumed-role/([^/]+)/[^/]+", arn)
    require(match is not None)
    role = os.environ.get("COGS_STAGE2_EXECUTOR_ROLE_NAME", "")
    observer_role = os.environ.get("COGS_STAGE2_INVENTORY_OBSERVER_ROLE_NAME", "")
    require(re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role) is not None
            and re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", observer_role) is not None
            and len({role, observer_role, match.group(1)}) == 3)
    images = run((str(AWS), "--region", "us-east-1", "ec2", "describe-images",
        "--owners", "099720109477", "--filters",
        "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*",
        "Name=state,Values=available", "Name=architecture,Values=x86_64",
        "Name=virtualization-type,Values=hvm", "Name=root-device-type,Values=ebs",
        "--output", "json", "--no-cli-pager"), 120, environment, True).get("Images")
    require(type(images) is list and images)
    image = sorted(images, key=lambda row: (row.get("CreationDate", ""), row.get("ImageId", "")))[-1]
    aws_after = aws_path.stat()
    require((aws_before.st_dev, aws_before.st_ino, aws_before.st_size,
             aws_before.st_mtime_ns, aws_before.st_ctime_ns) ==
            (aws_after.st_dev, aws_after.st_ino, aws_after.st_size,
             aws_after.st_mtime_ns, aws_after.st_ctime_ns)
            and hashlib.sha256(aws_path.read_bytes()).hexdigest() == aws_sha256)
    require(type(image.get("ImageId")) is str
            and re.fullmatch(r"ami-[0-9a-f]{17}", image["ImageId"]) is not None
            and image.get("OwnerId") == "099720109477"
            and image.get("Architecture") == "x86_64"
            and image.get("VirtualizationType") == "hvm"
            and image.get("RootDeviceType") == "ebs" and image.get("State") == "available")
    now = time.time_ns()
    draft = {
        "version": "cogs.stage2-production-approval-draft/v3",
        "implementation_revision": bindings["source_head"],
        "control_revision": package["control_revision"],
        "qualification_revision": package["qualification_revision"],
        "source_manifest_sha256": bindings["source_manifest_sha256"],
        "source_bindings_sha256": production._commit(
            b"cogs.stage2-source-bindings/v1", bindings),
        "static_control_sha256": package["static_control_sha256"],
        "pre_aws_package_sha256": hashlib.sha256(package_raw).hexdigest(),
        "rootfs_descriptor_sha256": bindings["rootfs_descriptor_sha256"],
        "rootfs_package_manifest_sha256": producer["package_manifest_sha256"],
        "rootfs_provenance_sha256": producer["provenance_sha256"],
        "rootfs_qualification_receipt_sha256": producer["qualification_receipt_sha256"],
        "rootfs_publication_receipt_sha256": producer["publication_receipt_sha256"],
        "runtime_manifest_sha256": bindings["runtime_manifest_sha256"],
        "fixture_commitment": bindings["final_pin_sha256"],
        "account_commitment": hashlib.sha256(account.encode()).hexdigest(),
        "partition": "aws", "region": "us-east-1", "ami_id": image["ImageId"],
        "ami_owner_id": image["OwnerId"], "ami_architecture": image["Architecture"],
        "ami_virtualization_type": image["VirtualizationType"],
        "ami_root_device_type": image["RootDeviceType"], "ami_state": image["State"],
        "not_before_unix_ns": now, "effect_deadline_ns": 220 * 60 * 10**9,
        "cleanup_reserve_ns": 25 * 60 * 10**9, "expires_unix_ns": now + 7 * 60 * 60 * 10**9,
        "maximum_cycle_duration_ns": 150 * 60 * 10**9,
        "maximum_cost_micro_usd": 499_999,
        "executor_principal_commitment": production.executor_principal_commitment("aws", account, role),
        "inventory_observer_principal_commitment":
            production.executor_principal_commitment("aws", account, observer_role),
    }
    draft["ami_commitment"] = production.resolved_ami_commitment(draft)
    email = os.environ.get("COGS_STAGE2_BUDGET_ALERT_EMAIL", "")
    require(3 <= len(email) <= 254 and "@" in email and "\n" not in email)
    require(not output.exists() and not output.is_symlink())
    output.mkdir(mode=0o700); plans = output / "plans"; plans.mkdir(mode=0o700)
    package_output = output / production.QUALIFICATION_PACKAGE_NAME
    fd = os.open(package_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream: stream.write(package_raw)
    credentials = output / ".aws-credentials"
    credentials.write_text("[nebula]\naws_access_key_id = " + environment["AWS_ACCESS_KEY_ID"] +
        "\naws_secret_access_key = " + environment["AWS_SECRET_ACCESS_KEY"] +
        "\naws_session_token = " + environment["AWS_SESSION_TOKEN"] + "\n")
    config = output / ".aws-config"; config.write_text("[profile nebula]\nregion = us-east-1\noutput = json\n")
    os.chmod(credentials, 0o600); os.chmod(config, 0o600)
    environment.update({"AWS_SHARED_CREDENTIALS_FILE": str(credentials),
                        "AWS_CONFIG_FILE": str(config), "AWS_PROFILE": "nebula"})
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        environment.pop(name)
    # Provider installation is local-only.  It has an explicit disposable local
    # backend too; no plan cycle can inherit this bootstrap cache.
    bootstrap_data, bootstrap_state = plans / ".provider-tf-data", plans / ".provider.tfstate"
    require(not bootstrap_data.exists() and not bootstrap_state.exists())
    bootstrap_data.mkdir(mode=0o700)
    run((str(tofu), "init", "-input=false", "-lockfile=readonly",
         "-backend-config=path=" + str(bootstrap_state)), 300,
        {**environment, "TF_DATA_DIR": str(bootstrap_data)})
    provider_root = bootstrap_data / "providers" / PACKAGE_PREFIX
    provider_manifest = provider_package(provider_root)
    provider_raw = _read_regular(provider_root / provider_manifest["provider_path"], PACKAGE_MAX_BYTES)
    require(hashlib.sha256(provider_raw).hexdigest() == provider_manifest["provider_binary_sha256"])
    draft["provider_binary_sha256"] = provider_manifest["provider_binary_sha256"]
    draft["aws_cli_sha256"] = aws_sha256
    batch = production.approval_batch_commitment(draft)
    hashes = []
    for ordinal in range(1, 8):
        paths = cycle_paths(plans, ordinal)
        variables = {"aws_profile": "nebula", "aws_region": "us-east-1",
            "ami_id": image["ImageId"], "ami_owner_id": image["OwnerId"],
            "ami_commitment": draft["ami_commitment"], "batch_commitment": batch,
            "cycle_ordinal": ordinal, "source_revision": bindings["source_head"],
            "control_revision": package["control_revision"],
            "rootfs_descriptor_sha256": bindings["rootfs_descriptor_sha256"],
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(draft["expires_unix_ns"] // 10**9)),
            "budget_alert_email": email, "account_id_sha256": draft["account_commitment"]}
        paths["variables_path"].write_bytes(canonical(variables))
        local_environment = {**environment, "TF_DATA_DIR": str(paths["tf_data_dir"])}
        run((str(tofu), "init", "-input=false", "-lockfile=readonly",
             "-backend-config=path=" + str(paths["state_path"])), 300, local_environment)
        # The exact state path is passed to plan as well as the explicit local
        # backend, so a changed backend configuration cannot silently redirect it.
        run((str(tofu), "plan", "-input=false", "-lock=false", "-refresh=true",
            "-state=" + str(paths["state_path"]), "-var-file=" + str(paths["variables_path"]),
            "-out=" + str(paths["plan_path"])), 900, local_environment)
        shown = run((str(tofu), "show", "-json", str(paths["plan_path"])), 120, local_environment, True)
        fd = os.open(paths["plan_json_path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            rendered = canonical(shown); require(os.write(fd, rendered) == len(rendered)); os.fsync(fd)
        finally: os.close(fd)
        paths["variables_path"].unlink()
        run(("/usr/bin/python3", str(ROOT / "deploy/aws-feasibility/check-plan.py"),
             str(paths["plan_json_path"])), 30, local_environment)
        staged = stage_plan(paths, ordinal, batch, paths["plan_path"], shown)
        require(staged["plan_sha256"] == hashlib.sha256(paths["plan_path"].read_bytes()).hexdigest())
        hashes.append(staged["plan_sha256"])
    credentials.unlink(); config.unlink()
    draft["plan_sha256s"] = hashes
    # The bootstrap cache and its local state are never staged as plan inputs.
    require(not bootstrap_state.exists())
    (output / "approval-draft.json").write_bytes(canonical(draft))
    (output / "tofu").write_bytes(tofu.read_bytes()); os.chmod(output / "tofu", 0o555)
    (output / PACKAGE_MANIFEST).write_bytes(canonical(provider_manifest))
    # Artifact services do not preserve executable modes for unpacked files.  The
    # ordinary provider closure therefore crosses every workflow boundary only
    # in this mode-bearing archive, accompanied by its exact byte digest.
    package_output = output / "provider-package"
    copy_provider_package(provider_root, package_output, provider_manifest)
    archive_path = output / PACKAGE_ARCHIVE
    with tarfile.open(archive_path, "x") as archive:
        archive.add(package_output, arcname="provider-package", recursive=False)
        for row in provider_manifest["files"]:
            archive.add(package_output / row["name"], arcname="provider-package/" + row["name"], recursive=False)
    archive_digest = "sha256:" + hashlib.sha256(_read_regular(archive_path, PACKAGE_MAX_BYTES)).hexdigest()
    (output / PACKAGE_ARCHIVE_DIGEST).write_text(archive_digest + "\n", encoding="ascii")
    for path in package_output.iterdir(): path.unlink()
    package_output.rmdir()


if __name__ == "__main__":
    try:
        if len(sys.argv) == 6 and sys.argv[1] == "eligibility": eligibility(sys.argv[2], sys.argv[3:])
        else: main(sys.argv[1:])
    except BaseException: _fail()

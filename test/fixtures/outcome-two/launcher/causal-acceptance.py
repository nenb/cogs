# Portable causal acceptance owners loaded by the trusted-launcher suite.
# This is executable test-fixture code, never a production or native entry.

def common_fixed_cli_contract(module, job):
    """Run common's actual fixed CLI issuer into an exact real bootstrap owner."""
    if job not in ("A", "B", "E", "integration"):
        raise AssertionError("unsupported portable fixed CLI profile")
    common = load_path(f"outcome_two_native_common_{job}", COMMON)
    mapped = load_path(f"outcome_two_mapped_owner_model_{job}", ROOT / "test/outcome-two-mapped-closure-portable.py")
    head = __import__("subprocess").check_output(
        ("/usr/bin/git", "rev-parse", "HEAD"), cwd=ROOT,
    ).decode("ascii").strip()
    driver = ROOT / "scripts/native-qualification" / common.DRIVERS[job]
    schema = common.SCHEMA.read_bytes()
    digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    context = common.WorkflowContext(
        job, "owner/repo", "owner/repo", head, head, head, head, "0" * 40,
        common.JOB_IDS[job], 1, 1, 1, "portable", "6.8.0-portable", "x86_64",
        digest(common.WORKFLOW), digest(driver), digest(common.COMMON),
        hashlib.sha256(schema).hexdigest(), schema,
    )
    registry = common.FdRegistry()
    issuer = common.SystemCommonOps(registry)
    real_open, real_close, real_read, real_write = os.open, os.close, os.read, os.write
    real_lseek, real_dup, real_exit, real_waitpid, real_fork = os.lseek, os.dup, os._exit, os.waitpid, os.fork
    real_fcntl = fcntl.fcntl
    sealed = set()

    def memfd_create(name, flags=0):
        del flags
        descriptor, path = tempfile.mkstemp(prefix=f"{name}-")
        os.unlink(path)
        return descriptor

    def portable_fcntl(fd, command, *arguments):
        if command == fcntl.F_ADD_SEALS:
            sealed.add(fd)
            return 0
        if command == fcntl.F_GET_SEALS:
            return 0x1f if fd in sealed or fd in (3, 4) else 0
        return real_fcntl(fd, command, *arguments)

    def bootstrap_exec(path, argv, environment):
        marker_fd = real_open(f"/tmp/cogs-cli-{job}.debug", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        real_write(marker_fd, b"entered\n")
        real_close(marker_fd)
        if path != "/usr/bin/python3" or tuple(argv) != ("/usr/bin/python3", "-I", "-B", "-") or environment:
            real_exit(126)
        try:
            real_lseek(0, 0, os.SEEK_SET)
            raw = bytearray()
            while True:
                part = real_read(0, 65536)
                if not part:
                    break
                raw.extend(part)
            expected_launcher = (ROOT / module._MODULE_PATHS[2]).read_bytes()
            if bytes(raw) != expected_launcher:
                raise AssertionError(
                    f"held launcher bytes drift: {len(raw)}/{len(expected_launcher)} "
                    f"{hashlib.sha256(raw).hexdigest()}/{hashlib.sha256(expected_launcher).hexdigest()}"
                )
            held = types.ModuleType("causal_held_launcher")
            held.__file__ = "cogs-held:common-fixed-cli"
            exec(compile(bytes(raw), held.__file__, "exec", dont_inherit=True, optimize=0), held.__dict__)
            owner_ops = mapped.MappingOwnerOps("complete")
            if job == "E":
                expected_sources = {
                    logical: (ROOT / logical).read_bytes()
                    for logical in held._FIXED_SOURCE_SET
                }
                expected_rows = [
                    {"path": logical, "sha256": hashlib.sha256(expected_sources[logical]).hexdigest(), "size": len(expected_sources[logical])}
                    for logical in held._FIXED_SOURCE_SET
                ]
                root_authority = {
                    "bootstrap_sha256": hashlib.sha256(expected_sources[held._MODULE_PATHS[2]]).hexdigest(),
                    "revision": head,
                    "root_bootstrap_sha256": hashlib.sha256(held._ROOT_BOOTSTRAP.encode()).hexdigest(),
                    "source_set_sha256": held._source_set_digest(expected_sources),
                    "sources": expected_rows,
                    "version": "cogs.root-capsule-authority/v1",
                }
                def admitted_root_run(ops, capsule):
                    decoded, header = held._decode_root_capsule(capsule, root_authority)
                    if decoded != expected_sources or header["revision"] != head:
                        raise AssertionError("fixed root authority did not hold exact admitted bytes")
                    output, _events = execute_root_entry_model(held, capsule, root_authority)
                    return output
                held._run_root_capsule_with_ops = admitted_root_run
            load_closure = held._load_private_closure
            retained_models = []
            def modeled_closure(sources, source_digest):
                closure_module = load_closure(sources, source_digest)
                if job == "A":
                    closure_module._Ops = lambda: owner_ops
                    return closure_module
                bundle_directory = tempfile.mkdtemp(prefix="cogs-cli-bundle-")
                root_parent = tempfile.mkdtemp(prefix="cogs-cli-root-")
                retained_models.extend((bundle_directory, root_parent))
                report_bytes, descriptors, rows = valid_bundle(held, bundle_directory)
                report = held._decode_report(report_bytes)
                duplicated = tuple(_BIos.dup(fd) for fd in descriptors)
                for fd in descriptors:
                    _BIos.close(fd)
                kernel = _BIKernel(
                    held, report, report_bytes, duplicated, rows,
                    f"{root_parent}/{held._ROOT_LEAF}", admission_revision=head,
                    admission_source_set=source_digest,
                )
                held._ROOT_PARENT = root_parent
                actual_child_fcntl = held.fcntl.fcntl
                def modeled_fcntl(fd, command, *arguments):
                    if fd in duplicated and command == held._F_GET_SEALS:
                        return held._DATA_SEALS if fd == duplicated[0] else held._EXEC_SEALS
                    if fd in duplicated and command == _BIfcntl.F_GETFL:
                        return _BIos.O_RDONLY
                    return actual_child_fcntl(fd, command, *arguments)
                bootstrap_ops.runtime = kernel
                held._SystemOps = lambda: kernel
                held.os.open = kernel.open
                held.os.close = kernel.close
                held.os.read = kernel.read
                held.os.write = kernel.write
                held.os.pipe2 = kernel.pipe2
                held.os.fstat = kernel.fstat
                held.os.stat = kernel.stat
                held.os.pread = kernel.pread
                held.os.getpid = lambda: kernel.outer
                held.os.getppid = lambda: 1
                held.os.pidfd_open = kernel.pidfd_open
                held.os.getsid = kernel.getsid
                held.os.getpgid = kernel.getpgid
                held.os.waitpid = kernel.waitpid
                held.fcntl.fcntl = modeled_fcntl
                held.fcntl.ioctl = kernel.ioctl
                held.signal.pidfd_send_signal = kernel.pidfd_signal
                held.select.select = kernel.select
                held.os.path.lexists = kernel.lexists
                held.os.path.ismount = kernel.ismount
                return closure_module
            class BootstrapCloseOps:
                runtime = None
                def close(self, fd):
                    if self.runtime is None:
                        real_close(fd)
                    else:
                        self.runtime.close(fd)
                def __getattr__(self, name):
                    if self.runtime is None:
                        raise AttributeError(name)
                    return getattr(self.runtime, name)
            bootstrap_ops = BootstrapCloseOps()
            def bootstrap_open(selected, flags, mode=0o600, **kwargs):
                if selected in ("/proc/self/exe", "/usr/bin/python3"):
                    return real_dup(3)
                return real_open(selected, flags, mode, **kwargs)
            saved_environment, saved_argv = dict(os.environ), sys.argv[:]
            os.environ.clear()
            sys.argv[:] = ["-"]
            exact_descriptor_snapshot = held._descriptor_snapshot
            bootstrap_snapshots = 0
            def bootstrap_descriptor_snapshot(ops=None, pid="self"):
                nonlocal bootstrap_snapshots
                bootstrap_snapshots += 1
                if bootstrap_snapshots == 1:
                    return (0, 1, 2, 3, 4)
                return exact_descriptor_snapshot(ops, pid)
            try:
                with patched(
                    held,
                    _platform_gate=lambda: None,
                    _descriptor_snapshot=bootstrap_descriptor_snapshot,
                    _load_private_closure=modeled_closure,
                ), patched(held.os, open=bootstrap_open), patched(held.fcntl, fcntl=portable_fcntl):
                    status = held._bootstrap_with_ops(bootstrap_ops)
            finally:
                os.environ.update(saved_environment)
                sys.argv[:] = saved_argv
            real_exit(status)
        except BaseException as error:
            parts = []
            pending = [error]
            while pending:
                item = pending.pop(0)
                parts.append(type(item).__name__ + ": " + repr(item))
                pending.extend(getattr(item, "failures", ()))
                cause = getattr(item, "__cause__", None)
                if cause is not None and cause not in pending:
                    pending.append(cause)
            diagnostic = "\n".join(parts).encode("utf-8", "replace")
            try:
                real_write(2, diagnostic[:65536])
                debug_fd = real_open(f"/tmp/cogs-cli-{job}.debug", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                real_write(debug_fd, diagnostic[:65536])
                real_close(debug_fd)
            except BaseException:
                pass
            real_exit(124)

    def pidfd_open(pid, flags=0):
        del pid, flags
        return real_open("/dev/null", os.O_RDONLY)

    def portable_git_tree(_self, root, revision, paths):
        del root
        raw = __import__("subprocess").check_output(
            ("/usr/bin/git", "ls-tree", "-z", revision, "--", *paths), cwd=ROOT,
        )
        rows = {}
        for record in raw.split(b"\0"):
            if not record:
                continue
            header, path = record.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            if mode != "100644" or kind != "blob":
                raise AssertionError("portable held Git row")
            rows[path.decode()] = oid
        if set(rows) != set(paths):
            raise AssertionError("portable held Git cardinality")
        return rows

    builtins = __import__("builtins")
    remove_group = not hasattr(builtins, "ExceptionGroup")
    remove_base_group = not hasattr(builtins, "BaseExceptionGroup")
    class PortableExceptionGroup(Exception):
        def __init__(self, message, failures):
            super().__init__(message)
            self.exceptions = tuple(failures)
    if remove_group:
        builtins.ExceptionGroup = PortableExceptionGroup
    if remove_base_group:
        builtins.BaseExceptionGroup = PortableExceptionGroup
    original_git_tree = issuer._git_tree
    issuer._git_tree = types.MethodType(portable_git_tree, issuer)
    # Pipe EOF proves child exit before _issue_cli performs its exact waitpid.
    # The portable pidfd is only a stable adopted authority placeholder.
    waits = []
    fork_fds = []
    def observed_fork():
        fork_fds.append(tuple((lease.purpose, lease.number) for lease in registry._leases if lease.state is common.FdState.OWNED))
        return real_fork()
    def observed_waitpid(pid, flags):
        value = real_waitpid(pid, flags)
        waits.append(value)
        return value
    try:
        try:
            with patched(
                common.os,
                memfd_create=memfd_create,
                pidfd_open=pidfd_open,
                execve=bootstrap_exec,
                fork=observed_fork,
                waitpid=observed_waitpid,
                MFD_CLOEXEC=1,
                MFD_ALLOW_SEALING=2,
            ), patched(
                common.fcntl, fcntl=portable_fcntl, F_ADD_SEALS=1033, F_GET_SEALS=1034,
            ), patched(common, _bounded_reap=lambda pid, pidfd, waitable=False: real_time.sleep(0.05)):
                result = issuer.run_fixed_operation(context, job)
        except BaseException as error:
            debug = Path(f"/tmp/cogs-cli-{job}.debug")
            detail = debug.read_text(errors="replace") if debug.exists() else ""
            raise AssertionError(f"fixed CLI {job} failed; waits={waits}; fds={fork_fds}; child={detail}") from error
    finally:
        issuer._git_tree = original_git_tree
        if remove_group:
            del builtins.ExceptionGroup
        if remove_base_group:
            del builtins.BaseExceptionGroup
    if result.get("source_revision") != head or result.get("source_set_sha256") != issuer.source_set_sha256:
        raise AssertionError("common fixed CLI did not retain its exact admitted generations")
    runtime = result.get("runtime", result)
    facts = {
        name: value for name, value in runtime.items()
        if name not in {
            "version", "marker", "source_revision", "source_set_sha256", "closure_sha256",
            "gzip_output_sha256", "zstd_output_sha256", "mapping_sha256", "objects",
            "mapped", "mapped_objects",
        }
    }
    if job in ("B", "E"):
        facts = {name: value for name, value in facts.items() if type(value) is bool}
        if job == "B" and tuple(item["id"] for item in result.get("tools", ())) != ("gzip", "zstd"):
            raise AssertionError("common fixed CLI B metadata order drift")
    if not facts or not all(value is True for value in facts.values()):
        raise AssertionError(f"common fixed CLI {job} owner result drift")
    if registry.uncertain or any(lease.state is common.FdState.OWNED for lease in registry._leases):
        raise AssertionError("common fixed CLI retained an owned descriptor")


def capsule_contract(module):
    sources = {path: (ROOT / path).read_bytes()
               for path in module._FIXED_SOURCE_SET}
    source_digest = module._source_set_digest(sources)
    admission = module._SourceAdmission(
        "0" * 40, hashlib.sha256(sources[module._MODULE_PATHS[2]]).hexdigest(),
        source_digest, sources[module._SCHEMA_PATH], "", 0, None,
        module._BOOTSTRAP_OPERATION_TOKEN, 0, 0, 0, "sandbox",
    )
    rows = [
        {
            "path": path,
            "sha256": hashlib.sha256(sources[path]).hexdigest(),
            "size": len(sources[path]),
        }
        for path in module._FIXED_SOURCE_SET
    ]
    authority = {
        "bootstrap_sha256": admission.bootstrap_sha256,
        "revision": admission.revision,
        "root_bootstrap_sha256": hashlib.sha256(module._ROOT_BOOTSTRAP.encode()).hexdigest(),
        "source_set_sha256": admission.source_set_sha256,
        "sources": rows,
        "version": "cogs.root-capsule-authority/v1",
    }
    bootstrap = module._ROOT_BOOTSTRAP
    capsule = module._encode_root_capsule(sources, admission)
    decoded, header = module._decode_root_capsule(capsule, authority)
    if decoded != sources or header["parent_pid"] != os.getpid():
        raise AssertionError("held root capsule round trip")
    authority_check = bootstrap.index("rows == authority['sources']")
    compilation = bootstrap.index("exec(compile(launcher")
    if authority_check > compilation:
        raise AssertionError("independent root authority is not fixed before compilation")
    for path in module._FIXED_SOURCE_SET:
        unauthorized = dict(sources)
        unauthorized[path] += b"\n# self-consistent unauthorized generation\n"
        hostile_admission = replace(
            admission,
            bootstrap_sha256=hashlib.sha256(
                unauthorized[module._MODULE_PATHS[2]],
            ).hexdigest(),
            source_set_sha256=module._source_set_digest(unauthorized),
        )
        hostile = module._encode_root_capsule(unauthorized, hostile_admission)
        reached_sandbox = []
        def forbidden_sandbox(ops):
            del ops
            reached_sandbox.append(path)
            raise AssertionError("unauthorized root capsule reached sandbox effects")
        saved_environment = dict(os.environ)
        saved_argv = sys.argv[:]
        os.environ.clear()
        sys.argv[:] = ["fixed-root-bootstrap"]
        try:
            with patched(
                module,
                _descriptor_snapshot=lambda ops=None, pid="self": (0, 1, 2),
                _sandbox_only_transaction=forbidden_sandbox,
            ), patched(module.os, geteuid=lambda: 0):
                module._root_capsule_entry(hostile, authority)
        except module.RuntimeLauncherError as error:
            if error.code != "root-authority":
                raise
        else:
            raise AssertionError(f"root accepted unauthorized {path} generation")
        finally:
            os.environ.update(saved_environment)
            sys.argv[:] = saved_argv
        if reached_sandbox:
            raise AssertionError("fixed root pin was checked after sandbox effects")
    header_raw, payload = capsule.split(b"\n", 1)
    duplicate = header_raw[:-1] + b',"version":"cogs.runtime-source-admission/sandbox-v1"}'
    for hostile in (duplicate + b"\n" + payload, capsule[:-1], capsule + b"x"):
        try:
            module._decode_root_capsule(hostile)
        except module.RuntimeLauncherError:
            pass
        else:
            raise AssertionError("hostile root capsule accepted")
    bootstrap = module._ROOT_BOOTSTRAP
    required = (
        "object_pairs_hook=pairs",
        "parent_pid",
        "source_set_sha256",
        "os.getppid() == parent",
        "numbers.count(directory) == 1",
        "offset == len(payload)",
        "authority_raw = read_fixed(authority_path",
        "bootstrap_raw = read_fixed(bootstrap_path",
        "rows == authority['sources']",
    )
    if not all(token in bootstrap for token in required):
        raise AssertionError("root bootstrap pre-exec admission weakened")
    source = MODULE.read_text()
    root_entry = source[source.index("def _root_capsule_entry"):source.index("def _qualify_admitted_fixed_process_lifecycle")]
    if "_load_private_closure" in root_entry or "checkout" in module._ROOT_BOOTSTRAP:
        raise AssertionError("sandbox root reached closure/checkout authority")

def execute_root_entry_model(module, capsule, authority):
    """Execute the real fixed root entry and its owners above one kernel model."""
    row = {
        "id": "AT93-E-01:root-bootstrap-complete",
        "production_method": "_root_capsule_entry",
        "primitive_fault": {"point": "none", "mutation": "none"},
    }
    kernel = SandboxKernel(module, row)
    output = bytearray()
    saved_environment, saved_argv = dict(os.environ), sys.argv[:]
    os.environ.clear()
    sys.argv[:] = [module._ROOT_BOOTSTRAP_PATH]
    def pid(): return kernel.process.pid
    def ppid(): return kernel.process.parent
    def write(fd, data):
        if fd == 1:
            output.extend(data)
            return len(data)
        return kernel.write(fd, data)
    replacements = dict(
        open=kernel.open, close=kernel.close, read=kernel.read, write=write,
        pipe2=kernel.pipe2, fstat=kernel.fstat, stat=kernel.stat,
        mkdir=kernel.mkdir, rmdir=kernel.rmdir, getpid=pid, getppid=ppid,
        getuid=lambda: 0, getgid=lambda: 0, geteuid=lambda: 0, getegid=lambda: 0,
        getsid=kernel.getsid, getpgid=kernel.getpgid, setsid=kernel.setsid,
        setgroups=lambda groups: None, chdir=lambda path: None,
        waitpid=kernel.waitpid, _exit=kernel.exit,
    )
    descriptor_snapshot = module._descriptor_snapshot
    snapshot_calls = 0
    def root_descriptor_snapshot(ops=None, pid="self"):
        nonlocal snapshot_calls
        snapshot_calls += 1
        if snapshot_calls == 1:
            return (0, 1, 2)
        return descriptor_snapshot(ops, pid)
    try:
        with patched(module, _SystemOps=lambda: kernel, _descriptor_snapshot=root_descriptor_snapshot), patched(
            module.os, **replacements,
        ), patched(module.fcntl, ioctl=kernel.ioctl), patched(
            module.select, select=kernel.select,
        ), patched(module.signal, pidfd_send_signal=kernel.pidfd_signal), patched(
            module.os.path, lexists=kernel.lexists,
        ):
            try:
                status = module._root_capsule_entry(capsule, authority)
            finally:
                for thread in kernel.threads:
                    thread.join(2)
                if any(thread.is_alive() for thread in kernel.threads):
                    raise AssertionError("root owner thread did not settle")
    finally:
        os.environ.update(saved_environment)
        sys.argv[:] = saved_argv
    if status != 0 or not kernel.baseline_exact():
        raise AssertionError("real root bootstrap owner transaction did not restore baseline")
    mandatory = {"milestone:inner-chroot", "exit:inner:0", "exit:leader:0"}
    if not mandatory <= set(kernel.events):
        raise AssertionError("real root bootstrap bypassed leader/inner owners")
    return bytes(output), tuple(kernel.events)


def full_sandbox_launch_contract(module):
    """Compose E with the real root entry and sandbox owners above one kernel model."""
    sources = {path: (ROOT / path).read_bytes() for path in module._FIXED_SOURCE_SET}
    admission = module._SourceAdmission(
        "0" * 40, hashlib.sha256(sources[module._MODULE_PATHS[2]]).hexdigest(),
        module._source_set_digest(sources), sources[module._SCHEMA_PATH], "", 0,
        None, module._BOOTSTRAP_OPERATION_TOKEN, 0, 0, 0, "sandbox",
    )
    rows = [
        {"path": path, "sha256": hashlib.sha256(sources[path]).hexdigest(), "size": len(sources[path])}
        for path in module._FIXED_SOURCE_SET
    ]
    authority = {
        "bootstrap_sha256": admission.bootstrap_sha256,
        "revision": admission.revision,
        "root_bootstrap_sha256": hashlib.sha256(module._ROOT_BOOTSTRAP.encode()).hexdigest(),
        "source_set_sha256": admission.source_set_sha256,
        "sources": rows,
        "version": "cogs.root-capsule-authority/v1",
    }
    root_runs = []

    def modeled_root_issuer(ops, capsule):
        # The unprivileged issuer's exact capsule is consumed by the real fixed
        # root entry. Its result is caused by the real leader/inner owners; no
        # completed SandboxQualificationResult is supplied by this adapter.
        output, events = execute_root_entry_model(module, capsule, authority)
        root_runs.append((ops, hashlib.sha256(capsule).hexdigest(), events))
        return output

    owner = object()
    with patched(module, _run_root_capsule_with_ops=modeled_root_issuer):
        observed = module._launch_admitted_fixed_sandbox_qualification(admission, sources, owner)
    if len(root_runs) != 1 or root_runs[0][0] is not owner:
        raise AssertionError("E did not use its exact root issuer once")
    if not all(getattr(observed, name) is True for name in tuple(observed.__dataclass_fields__)[4:]):
        raise AssertionError("real root owner result drift")

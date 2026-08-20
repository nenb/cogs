from dataclasses import asdict, dataclass; import hashlib; import json; import os; from pathlib import Path; import platform; import stat; import struct; VERSION = 'cogs.stage2-local-execution-envelope/v1'; RUNTIME_VERSION = 'cogs.stage2-local-runtime-manifest/v1'; CONTRACT_VERSION = 'cogs.stage2-local-executable-closure/v1'; AUTHORITY = 'non-authoritative-execution-input-description'; FIXED_ROOT = Path('/var/lib/cogs/stage2-completion-v1/source'); ENVELOPE_PATH = FIXED_ROOT / 'deploy/aws-feasibility/remote/stage2-completion-local-envelope-v1.json'; RUNTIME_MANIFEST_PATH = FIXED_ROOT / 'deploy/aws-feasibility/remote/stage2-completion-local-runtime-v1.json'; REVIEWED_ENVELOPE_SHA256 = None; REVIEWED_RUNTIME_MANIFEST_SHA256 = None; MAX_ENVELOPE_BYTES = 131072; MAX_RUNTIME_MANIFEST_BYTES = 65536; MAX_SOURCE_BYTES = 2 * 1024 * 1024; MAX_CONTRACT_BYTES = 262144; HEX = frozenset('0123456789abcdef'); RECEIPT_VERSION = 'cogs.stage2-local-private-receipt/v1'; RECEIPT_DOMAIN = 'cogs.stage2-local-private-receipt/v1\x00'
EXECUTABLES = (('ip', 'host-path', '/usr/sbin/ip'), ('tc', 'host-path', '/usr/sbin/tc'), ('nft', 'host-path', '/usr/sbin/nft'), ('ssh', 'host-path', '/usr/bin/ssh'), ('ssh-keygen', 'host-path', '/usr/bin/ssh-keygen'), ('containerd', 'staged-runtime', '/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1/kata-runtime-v1/bin/containerd'), ('ctr', 'staged-runtime', '/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1/kata-runtime-v1/bin/ctr'), ('shim', 'kata-runtime', '/opt/kata/bin/containerd-shim-kata-v2'), ('qemu', 'kata-runtime', '/opt/kata/bin/qemu-system-x86_64'), ('virtiofsd', 'kata-runtime', '/opt/kata/libexec/virtiofsd')); MANDATORY_SOURCES = frozenset({'deploy/aws-feasibility/remote/completion_guest_workloads_v2.py', 'deploy/aws-feasibility/remote/completion_kata_admission.py', 'deploy/aws-feasibility/remote/completion_kata_command_policy.py', 'deploy/aws-feasibility/remote/completion_kata_coordinator.py', 'deploy/aws-feasibility/remote/completion_kata_process.py', 'deploy/aws-feasibility/remote/completion_kata_qualification.py', 'deploy/aws-feasibility/remote/completion_kata_runtime.py', 'deploy/aws-feasibility/remote/completion_runtime_closure.py', 'deploy/aws-feasibility/remote/completion_runtime_contract.py', 'deploy/aws-feasibility/remote/completion_rootfs_plan.py', 'deploy/aws-feasibility/remote/completion_local_full.py', 'deploy/aws-feasibility/remote/completion_local_receipt.py'}); BINDING_KEYS = frozenset({'source_head', 'source_manifest_sha256', 'host_attestation_sha256', 'runtime_attestation_sha256', 'rootfs_sha256', 'artifact_sha256', 'candidate_sha256', 'final_pin_sha256', 'guest_program_sha256', 'owner_implementation_sha256'}); PACKAGE_IDENTITY_KEYS = ('deb_sha256', 'deb_bytes', 'installed_tree_sha256', 'installed_entries', 'installed_bytes', 'package', 'version', 'architecture'); STATIC_OBJECT_KEYS = ('version', 'path', 'source', 'mode', 'size', 'content_sha256', 'interpreter', 'soname', 'needed', 'resolved'); MAPPING_KEYS = ('path', 'execution_path', 'device', 'inode', 'mode', 'uid', 'gid', 'nlink', 'size', 'sha256')
class AdmissionError(Exception): pass
class AdmissionUnavailable(AdmissionError): pass
@dataclass(frozen=True)
class EnvelopeDescription:
    sha256: str; value: dict
def _require(condition, message='invalid local execution admission'):
    if not condition:
        raise AdmissionError(message)
def _digest(value): _require(type(value) is str and len(value) == 64 and (set(value) <= HEX))
def _sha(raw): return hashlib.sha256(raw).hexdigest()
def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise AdmissionError('noncanonical admission value') from error
def _pairs(rows):
    value = {}
    for (key, item) in rows:
        _require(type(key) is str and key not in value, 'duplicate admission key'); value[key] = item
    return value
def _decode(raw, maximum):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum and raw.endswith(b'\n') and (b'\x00' not in raw), 'invalid admission bytes')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=_pairs, parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except AdmissionError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise AdmissionError('invalid admission JSON') from error
    _require(type(value) is dict and _canonical(value) == raw, 'admission bytes are not canonical')
    return value
def _keys(value, expected): _require(type(value) is dict and set(value) == set(expected))
def _relative(value):
    _require(type(value) is str and 0 < len(value) <= 240 and value.isascii() and (not value.startswith('/')) and ('\\' not in value)); parts = value.split('/'); _require(all((part not in {'', '.', '..'} for part in parts)))
def _validate_sources(source):
    _keys(source, ('root', 'head', 'manifest_sha256', 'files')); _require(source['root'] == str(FIXED_ROOT)); head = source['head']; _require(type(head) is str and len(head) == 40 and (set(head) <= HEX)); _digest(source['manifest_sha256']); files = source['files']; _require(type(files) is list and len(MANDATORY_SOURCES) <= len(files) <= 128); paths = []
    for row in files:
        _keys(row, ('path', 'sha256', 'size')); _relative(row['path']); _digest(row['sha256']); _require(type(row['size']) is int and (not isinstance(row['size'], bool)) and (1 <= row['size'] <= MAX_SOURCE_BYTES)); paths.append(row['path'])
    _require(paths == sorted(set(paths), key=lambda item: item.encode('ascii'))); _require(MANDATORY_SOURCES <= set(paths)); _require(source['manifest_sha256'] == _sha(_canonical(files)))
def _validate_executables(rows):
    _require(type(rows) is list and len(rows) == len(EXECUTABLES))
    for (row, expected) in zip(rows, EXECUTABLES, strict=True):
        _keys(row, ('role', 'source_class', 'path', 'contract_path', 'contract_sha256', 'executable_sha256', 'tool_closure_sha256')); _require((row['role'], row['source_class'], row['path']) == expected); _relative(row['contract_path'])
        for name in ('contract_sha256', 'executable_sha256', 'tool_closure_sha256'):
            _digest(row[name])
def _validate_contract(raw, expected):
    value = _decode(raw, MAX_CONTRACT_BYTES); _keys(value, ('version', 'architecture', 'role', 'path', 'dynamic_tags', 'objects', 'closure_sha256')); _require(value['version'] == CONTRACT_VERSION and value['architecture'] == 'x86_64' and ((value['role'], value['path']) == (expected['role'], expected['path']))); tags = value['dynamic_tags']; forbidden = {'RPATH', 'RUNPATH', 'AUDIT', 'DEPAUDIT', 'FILTER', 'AUXILIARY', 'CONFIG'}; _require(type(tags) is list and tags == sorted(set(tags)) and all((type(tag) is str and tag not in forbidden for tag in tags))); objects = value['objects']; _require(type(objects) is list and 1 <= len(objects) <= 130); (identities, sonames, total) = ([], {}, 0)
    for (index, item) in enumerate(objects):
        _keys(item, ('kind', 'path', 'size', 'sha256', 'interpreter', 'soname', 'needed')); _require(item['kind'] in {'executable', 'loader', 'library'} and type(item['path']) is str and item['path'].startswith('/') and item['path'].isascii() and (os.path.normpath(item['path']) == item['path']) and ('//' not in item['path']) and ('\\' not in item['path'])); _require(type(item['size']) is int and (not isinstance(item['size'], bool)) and (1 <= item['size'] <= 128 * 1024 * 1024)); _digest(item['sha256']); total += item['size']; interpreter = item['interpreter']; _require(interpreter is None or (item['kind'] == 'executable' and type(interpreter) is str and interpreter.startswith('/') and (os.path.normpath(interpreter) == interpreter))); soname = item['soname']; _require(soname is None or (type(soname) is str and 0 < len(soname) <= 255 and soname.isascii() and ('/' not in soname) and (soname not in sonames)))
        if soname is not None:
            sonames[soname] = item['path']
        if item['kind'] == 'library':
            _require(soname is not None)
        elif item['kind'] == 'executable':
            _require(soname is None)
        needed = item['needed']; _require(type(needed) is list and len(needed) <= 128 and (needed == sorted(set(needed))) and all((type(name) is str and 0 < len(name) <= 255 and name.isascii() and ('/' not in name) for name in needed))); identities.append((item['kind'], item['path']))
    _require(len({path for (_kind, path) in identities}) == len(identities), 'tool closure aliases an object path'); _require(total <= 512 * 1024 * 1024 and identities[0] == ('executable', expected['path']) and (sum((kind == 'executable' for (kind, _path) in identities)) == 1) and (sum((kind == 'loader' for (kind, _path) in identities)) <= 1)); _require(objects[0]['sha256'] == expected['executable_sha256']); loader_count = sum((kind == 'loader' for (kind, _path) in identities)); interpreter = objects[0]['interpreter']; _require((loader_count == 1) == (interpreter is not None)); _require(loader_count == 0 or (objects[1]['kind'] == 'loader' and objects[1]['path'] == interpreter)); libraries = objects[1 + loader_count:]; _require(all(item['kind'] == 'library' for item in libraries)); library_sonames = {item['soname'] for item in libraries}; _require([item['soname'] for item in libraries] == sorted(library_sonames)); _require(all((name in library_sonames for item in objects for name in item['needed']))); by_soname = {item['soname']: item for item in libraries}; (pending, reached) = (list(objects[0]['needed']), set())
    while pending:
        name = pending.pop(0)
        if name in reached:
            continue
        reached.add(name); pending.extend(by_soname[name]['needed'])
    _require(reached == library_sonames, 'tool closure has missing or extra libraries'); body = {name: value[name] for name in value if name != 'closure_sha256'}; _require(value['closure_sha256'] == _sha(_canonical(body)) and value['closure_sha256'] == expected['tool_closure_sha256'])
    return value
def _attestation_digest(rows): return _sha(_canonical(rows))
def _source_digest(source, path):
    rows = [row for row in source['files'] if row['path'] == path]; _require(len(rows) == 1)
    return rows[0]['sha256']
def _validate_package_identity(value):
    _keys(value, PACKAGE_IDENTITY_KEYS)
    for name in ('deb_sha256', 'installed_tree_sha256'):
        _digest(value[name])
    for (name, maximum) in (('deb_bytes', 4194304), ('installed_entries', 1000000), ('installed_bytes', 1 << 40)):
        _require(type(value[name]) is int and (not isinstance(value[name], bool)) and (1 <= value[name] <= maximum))
    _require((value['package'], value['version'], value['architecture']) == ('cogs-stage2-fixture', '1.0', 'all'))
def validate_envelope_value(value):
    _keys(value, ('version', 'authority', 'source', 'package', 'runtime', 'executables', 'result_bindings', 'receipt')); _require(value['version'] == VERSION and value['authority'] == AUTHORITY); _validate_sources(value['source']); package = value['package']; _keys(package, ('candidate_contract_sha256', 'candidate_result_sha256', 'final_pin_sha256', 'package_identity', 'artifact'))
    for name in ('candidate_contract_sha256', 'candidate_result_sha256', 'final_pin_sha256'):
        _digest(package[name])
    _validate_package_identity(package['package_identity']); _keys(package['artifact'], ('sha256', 'bytes')); _digest(package['artifact']['sha256']); _require(type(package['artifact']['bytes']) is int and (not isinstance(package['artifact']['bytes'], bool)) and (1 <= package['artifact']['bytes'] <= 4194304)); _require((package['artifact']['sha256'], package['artifact']['bytes']) == (package['package_identity']['deb_sha256'], package['package_identity']['deb_bytes'])); runtime = value['runtime']; _keys(runtime, ('manifest_sha256', 'rootfs_sha256', 'static_closure_sha256', 'execution_mapping_sha256'))
    for item in runtime.values():
        _digest(item)
    _validate_executables(value['executables']); bindings = value['result_bindings']; _keys(bindings, BINDING_KEYS)
    for (name, item) in bindings.items():
        if name == 'source_head':
            _require(item == value['source']['head'])
        else:
            _digest(item)
    _require(bindings['source_manifest_sha256'] == value['source']['manifest_sha256']); _require(bindings['host_attestation_sha256'] == _attestation_digest(value['executables'][:5])); _require(bindings['runtime_attestation_sha256'] == runtime['execution_mapping_sha256']); _require(bindings['rootfs_sha256'] == runtime['rootfs_sha256']); _require(bindings['artifact_sha256'] == package['artifact']['sha256']); _require(bindings['candidate_sha256'] == package['candidate_result_sha256']); _require(bindings['final_pin_sha256'] == package['final_pin_sha256']); _require(bindings['guest_program_sha256'] == _source_digest(value['source'], 'deploy/aws-feasibility/remote/completion_guest_workloads_v2.py')); _require(bindings['owner_implementation_sha256'] == _source_digest(value['source'], 'deploy/aws-feasibility/remote/completion_kata_coordinator.py')); _require(value['receipt'] == {'version': RECEIPT_VERSION, 'domain': RECEIPT_DOMAIN})
    return value
def load_envelope(raw):
    value = validate_envelope_value(_decode(raw, MAX_ENVELOPE_BYTES))
    return EnvelopeDescription(_sha(raw), value)
def _validate_static_closure(value):
    _keys(value, ('version', 'manifest_sha256', 'object_count', 'tools', 'objects')); _require(value['version'] == 'cogs.stage2-runtime-tool-closure/v1'); _digest(value['manifest_sha256']); _require(value['object_count'] == 35 and type(value['tools']) is list and (len(value['tools']) == 3))
    for tool in value['tools']:
        _keys(tool, ('name', 'sha256', 'bytes', 'version')); _digest(tool['sha256']); _require(type(tool['name']) is str and type(tool['version']) is str and (type(tool['bytes']) is int) and (not isinstance(tool['bytes'], bool)) and (tool['bytes'] > 0))
    objects = value['objects']; _require(type(objects) is list and len(objects) == 35); paths = []
    for row in objects:
        _keys(row, STATIC_OBJECT_KEYS); _require(row['version'] == 'cogs.stage2-completion-runtime-object/v1'); _relative(row['path']); _digest(row['content_sha256']); _require(type(row['source']) is str and row['source'] and (type(row['mode']) is int) and (0 <= row['mode'] <= 4095) and (type(row['size']) is int) and (row['size'] > 0))
        for name in ('interpreter', 'soname'):
            _require(row[name] is None or (type(row[name]) is str and row[name]))
        for name in ('needed', 'resolved'):
            _require(type(row[name]) is list and len(row[name]) <= 128 and (len(row[name]) == len(set(row[name]))) and all((type(item) is str and item for item in row[name])))
        _require(len(row['needed']) == len(row['resolved'])); paths.append(row['path'])
    _require(paths == sorted(set(paths), key=str.encode), 'static closure paths differ'); stream = b''.join((_canonical(row) for row in objects)); _require(_sha(stream) == value['manifest_sha256'], 'static closure object stream differs')
def _validate_execution_mapping(value, static, rootfs_sha256):
    _keys(value, ('version', 'rootfs_sha256', 'static_manifest_sha256', 'objects')); _require(value['version'] == 'cogs.stage2-local-execution-mapping/v1' and value['rootfs_sha256'] == rootfs_sha256 and (value['static_manifest_sha256'] == static['manifest_sha256'])); rows = value['objects']; _require(type(rows) is list and len(rows) == 35); (identities, paths) = (set(), [])
    for (row, pinned) in zip(rows, static['objects'], strict=True):
        _keys(row, MAPPING_KEYS); _relative(row['path']); _require(type(row['execution_path']) is str and row['execution_path'].startswith('/') and (os.path.normpath(row['execution_path']) == row['execution_path']))
        for name in ('device', 'inode', 'mode', 'uid', 'gid', 'nlink', 'size'):
            _require(type(row[name]) is int and (not isinstance(row[name], bool)) and (row[name] >= 0))
        _digest(row['sha256']); _require((row['path'], row['size'], row['sha256']) == (pinned['path'], pinned['size'], pinned['content_sha256']) and row['inode'] > 0 and (row['nlink'] == 1)); paths.append(row['execution_path']); identities.add((row['device'], row['inode']))
    _require(len(set(paths)) == len(rows) and len(identities) == len(rows), 'execution mapping aliases a path or file identity')
def load_runtime_manifest(raw):
    value = _decode(raw, MAX_RUNTIME_MANIFEST_BYTES); _keys(value, ('version', 'architecture', 'rootfs_sha256', 'static_closure', 'execution_mapping', 'executables')); _require(value['version'] == RUNTIME_VERSION and value['architecture'] == 'x86_64'); _digest(value['rootfs_sha256']); _validate_static_closure(value['static_closure']); _validate_execution_mapping(value['execution_mapping'], value['static_closure'], value['rootfs_sha256']); rows = value['executables']; _require(type(rows) is list and len(rows) == len(EXECUTABLES) - 5)
    for (row, expected) in zip(rows, EXECUTABLES[5:], strict=True):
        _keys(row, ('role', 'source_class', 'path', 'contract_path', 'contract_sha256', 'executable_sha256', 'tool_closure_sha256')); _require((row['role'], row['source_class'], row['path']) == expected); _relative(row['contract_path'])
        for name in ('contract_sha256', 'executable_sha256', 'tool_closure_sha256'):
            _digest(row[name])
    return value
def _status(status, maximum, expected_uid, expected_gid): _require(stat.S_ISREG(status.st_mode) and status.st_uid == expected_uid and (status.st_gid == expected_gid) and (status.st_nlink == 1) and (not stat.S_IMODE(status.st_mode) & 18) and (0 < status.st_size <= maximum), 'untrusted admitted file identity')
def _open_fixed_relative(root, relative, maximum, expected_uid=0, expected_gid=0):
    _relative(relative); flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW; parent = os.open(root, flags); descriptor = -1
    try:
        root_status = os.fstat(parent); _require(stat.S_ISDIR(root_status.st_mode) and root_status.st_uid == expected_uid and (root_status.st_gid == expected_gid) and (not stat.S_IMODE(root_status.st_mode) & 18), 'untrusted admitted root')
        for component in relative.split('/')[:-1]:
            child = os.open(component, flags, dir_fd=parent); seen = os.fstat(child); _require(stat.S_ISDIR(seen.st_mode) and seen.st_uid == expected_uid and (seen.st_gid == expected_gid) and (not stat.S_IMODE(seen.st_mode) & 18), 'untrusted admitted directory'); os.close(parent); parent = child
        descriptor = os.open(relative.rsplit('/', 1)[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent); before = os.fstat(descriptor); _status(before, maximum, expected_uid, expected_gid)
        return (descriptor, parent, before)
    except BaseException as error:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)
        if isinstance(error, OSError):
            raise AdmissionError('admitted file open failed') from error
        raise
def _open_absolute_regular(path, maximum):
    _require(type(path) is str and path.startswith('/') and path.isascii() and ('//' not in path) and ('/../' not in path) and ('\\' not in path)); relative = path[1:]
    return _open_fixed_relative('/', relative, maximum)
def _read_held(descriptor, before, maximum):
    digest = hashlib.sha256(); total = 0
    while total <= maximum:
        part = os.pread(descriptor, min(65536, maximum + 1 - total), total)
        if not part:
            break
        digest.update(part); total += len(part)
    after = os.fstat(descriptor); _require(total == before.st_size and total <= maximum and ((before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)), 'admitted file changed while reading')
    return digest.hexdigest()
def _read_held_raw(descriptor, before, maximum):
    raw = os.pread(descriptor, before.st_size, 0); _require(len(raw) == before.st_size and _sha(raw) == _read_held(descriptor, before, maximum), 'admitted file changed while reading')
    return raw
def _derived_elf(raw):
    _require(type(raw) is bytes and len(raw) >= 64)
    try:
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw); (ident, kind, machine, version) = header[:4]; (phoff, phsize, phnum) = (header[5], header[9], header[10]); _require(ident[:7] == b'\x7fELF\x02\x01\x01' and kind in {2, 3} and (machine == 62) and (version == 1) and (phsize == 56) and (0 < phnum <= 256) and (phoff + phsize * phnum <= len(raw)), 'retained object is not exact ELF64'); dynamic = sum((struct.unpack_from('<I', raw, phoff + index * phsize)[0] == 2 for index in range(phnum)))
        if dynamic == 0:
            return (None, None, ())
        _require(dynamic == 1)
        from completion_runtime_closure import _elf
        return _elf(raw)
    except AdmissionError:
        raise
    except Exception as error:
        raise AdmissionError('retained ELF metadata is invalid') from error
def _retain_contract_objects(contract, descriptors):
    identities = set()
    for item in contract['objects']:
        (descriptor, parent, status) = _open_absolute_regular(item['path'], item['size']); descriptors.extend((parent, descriptor)); raw = _read_held_raw(descriptor, status, item['size']); identity = (status.st_dev, status.st_ino); _require(identity not in identities, 'tool closure aliases a retained file identity'); identities.add(identity); _require(status.st_size == item['size'] and _sha(raw) == item['sha256'], 'executable closure source differs'); (interpreter, soname, needed) = _derived_elf(raw); _require((interpreter, soname, list(needed)) == (item['interpreter'], item['soname'], item['needed']), 'declared ELF metadata differs from retained bytes')
def _qualification_checks():
    try:
        observed = os.stat('/dev/kvm', follow_symlinks=False); kvm = stat.S_ISCHR(observed.st_mode) and os.access('/dev/kvm', os.R_OK | os.W_OK)
    except OSError:
        kvm = False
    return (platform.system() == 'Linux', platform.machine() == 'x86_64', os.geteuid() == 0, os.path.realpath(os.getcwd()) == str(FIXED_ROOT), kvm)
def _custody_routes():
    (seal, states) = (object(), {}); issuance_started = False; issuer_taken = False
    class _ExecutionCustody:
        __slots__ = ()
        def __new__(cls, key=None):
            _require(key is seal, 'sealed execution custody')
            return super().__new__(cls)
    class _CustodyQualification:
        __slots__ = ()
        def __new__(cls, key=None):
            _require(key is seal, 'sealed custody qualification')
            return super().__new__(cls)
    def close_descriptors(state):
        errors = []
        for descriptor in reversed(state['descriptors']):
            try:
                os.close(descriptor)
            except OSError as error:
                errors.append(error)
        state['descriptors'] = []
        if errors:
            raise BaseExceptionGroup('execution custody close', errors)
    def claim():
        nonlocal issuance_started
        if REVIEWED_ENVELOPE_SHA256 is None or REVIEWED_RUNTIME_MANIFEST_SHA256 is None:
            raise AdmissionUnavailable('reviewed final envelope/runtime manifest unavailable')
        if issuance_started:
            raise AdmissionUnavailable('execution custody issuance is globally one-shot')
        issuance_started = True; _digest(REVIEWED_ENVELOPE_SHA256); _digest(REVIEWED_RUNTIME_MANIFEST_SHA256); descriptors = []
        try:
            (envelope_fd, envelope_parent, envelope_status) = _open_fixed_relative(FIXED_ROOT, str(ENVELOPE_PATH.relative_to(FIXED_ROOT)), MAX_ENVELOPE_BYTES); descriptors.extend((envelope_parent, envelope_fd)); envelope_raw = _read_held_raw(envelope_fd, envelope_status, MAX_ENVELOPE_BYTES); _require(_sha(envelope_raw) == REVIEWED_ENVELOPE_SHA256); envelope = load_envelope(envelope_raw); (runtime_fd, runtime_parent, runtime_status) = _open_fixed_relative(FIXED_ROOT, str(RUNTIME_MANIFEST_PATH.relative_to(FIXED_ROOT)), MAX_RUNTIME_MANIFEST_BYTES); descriptors.extend((runtime_parent, runtime_fd)); runtime_raw = _read_held_raw(runtime_fd, runtime_status, MAX_RUNTIME_MANIFEST_BYTES); _require(_sha(runtime_raw) == REVIEWED_RUNTIME_MANIFEST_SHA256); runtime = load_runtime_manifest(runtime_raw); value = envelope.value; runtime_binding = value['runtime']; _require(runtime_binding == {'manifest_sha256': REVIEWED_RUNTIME_MANIFEST_SHA256, 'rootfs_sha256': runtime['rootfs_sha256'], 'static_closure_sha256': runtime['static_closure']['manifest_sha256'], 'execution_mapping_sha256': _sha(_canonical(runtime['execution_mapping']))} and runtime['executables'] == value['executables'][5:])
            for row in value['source']['files']:
                (descriptor, parent, seen) = _open_fixed_relative(FIXED_ROOT, row['path'], row['size']); descriptors.extend((parent, descriptor)); _require(seen.st_size == row['size'] and _read_held(descriptor, seen, row['size']) == row['sha256'], 'source closure differs')
            import completion_runtime_contract as workload_contract
            final_pin = workload_contract.load_final_pin(); package = value['package']; _require(type(final_pin) is workload_contract.FinalPin and final_pin.final_pin_sha256 == package['final_pin_sha256'] and (final_pin.candidate_contract_sha256 == package['candidate_contract_sha256']) and (final_pin.candidate_result_sha256 == package['candidate_result_sha256']) and (final_pin.package_identity.value() == package['package_identity']) and ((final_pin.package_identity.deb_sha256, final_pin.package_identity.deb_bytes) == (package['artifact']['sha256'], package['artifact']['bytes'])), 'final pin/package envelope mismatch'); pinned_closure = final_pin.runtime_closure.value(); static = runtime['static_closure']; _require({name: static[name] for name in pinned_closure} == pinned_closure, 'final pin runtime closure differs')
            from completion_rootfs_plan import load_verified_build_inputs
            from completion_runtime_closure import fixed_runtime_closure
            observed = fixed_runtime_closure(load_verified_build_inputs()); observed_objects = [json.loads(_canonical(asdict(row))) for row in observed.records]; _require(static['manifest_sha256'] == observed.manifest_sha256 and static['object_count'] == observed.object_count and (static['objects'] == observed_objects), 'exact 35-object final-pin closure differs')
            for mapped in runtime['execution_mapping']['objects']:
                (descriptor, parent, seen) = _open_absolute_regular(mapped['execution_path'], mapped['size']); descriptors.extend((parent, descriptor)); _require((seen.st_dev, seen.st_ino, stat.S_IMODE(seen.st_mode), seen.st_uid, seen.st_gid, seen.st_nlink, seen.st_size, _read_held(descriptor, seen, mapped['size'])) == (mapped['device'], mapped['inode'], mapped['mode'], mapped['uid'], mapped['gid'], mapped['nlink'], mapped['size'], mapped['sha256']), 'execution-time mapping differs')
            for row in value['executables']:
                (contract_fd, contract_parent, contract_status) = _open_fixed_relative(FIXED_ROOT, row['contract_path'], MAX_CONTRACT_BYTES); descriptors.extend((contract_parent, contract_fd)); contract_raw = _read_held_raw(contract_fd, contract_status, MAX_CONTRACT_BYTES); _require(_sha(contract_raw) == row['contract_sha256']); contract = _validate_contract(contract_raw, row); _retain_contract_objects(contract, descriptors)
            _require(all(_qualification_checks()), 'custody-derived local qualification failed'); (custody, qualification) = (_ExecutionCustody(seal), _CustodyQualification(seal)); state = {'envelope': envelope, 'runtime_sha256': REVIEWED_RUNTIME_MANIFEST_SHA256, 'descriptors': descriptors, 'qualification': qualification, 'qualification_consumed': False}; states[custody] = state
            return (custody, qualification)
        except BaseException:
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
    def take_issuer():
        nonlocal issuer_taken
        _require(not issuer_taken, 'execution custody issuer already taken'); issuer_taken = True
        return claim
    def consume_qualification(custody, qualification):
        state = states.get(custody); _require(type(custody) is _ExecutionCustody and state is not None and (type(qualification) is _CustodyQualification) and (qualification is state['qualification']) and (not state['qualification_consumed']), 'live custody qualification required'); state['qualification_consumed'] = True
    def binding(custody):
        state = states.get(custody); _require(type(custody) is _ExecutionCustody and state is not None, 'live exact custody required')
        return dict(state['envelope'].value['result_bindings'])
    def abort(custody):
        state = states.pop(custody, None); _require(type(custody) is _ExecutionCustody and state is not None); close_descriptors(state)
    return (take_issuer, consume_qualification, binding, abort)
(_take_execution_custody_issuer, _consume_custody_qualification, _execution_custody_binding, _abort_execution_custody) = _custody_routes(); del _custody_routes
def committed_status(): return {'envelope_reviewed': REVIEWED_ENVELOPE_SHA256 is not None, 'runtime_manifest_reviewed': REVIEWED_RUNTIME_MANIFEST_SHA256 is not None, 'custody_issued': False}

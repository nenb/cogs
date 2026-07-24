"""Direct fixed-plan rootfs writer and complete postwalk for ADR 0040."""

from dataclasses import dataclass, replace
import hashlib
import os
import stat
import sys
import time

sys.dont_write_bytecode = True

import completion_rootfs_builder as builder
import completion_rootfs_fs as fs
import completion_rootfs_ledger as ledger
import completion_rootfs_plan as plan

MATERIALIZE_SECONDS = 300
CLEANUP_SECONDS = 120


class MaterializerError(Exception):
    pass


def _fail(condition):
    if not condition:
        raise MaterializerError()


@dataclass(frozen=True)
class MaterializedRoot:
    owned: builder.OwnedOperation
    active: builder.ActiveLedger
    entry_count: int


def _check(control):
    control.check()


def _generation(node, control):
    return fs._observe_node(node.identity_fd, node.operation_fd, control)


def _open_parent(root, path, control):
    parts = path.split("/")
    parent = root
    opened = []
    try:
        for part in parts[:-1]:
            node = fs._open_path_node(parent, fs._name(part), "directory", control)
            opened.append(node)
            parent = node
        return parent, tuple(opened), fs._name(parts[-1])
    except BaseException as error:
        _close_opened(opened, error)


def _close_opened(opened, primary=None):
    error = primary
    for node in reversed(opened):
        try:
            fs._close_node(node)
        except BaseException as close_error:
            error = fs.RootfsFsError(error, close_error)
    if error is not None:
        raise error


def _close_final(opened):
    primary = sys.exception()
    try:
        _close_opened(opened)
    except BaseException as close_error:
        if primary is not None:
            raise fs.RootfsFsError(primary, close_error) from close_error
        raise


def _desired(record, host_size):
    size = record.archive_size if record.kind == "file" else host_size
    return ledger._metadata_value(record.mode, record.uid, record.gid, size, record.mtime * 1_000_000_000)


def _append(active, record_type, body, control):
    return builder._append(active, record_type, body, control)


def _apply_metadata(node, parent, symlink_name, record, desired, control):
    if symlink_name is None:
        _check(control)
        os.fchown(node.operation_fd.number, record.uid, record.gid)
        _check(control)
        os.fchmod(node.operation_fd.number, record.mode)
        _check(control)
        os.utime(node.operation_fd.number, ns=(record.mtime * 1_000_000_000,) * 2)
        _check(control)
        builder._fsync(node.operation_fd, control)
        after = _generation(node, control)
    else:
        _check(control)
        os.chown(symlink_name.raw, record.uid, record.gid, dir_fd=parent.operation_fd.number, follow_symlinks=False)
        _check(control)
        os.utime(symlink_name.raw, ns=(record.mtime * 1_000_000_000,) * 2, dir_fd=parent.operation_fd.number, follow_symlinks=False)
        _check(control)
        builder._fsync(parent.operation_fd, control)
        after = fs._observe_child(parent, symlink_name, control)
    _fail((after.mode, after.uid, after.gid, after.size, after.mtime_ns) == ledger._parse_metadata(desired))
    return after


def _metadata(active, node, path, record, parent, control, symlink_name=None):
    before = _generation(node, control)
    desired = _desired(record, before.size)
    active = _append(active, "metadata-intent", {"token": builder._token(active), "path": path, "before": builder._g(before), "desired": desired}, control)
    transition = builder._transition_control()
    try:
        after = _apply_metadata(node, parent, symlink_name, record, desired, transition)
        observed = {"token": builder._token(active), "path": path, "child": builder._g(after)}
        active = _append(active, "metadata-observed", observed, transition)
        active = _append(active, "metadata-settled", observed, transition)
        control.check()
        return active, after
    except BaseException as error:
        recovery = builder._transition_control()
        try:
            refreshed = builder._refresh_active(active, recovery)
            terminal = refreshed.records[-1]
            body = terminal.body_value()
            _fail(body["path"] == path and terminal.record_type in {"metadata-intent", "metadata-observed", "metadata-settled"})
            current = fs._observe_child(parent, symlink_name, recovery) if symlink_name is not None else _generation(node, recovery)
            intent = next(item.body_value() for item in reversed(refreshed.records) if item.record_type == "metadata-intent" and item.body_value()["path"] == path)
            _fail(current.key == ledger._parse_generation(intent["before"]).key)
            if terminal.record_type == "metadata-intent":
                current = _apply_metadata(node, parent, symlink_name, record, desired, recovery)
                observed = {"token": builder._token(refreshed), "path": path, "child": builder._g(current)}
                refreshed = _append(refreshed, "metadata-observed", observed, recovery)
                _append(refreshed, "metadata-settled", observed, recovery)
            else:
                _fail(current == ledger._parse_generation(body["child"]))
                if terminal.record_type == "metadata-observed":
                    _append(refreshed, "metadata-settled", body, recovery)
        except BaseException as recovery_error:
            error = fs.RootfsFsError(error, recovery_error)
        raise error


def _create_directory(active, root, entry, control):
    path = "rootfs/" + entry.record.path
    parent, opened, name = _open_parent(root, entry.record.path, control)
    try:
        active, child = builder._create_ledger_entry(active, parent, path, name, "directory", None, control)
        fs._close_node(child)
        return active
    finally:
        _close_final(opened)


def _create_file(active, root, entry, control):
    path = "rootfs/" + entry.record.path
    parent, opened, name = _open_parent(root, entry.record.path, control)
    child = None
    try:
        content = bytes(entry.content())
        _fail(len(content) == entry.record.archive_size)
        _fail(hashlib.sha256(content).hexdigest() == entry.record.content_sha256)
        active, child = builder._create_ledger_entry(active, parent, path, name, "file", content, control)
        active, _after = _metadata(active, child, path, entry.record, parent, control)
        actual = fs._read_regular(child, entry.record.archive_size, control)
        _fail(hashlib.sha256(actual).hexdigest() == entry.record.content_sha256)
        fs._require_empty_fd_xattrs(child, control)
        fs._close_node(child)
        child = None
        return active
    except BaseException as error:
        if child is not None and child.identity_fd.disposition == "open":
            fs._close_node(child, error)
        raise
    finally:
        _close_final(opened)


def _snapshot(node, control):
    return fs._enumerate_stable(node, control)


def _parent_value(snapshot):
    value = ledger.LedgerParent(snapshot.generation, tuple(item.text for item in snapshot.names))
    return ledger._parent_value(value)


def _create_hardlinks(active, root, authority, control):
    plans = ledger._plan_hardlink_groups(authority)
    entries = {entry.record.path: entry for entry in authority.plan.entries}
    for group in plans:
        target_parent, target_opened, target_name = _open_parent(root, group.target_path, control)
        target = fs._open_path_node(target_parent, target_name, "file", control)
        try:
            content = fs._read_regular(target, group.size, control)
            state = ledger._new_hardlink_group(group, _generation(target, control), hashlib.sha256(content).hexdigest())
            body = {
                "token": builder._token(active),
                "target_path": "rootfs/" + group.target_path,
                "aliases": ["rootfs/" + value for value in group.aliases],
                "content_sha256": group.content_sha256,
                "target": builder._g(state.target),
            }
            active = _append(active, "hardlink-group", body, control)
            for index, alias_path in enumerate(group.aliases):
                parent, opened, alias_name = _open_parent(root, alias_path, control)
                alias_created = False
                try:
                    before_parent = _snapshot(parent, control)
                    before_target = _generation(target, control)
                    intent = {
                        "token": builder._token(active),
                        "target_path": "rootfs/" + group.target_path,
                        "alias": "rootfs/" + alias_path,
                        "index": index,
                        "target": builder._g(before_target),
                        "parent": _parent_value(before_parent),
                    }
                    active = _append(active, "hardlink-create-intent", intent, control)
                    transition = builder._transition_control()
                    _check(transition)
                    os.link(
                        target_name.raw,
                        alias_name.raw,
                        src_dir_fd=target_parent.operation_fd.number,
                        dst_dir_fd=parent.operation_fd.number,
                        follow_symlinks=False,
                    )
                    alias_created = True
                    _check(transition)
                    after_parent = _snapshot(parent, transition)
                    after_target = _generation(target, transition)
                    alias = fs._observe_child(parent, alias_name, transition)
                    delta = fs.ParentDelta("hardlink", alias_name, before_parent, after_parent)
                    model_transition = ledger._hardlink_transition(
                        state,
                        "create",
                        index,
                        before_target,
                        after_target,
                        alias,
                        delta,
                        hashlib.sha256(fs._read_regular(target, group.size, transition)).hexdigest(),
                    )
                    observed = {
                        "token": builder._token(active),
                        "target_path": "rootfs/" + group.target_path,
                        "alias": "rootfs/" + alias_path,
                        "index": index,
                        "target_before": builder._g(before_target),
                        "target_after": builder._g(after_target),
                        "alias_generation": builder._g(alias),
                        "parent": _parent_value(after_parent),
                    }
                    active = _append(active, "hardlink-create-observed", observed, transition)
                    builder._fsync(target.operation_fd, transition)
                    builder._fsync(parent.operation_fd, transition)
                    active = _append(active, "hardlink-create-settled", observed, transition)
                    control.check()
                    state = ledger._settle_hardlink(state, model_transition)
                    _fail(entries[alias_path].record.hardlink_target == group.target_path)
                except BaseException as error:
                    if alias_created:
                        cleanup = builder._transition_control()
                        try:
                            terminal = builder._durable_terminal(active, cleanup)
                            terminal_body = terminal.body_value()
                            durable = terminal.record_type in {"hardlink-create-observed", "hardlink-create-settled"} and terminal_body["alias"] == "rootfs/" + alias_path
                            if not durable:
                                current = fs._observe_child(parent, alias_name, cleanup)
                                _fail(current.key == target.generation.key)
                                os.unlink(alias_name.raw, dir_fd=parent.operation_fd.number)
                                builder._fsync(target.operation_fd, cleanup)
                                builder._fsync(parent.operation_fd, cleanup)
                                intent_body = builder._absence_abort_body(terminal.body_value(), parent, alias_name, cleanup)
                                intent_body["target"] = builder._g(_generation(target, cleanup))
                                active = _append(active, "hardlink-create-abort", intent_body, cleanup)
                        except BaseException as cleanup_error:
                            error = fs.RootfsFsError(error, cleanup_error)
                    raise error
                finally:
                    _close_final(opened)
        finally:
            _close_final(target_opened + (target,))
    return active


def _fresh_chain_to_parent(owned, root, relative_parent, control):
    state = replace(owned.locked.state, generation=_generation(owned.locked.state, control))
    operation = replace(owned.operation, generation=_generation(owned.operation, control))
    retained = replace(root, generation=_generation(root, control))
    chain = fs.HeldChain(
        owned.locked.chain.anchor,
        owned.locked.chain.components[:-1]
        + (fs.ChainComponent(builder.STATE_NAME, state),)
        + (fs.ChainComponent(fs._name(owned.operation_name), operation),)
        + (fs.ChainComponent(builder.ROOT_NAME, retained),),
    )
    parent = retained
    opened = []
    try:
        if relative_parent:
            for part in relative_parent.split("/"):
                node = fs._open_path_node(parent, fs._name(part), "directory", control)
                opened.append(node)
                chain = fs.HeldChain(chain.anchor, chain.components + (fs.ChainComponent(fs._name(part), node),))
                parent = node
        return chain, parent, tuple(opened)
    except BaseException as error:
        _close_opened(opened, error)


def _create_symlink(active, owned, root, entry, control):
    record = entry.record
    path = "rootfs/" + record.path
    parent_path, _separator, base = record.path.rpartition("/")
    parent, opened, name = _open_parent(root, record.path, control)
    child = None
    created = False
    try:
        before = _snapshot(parent, control)
        active = _append(
            active,
            "create-intent",
            {"token": builder._token(active), "path": path, "kind": "symlink", "parent": _parent_value(before)},
            control,
        )
        transition = builder._transition_control()
        _check(transition)
        os.symlink(record.link_text, name.raw, dir_fd=parent.operation_fd.number)
        created = True
        _check(transition)
        child = fs._open_path_node(parent, name, "symlink", transition)
        after = _snapshot(parent, transition)
        observed = {
            "token": builder._token(active),
            "path": path,
            "kind": "symlink",
            "parent": _parent_value(after),
            "child": builder._g(child.generation),
        }
        active = _append(active, "create-observed", observed, transition)
        builder._fsync(parent.operation_fd, transition)
        active = _append(active, "create-settled", observed, transition)
        control.check()
        active, generation = _metadata(active, child, path, record, parent, control, name)
        child = replace(child, generation=generation)
        chain, chain_parent, chain_opened = _fresh_chain_to_parent(owned, root, parent_path, control)
        try:
            fs._require_empty_symlink_xattrs(chain, chain_parent, name, child, control)
        finally:
            _close_final(chain_opened)
        fs._close_node(child)
        child = None
        return active
    except BaseException as error:
        if created:
            cleanup_control = builder._transition_control()
            try:
                records = builder._durable_records(active, cleanup_control)
                durable = False
                for ledger_record in records:
                    if ledger_record.record_type in {"create-observed", "create-settled"}:
                        body = ledger_record.body_value()
                        if body["path"] == path and (child is None or ledger._parse_generation(body["child"]).key == child.generation.key):
                            durable = True
                current = fs._observe_child(parent, name, cleanup_control)
                if child is not None:
                    _fail(current.key == child.generation.key)
                if not durable:
                    _fail(current.key.kind == "symlink")
                    os.unlink(name.raw, dir_fd=parent.operation_fd.number)
                    builder._fsync(parent.operation_fd, cleanup_control)
                    intent = builder._absence_abort_body(records[-1].body_value(), parent, name, cleanup_control)
                    active = _append(active, "create-abort", intent, cleanup_control)
                if child is not None and child.identity_fd.disposition == "open":
                    fs._close_node(child)
            except BaseException as cleanup_error:
                if child is not None and child.identity_fd.disposition == "open":
                    try:
                        fs._close_node(child)
                    except BaseException as close_error:
                        cleanup_error = fs.RootfsFsError(cleanup_error, close_error)
                error = fs.RootfsFsError(error, cleanup_error)
        raise error
    finally:
        _close_final(opened)


def _finalize_directory(active, root, entry, control):
    path = "rootfs/" + entry.record.path
    parent, opened, name = _open_parent(root, entry.record.path, control)
    node = None
    try:
        node = fs._open_path_node(parent, name, "directory", control)
        active, _generation_value = _metadata(active, node, path, entry.record, parent, control)
        fs._require_empty_fd_xattrs(node, control)
    except BaseException as error:
        _close_opened(opened + (() if node is None else (node,)), error)
    _close_opened(opened + (node,))
    return active


def _record_matches(generation, record):
    expected_kind = "file" if record.kind == "hardlink" else record.kind
    _fail(generation.key.kind == expected_kind)
    _fail((generation.mode, generation.uid, generation.gid, generation.mtime_ns) == (
        record.mode,
        record.uid,
        record.gid,
        record.mtime * 1_000_000_000,
    ))
    if record.kind == "file":
        _fail(generation.size == record.archive_size)


def _postwalk(owned, root, authority, control):
    expected = {entry.record.path: entry for entry in authority.plan.entries}
    observed = {}

    def visit(directory, prefix):
        snapshot = _snapshot(directory, control)
        for name, generation in snapshot.children:
            path = name.text if not prefix else prefix + "/" + name.text
            entry = expected.get(path)
            _fail(entry is not None)
            record = entry.record
            _record_matches(generation, record)
            observed[path] = generation
            if record.kind == "directory":
                child = fs._open_path_node(directory, name, "directory", control)
                try:
                    fs._require_empty_fd_xattrs(child, control)
                    visit(child, path)
                    fs._close_node(child)
                except BaseException as error:
                    if child.identity_fd.disposition == "open":
                        fs._close_node(child, error)
                    raise
            elif record.kind == "file":
                child = fs._open_path_node(directory, name, "file", control)
                try:
                    fs._require_empty_fd_xattrs(child, control)
                    raw = fs._read_regular(child, record.archive_size, control)
                    _fail(hashlib.sha256(raw).hexdigest() == record.content_sha256)
                    fs._close_node(child)
                except BaseException as error:
                    if child.identity_fd.disposition == "open":
                        fs._close_node(child, error)
                    raise
            elif record.kind == "symlink":
                _check(control)
                literal = os.readlink(name.raw, dir_fd=directory.operation_fd.number)
                _check(control)
                _fail(type(literal) is bytes and literal == os.fsencode(record.link_text))
                child = fs._open_path_node(directory, name, "symlink", control)
                opened = ()
                error = None
                try:
                    chain, parent, opened = _fresh_chain_to_parent(owned, root, prefix, control)
                    fs._require_empty_symlink_xattrs(chain, parent, name, child, control)
                except BaseException as primary:
                    error = primary
                for retained in (child,) + tuple(reversed(opened)):
                    try:
                        fs._close_node(retained)
                    except BaseException as close_error:
                        error = fs.RootfsFsError(error, close_error)
                if error is not None:
                    raise error

    visit(root, "")
    _fail(set(observed) == set(expected))
    for path, entry in expected.items():
        if entry.record.kind == "hardlink":
            _fail(observed[path].key == observed[entry.record.hardlink_target].key)
    root_generation = _generation(root, control)
    root_record = authority.plan.root
    _fail((root_generation.mode, root_generation.uid, root_generation.gid, root_generation.mtime_ns) == (
        root_record.mode,
        root_record.uid,
        root_record.gid,
        root_record.mtime * 1_000_000_000,
    ))
    fs._require_empty_fd_xattrs(root, control)
    return len(observed)


def _fresh_cleanup_control():
    return fs.OperationControl(time.monotonic_ns() + CLEANUP_SECONDS * 1_000_000_000, lambda: False)


def _reload_and_cleanup(owned, control):
    error = None
    for node in (owned.root, owned.operation, owned.active.node):
        if node.identity_fd.disposition == "open":
            try:
                fs._close_node(node)
            except BaseException as close_error:
                error = fs.RootfsFsError(error, close_error)
    if error is not None:
        raise error
    active = builder._read_active_ledger(owned.locked.state, control)
    operation = fs._open_path_node(owned.locked.state, fs._name(owned.operation_name), "directory", control)
    root = fs._open_path_node(operation, builder.ROOT_NAME, "directory", control)
    refreshed = builder.OwnedOperation(owned.locked, active, operation, root, owned.operation_name)
    builder._cleanup_owned(refreshed, active, control)


def _materialize_unmasked(authority, owned, control):
    _fail(type(owned) is builder.OwnedOperation and type(control) is fs.OperationControl)
    fresh = plan.revalidate_build_inputs(authority)
    _fail(type(fresh) is plan.RootfsBuildInputs and fresh is not authority)
    active = owned.active
    root = owned.root
    try:
        entries = fresh.plan.entries
        directories = [entry for entry in entries if entry.record.kind == "directory"]
        files = [entry for entry in entries if entry.record.kind == "file"]
        hardlinks = [entry for entry in entries if entry.record.kind == "hardlink"]
        symlinks = [entry for entry in entries if entry.record.kind == "symlink"]
        for entry in sorted(directories, key=lambda item: (item.record.path.count("/"), item.record.path.encode("utf-8"))):
            active = _create_directory(active, root, entry, control)
        for entry in sorted(files, key=lambda item: item.record.path.encode("utf-8")):
            active = _create_file(active, root, entry, control)
        if hardlinks:
            active = _create_hardlinks(active, root, fresh, control)
        for entry in sorted(symlinks, key=lambda item: item.record.path.encode("utf-8")):
            active = _create_symlink(active, owned, root, entry, control)
        for entry in sorted(directories, key=lambda item: (-item.record.path.count("/"), item.record.path.encode("utf-8"))):
            active = _finalize_directory(active, root, entry, control)
        root_entry = plan.PlannedEntry("root", None, plan.MaterialRecord("rootfs", "directory", fresh.plan.root.mode, fresh.plan.root.uid, fresh.plan.root.gid, fresh.plan.root.mtime, 0, None, None, None, None, -1))
        active, root_generation = _metadata(active, root, "rootfs", root_entry.record, owned.operation, control)
        root = replace(root, generation=root_generation)
        refreshed = replace(owned, active=active, root=root)
        count = _postwalk(refreshed, root, fresh, control)
        return MaterializedRoot(refreshed, active, count)
    except BaseException as error:
        cleanup_control = _fresh_cleanup_control()
        try:
            _reload_and_cleanup(owned, cleanup_control)
        except BaseException as cleanup_error:
            raise fs.RootfsFsError(error, cleanup_error) from cleanup_error
        raise


def _materialize(authority, owned, control):
    return builder._fixed_umask(_materialize_unmasked, authority, owned, control)

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

MATERIALIZE_SECONDS = 900
NATIVE_PACKAGE_MATERIALIZE_SECONDS = 1_200
CLEANUP_SECONDS = 600


class MaterializerError(Exception):
    pass


MATERIALIZE_STAGES = frozenset({
    "internal", "plan", "dirs", "files", "hardlinks", "symlinks",
    "dir-meta", "root-meta", "postwalk",
})


class MaterializerWorkError(MaterializerError):
    def __init__(self, work_outcome, work_stage="internal"):
        _fail(work_outcome in {"cancelled", "deadline", "failed"}
              and work_stage in MATERIALIZE_STAGES)
        self.work_outcome, self.work_stage = work_outcome, work_stage
        super().__init__()


def _fail(condition):
    if not condition:
        raise MaterializerError()


@dataclass(frozen=True)
class MaterializedRoot:
    owned: builder.OwnedOperation
    active: builder.ActiveLedger
    entry_count: int


@dataclass(frozen=True)
class NativePackageControls:
    work: fs.OperationControl
    cleanup_deadline_ns: int


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


def _apply_metadata(node, parent, symlink_name, record, desired, control, node_chain):
    _fail(type(node_chain) is fs.HeldChain and node_chain.components[-1].node.generation == node.generation)

    def observe():
        return fs._observe_child(parent, symlink_name, control) if symlink_name is not None else _generation(node, control)

    def mutate(chain, action):
        fs._revalidate_chain(chain, control)
        before = observe()
        _fail(before == chain.components[-1].node.generation)
        _check(control)
        action()
        _check(control)
        after = observe()
        chain = builder._chain_after_parent(chain, before, after)
        fs._revalidate_chain(chain, control)
        return chain, after

    chain = node_chain
    if symlink_name is None:
        chain, _after = mutate(chain, lambda: os.fchown(node.operation_fd.number, record.uid, record.gid))
        chain, _after = mutate(chain, lambda: os.fchmod(node.operation_fd.number, record.mode))
        chain, after = mutate(
            chain, lambda: os.utime(node.operation_fd.number, ns=(record.mtime * 1_000_000_000,) * 2),
        )
        builder._fsync(node.operation_fd, control)
    else:
        chain, _after = mutate(
            chain,
            lambda: os.chown(
                symlink_name.raw, record.uid, record.gid,
                dir_fd=parent.operation_fd.number, follow_symlinks=False,
            ),
        )
        chain, after = mutate(
            chain,
            lambda: os.utime(
                symlink_name.raw, ns=(record.mtime * 1_000_000_000,) * 2,
                dir_fd=parent.operation_fd.number, follow_symlinks=False,
            ),
        )
        builder._fsync(parent.operation_fd, control)
    _fail(observe() == after)
    fs._revalidate_chain(chain, control)
    _fail((after.mode, after.uid, after.gid, after.size, after.mtime_ns) == ledger._parse_metadata(desired))
    return after, chain


def _metadata(active, node, path, record, parent, control, node_chain, symlink_name=None):
    _fail(type(node_chain) is fs.HeldChain and node_chain.components[-1].node.generation == node.generation)
    fs._revalidate_chain(node_chain, control)
    before = _generation(node, control)
    _fail(before == node_chain.components[-1].node.generation)
    desired = _desired(record, before.size)
    fs._revalidate_chain(node_chain, control)
    active = _append(active, "metadata-intent", {"token": builder._token(active), "path": path, "before": builder._g(before), "desired": desired}, control)
    transition = builder._transition_control()
    fs._revalidate_chain(node_chain, transition)
    after, node_chain = _apply_metadata(node, parent, symlink_name, record, desired, transition, node_chain)
    observed = {"token": builder._token(active), "path": path, "child": builder._g(after)}
    fs._revalidate_chain(node_chain, transition)
    active = _append(active, "metadata-observed", observed, transition)
    fs._revalidate_chain(node_chain, transition)
    active = _append(active, "metadata-settled", observed, transition)
    fs._revalidate_chain(node_chain, control)
    control.check()
    return active, after


def _create_directory(active, owned, root, entry, control):
    path = "rootfs/" + entry.record.path
    relative_parent, _separator, base = entry.record.path.rpartition("/")
    chain, _parent, opened = _fresh_chain_to_parent(owned, root, relative_parent, control)
    name = fs._name(base)
    try:
        active, child = builder._create_ledger_entry(active, chain, path, name, "directory", None, control)
        fs._close_node(child)
        return active
    finally:
        _close_final(opened)


def _create_file(active, owned, root, entry, control):
    path = "rootfs/" + entry.record.path
    relative_parent, _separator, base = entry.record.path.rpartition("/")
    chain, parent, opened = _fresh_chain_to_parent(owned, root, relative_parent, control)
    name = fs._name(base)
    child = None
    try:
        content = bytes(entry.content())
        _fail(len(content) == entry.record.archive_size)
        _fail(hashlib.sha256(content).hexdigest() == entry.record.content_sha256)
        active, child = builder._create_ledger_entry(active, chain, path, name, "file", content, control)
        current_parent = _generation(parent, control)
        current_chain = builder._chain_after_parent(
            chain, chain.components[-1].node.generation, current_parent,
        )
        node_chain = builder._chain_with_child(current_chain, name, child)
        active, _after = _metadata(active, child, path, entry.record, parent, control, node_chain)
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


def _parent_snapshot(node, control):
    return fs._enumerate_names_stable(node, control)


def _parent_value(snapshot):
    value = ledger.LedgerParent(snapshot.generation, tuple(item.text for item in snapshot.names))
    return ledger._parent_value(value)


def _create_hardlinks(active, owned, root, authority, control):
    plans = ledger._plan_hardlink_groups(authority)
    entries = {entry.record.path: entry for entry in authority.plan.entries}
    for group in plans:
        target_opened = ()
        target = None
        with builder._owned_nodes(lambda: target_opened + (() if target is None else (target,))):
            target_relative, _separator, target_base = group.target_path.rpartition("/")
            target_chain, target_parent, target_opened = _fresh_chain_to_parent(
                owned, root, target_relative, control,
            )
            target_name = fs._name(target_base)
            fs._revalidate_chain(target_chain, control)
            target = fs._open_path_node(target_parent, target_name, "file", control)
            target_node_chain = builder._chain_with_child(target_chain, target_name, target)
            fs._revalidate_chain(target_node_chain, control)
            content = fs._read_regular(target, group.size, control)
            fs._revalidate_chain(target_node_chain, control)
            state = ledger._new_hardlink_group(group, _generation(target, control), hashlib.sha256(content).hexdigest())
            body = {
                "token": builder._token(active),
                "target_path": "rootfs/" + group.target_path,
                "aliases": ["rootfs/" + value for value in group.aliases],
                "content_sha256": group.content_sha256,
                "target": builder._g(state.target),
            }
            fs._revalidate_chain(target_node_chain, control)
            active = _append(active, "hardlink-group", body, control)
            for index, alias_path in enumerate(group.aliases):
                alias_relative, _separator, alias_base = alias_path.rpartition("/")
                alias_chain, parent, opened = _fresh_chain_to_parent(owned, root, alias_relative, control)
                alias_name = fs._name(alias_base)
                alias_created = False
                alias_node = None
                delta = None
                try:
                    fs._revalidate_chain(target_chain, control)
                    fs._revalidate_chain(alias_chain, control)
                    before_parent = _parent_snapshot(parent, control)
                    fs._revalidate_chain(alias_chain, control)
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
                    fs._revalidate_chain(target_chain, transition)
                    fs._revalidate_chain(alias_chain, transition)
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
                    after_parent = _parent_snapshot(parent, transition)
                    after_target = _generation(target, transition)
                    alias_node = fs._open_path_node(parent, alias_name, "file", transition)
                    alias = alias_node.generation
                    delta = fs.ParentDelta("hardlink", alias_name, before_parent, after_parent)
                    fs._revalidate_chain(alias_chain, transition, delta)
                    target_delta = builder._delta_for_chain(target_chain, delta)
                    fs._revalidate_chain(target_chain, transition, target_delta)
                    current_alias_chain = builder._chain_after_parent(
                        alias_chain, before_parent.generation, after_parent.generation,
                    )
                    alias_node_chain = builder._chain_with_child(current_alias_chain, alias_name, alias_node)
                    current_target_chain = target_chain if target_delta is None else builder._chain_after_parent(
                        target_chain, before_parent.generation, after_parent.generation,
                    )
                    target_node = fs.HeldNode(target.identity_fd, target.operation_fd, after_target)
                    target_node_chain = builder._chain_with_child(current_target_chain, target_name, target_node)
                    fs._revalidate_chain(alias_node_chain, transition)
                    fs._revalidate_chain(target_node_chain, transition)
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
                    fs._revalidate_chain(alias_node_chain, transition)
                    fs._revalidate_chain(target_node_chain, transition)
                    active = _append(active, "hardlink-create-settled", observed, transition)
                    fs._revalidate_chain(alias_node_chain, transition)
                    fs._revalidate_chain(target_node_chain, transition)
                    control.check()
                    if target_delta is not None:
                        target_chain = current_target_chain
                        target_parent = target_chain.components[-1].node
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
                                _fail(type(delta) is fs.ParentDelta)
                                current_chain = builder._chain_after_parent(
                                    alias_chain, delta.before.generation, delta.after.generation,
                                )
                                fs._revalidate_chain(current_chain, cleanup)
                                before_remove = _parent_snapshot(parent, cleanup)
                                _fail(before_remove == delta.after)
                                current = fs._observe_child(parent, alias_name, cleanup)
                                _fail(current.key == target.generation.key)
                                fs._revalidate_chain(current_chain, cleanup)
                                os.unlink(alias_name.raw, dir_fd=parent.operation_fd.number)
                                after_remove = _parent_snapshot(parent, cleanup)
                                remove_delta = fs.ParentDelta("unlink", alias_name, before_remove, after_remove)
                                fs._revalidate_chain(current_chain, cleanup, remove_delta)
                                final_alias_chain = builder._chain_after_parent(
                                    current_chain, before_remove.generation, after_remove.generation,
                                )
                                builder._fsync(target.operation_fd, cleanup)
                                builder._fsync(parent.operation_fd, cleanup)
                                current_target = _generation(target, cleanup)
                                proof_chain, _proof_parent, proof_opened = _fresh_chain_to_parent(
                                    owned, root, target_relative, cleanup,
                                )
                                try:
                                    target_proof = builder._chain_with_child(
                                        proof_chain, target_name,
                                        fs.HeldNode(target.identity_fd, target.operation_fd, current_target),
                                    )
                                    fs._revalidate_chain(final_alias_chain, cleanup)
                                    fs._revalidate_chain(target_proof, cleanup)
                                    intent_body = builder._abort_body_from_snapshot(
                                        terminal.body_value(), alias_name, after_remove,
                                    )
                                    intent_body["target"] = builder._g(current_target)
                                    active = _append(active, "hardlink-create-abort", intent_body, cleanup)
                                    fs._revalidate_chain(final_alias_chain, cleanup)
                                    fs._revalidate_chain(target_proof, cleanup)
                                finally:
                                    _close_final(proof_opened)
                        except BaseException as cleanup_error:
                            error = fs.RootfsFsError(error, cleanup_error)
                    raise error
                finally:
                    _close_final(opened + (() if alias_node is None else (alias_node,)))
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
    parent_chain, parent, opened = _fresh_chain_to_parent(owned, root, parent_path, control)
    name = fs._name(base)
    child = None
    created = False
    delta = None
    try:
        fs._revalidate_chain(parent_chain, control)
        before = _parent_snapshot(parent, control)
        fs._revalidate_chain(parent_chain, control)
        active = _append(
            active,
            "create-intent",
            {"token": builder._token(active), "path": path, "kind": "symlink", "parent": _parent_value(before)},
            control,
        )
        transition = builder._transition_control()
        fs._revalidate_chain(parent_chain, transition)
        _check(transition)
        os.symlink(record.link_text, name.raw, dir_fd=parent.operation_fd.number)
        created = True
        _check(transition)
        child = fs._open_path_node(parent, name, "symlink", transition)
        after = _parent_snapshot(parent, transition)
        delta = fs.ParentDelta("create", name, before, after)
        fs._revalidate_chain(parent_chain, transition, delta)
        metadata_parent_chain = builder._chain_after_parent(
            parent_chain, before.generation, after.generation,
        )
        node_chain = builder._chain_with_child(metadata_parent_chain, name, child)
        fs._revalidate_chain(node_chain, transition)
        observed = {
            "token": builder._token(active),
            "path": path,
            "kind": "symlink",
            "parent": _parent_value(after),
            "child": builder._g(child.generation),
        }
        active = _append(active, "create-observed", observed, transition)
        builder._fsync(parent.operation_fd, transition)
        fs._revalidate_chain(node_chain, transition)
        active = _append(active, "create-settled", observed, transition)
        fs._revalidate_chain(node_chain, transition)
        control.check()
        active, generation = _metadata(
            active, child, path, record, parent, control, node_chain, name,
        )
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
                    _fail(type(delta) is fs.ParentDelta)
                    current_chain = builder._chain_after_parent(
                        parent_chain, delta.before.generation, delta.after.generation,
                    )
                    fs._revalidate_chain(current_chain, cleanup_control)
                    before_remove = _parent_snapshot(parent, cleanup_control)
                    _fail(before_remove == delta.after and current.key.kind == "symlink")
                    fs._revalidate_chain(current_chain, cleanup_control)
                    os.unlink(name.raw, dir_fd=parent.operation_fd.number)
                    after_remove = _parent_snapshot(parent, cleanup_control)
                    remove_delta = fs.ParentDelta("unlink", name, before_remove, after_remove)
                    fs._revalidate_chain(current_chain, cleanup_control, remove_delta)
                    final_chain = builder._chain_after_parent(
                        current_chain, before_remove.generation, after_remove.generation,
                    )
                    builder._fsync(parent.operation_fd, cleanup_control)
                    intent = builder._abort_body_from_snapshot(records[-1].body_value(), name, after_remove)
                    fs._revalidate_chain(final_chain, cleanup_control)
                    active = _append(active, "create-abort", intent, cleanup_control)
                    fs._revalidate_chain(final_chain, cleanup_control)
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


def _finalize_directory(active, owned, root, entry, control):
    path = "rootfs/" + entry.record.path
    relative_parent, _separator, base = entry.record.path.rpartition("/")
    parent_chain, parent, opened = _fresh_chain_to_parent(owned, root, relative_parent, control)
    name = fs._name(base)
    node = None
    try:
        fs._revalidate_chain(parent_chain, control)
        node = fs._open_path_node(parent, name, "directory", control)
        node_chain = builder._chain_with_child(parent_chain, name, node)
        fs._revalidate_chain(node_chain, control)
        active, _generation_value = _metadata(active, node, path, entry.record, parent, control, node_chain)
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
    fs._structural_increment("complete_walks")
    root_chain, _root_parent, root_opened = _fresh_chain_to_parent(owned, root, "", control)
    _fail(not root_opened)
    fs._revalidate_chain(root_chain, control)
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
    fs._revalidate_chain(root_chain, control)
    return len(observed)


def _fresh_cleanup_control():
    return fs.OperationControl(time.monotonic_ns() + CLEANUP_SECONDS * 1_000_000_000, lambda: False)


def _fixed_materialize_control(outer, seconds):
    _fail(type(outer) is fs.OperationControl and type(seconds) is int and seconds > 0)
    now_ns = time.monotonic_ns()
    deadline_ns = min(outer.deadline_ns, now_ns + seconds * 1_000_000_000)
    return fs.OperationControl(deadline_ns, outer.cancelled)


def _materialize_control(outer):
    return _fixed_materialize_control(outer, MATERIALIZE_SECONDS)


def _native_package_materialize_control(outer):
    return _fixed_materialize_control(outer, NATIVE_PACKAGE_MATERIALIZE_SECONDS)


def _work_failure(control):
    now_ns = time.monotonic_ns()
    try:
        cancelled = control.cancelled()
    except BaseException:
        return "failed"
    if type(cancelled) is not bool:
        return "failed"
    if cancelled:
        return "cancelled"
    return "deadline" if now_ns >= control.deadline_ns else "failed"


def _native_package_cleanup_control(control, deadline_ns):
    _fail(type(control) is fs.OperationControl and type(deadline_ns) is int)
    deadline = min(deadline_ns, time.monotonic_ns() + CLEANUP_SECONDS * 1_000_000_000)
    return fs.OperationControl(deadline, control.cancelled)


def _raise_work_failure(owned, control, primary, cleanup_deadline_ns=None, work_stage="internal"):
    work_outcome = _work_failure(control)
    cleanup_control = (_fresh_cleanup_control() if cleanup_deadline_ns is None
                       else _native_package_cleanup_control(control, cleanup_deadline_ns))
    try:
        _reload_and_cleanup(owned, cleanup_control)
    except BaseException as cleanup_error:
        primary = fs.RootfsFsError(primary, cleanup_error)
    raise MaterializerWorkError(work_outcome, work_stage) from primary


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
    operation = None
    root = None
    with builder._owned_nodes(lambda: (active.node,) + (() if operation is None else (operation,)) + (() if root is None else (root,))):
        operation = fs._open_path_node(owned.locked.state, fs._name(owned.operation_name), "directory", control)
        root = fs._open_path_node(operation, builder.ROOT_NAME, "directory", control)
        refreshed = builder.OwnedOperation(owned.locked, active, operation, root, owned.operation_name)
        builder._cleanup_owned(refreshed, active, control)


def _materialize_controlled(authority, owned, control, cleanup_deadline_ns=None):
    _fail(type(owned) is builder.OwnedOperation and type(control) is fs.OperationControl)
    _fail(cleanup_deadline_ns is None or type(cleanup_deadline_ns) is int)
    active = owned.active
    root = owned.root
    stage = "plan"
    try:
        fresh = plan.revalidate_build_inputs(authority)
        _fail(type(fresh) is plan.RootfsBuildInputs and fresh is not authority)
        entries = fresh.plan.entries
        directories = [entry for entry in entries if entry.record.kind == "directory"]
        files = [entry for entry in entries if entry.record.kind == "file"]
        hardlinks = [entry for entry in entries if entry.record.kind == "hardlink"]
        symlinks = [entry for entry in entries if entry.record.kind == "symlink"]
        stage = "dirs"
        for entry in sorted(directories, key=lambda item: (item.record.path.count("/"), item.record.path.encode("utf-8"))):
            active = _create_directory(active, owned, root, entry, control)
        stage = "files"
        for entry in sorted(files, key=lambda item: item.record.path.encode("utf-8")):
            active = _create_file(active, owned, root, entry, control)
        stage = "hardlinks"
        if hardlinks:
            active = _create_hardlinks(active, owned, root, fresh, control)
        stage = "symlinks"
        for entry in sorted(symlinks, key=lambda item: item.record.path.encode("utf-8")):
            active = _create_symlink(active, owned, root, entry, control)
        stage = "dir-meta"
        for entry in sorted(directories, key=lambda item: (-item.record.path.count("/"), item.record.path.encode("utf-8"))):
            active = _finalize_directory(active, owned, root, entry, control)
        stage = "root-meta"
        root_entry = plan.PlannedEntry("root", None, plan.MaterialRecord("rootfs", "directory", fresh.plan.root.mode, fresh.plan.root.uid, fresh.plan.root.gid, fresh.plan.root.mtime, 0, None, None, None, None, -1))
        root_chain, _root_parent, root_opened = _fresh_chain_to_parent(owned, root, "", control)
        _fail(not root_opened and root_chain.components[-1].node.generation == _generation(root, control))
        metadata_root = replace(root, generation=root_chain.components[-1].node.generation)
        active, root_generation = _metadata(
            active, metadata_root, "rootfs", root_entry.record, owned.operation, control, root_chain,
        )
        root = replace(root, generation=root_generation)
        refreshed = replace(owned, active=active, root=root)
        stage = "postwalk"
        count = _postwalk(refreshed, root, fresh, control)
        return MaterializedRoot(refreshed, active, count)
    except BaseException as error:
        _raise_work_failure(owned, control, error, cleanup_deadline_ns, stage)


def _materialize_unmasked(authority, owned, outer_control):
    _fail(type(outer_control) is fs.OperationControl)
    return _materialize_controlled(authority, owned, _materialize_control(outer_control))


def _native_package_materialize_unmasked(authority, owned, controls):
    _fail(type(controls) is NativePackageControls)
    return _materialize_controlled(
        authority, owned, _native_package_materialize_control(controls.work),
        controls.cleanup_deadline_ns)


def _materialize(authority, owned, control):
    return builder._fixed_umask(_materialize_unmasked, authority, owned, control)


def _native_package_materialize(authority, owned, controls):
    return builder._fixed_umask(
        _native_package_materialize_unmasked, authority, owned, controls)

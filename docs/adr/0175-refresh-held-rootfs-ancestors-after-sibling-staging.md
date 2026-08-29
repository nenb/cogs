# ADR 0175: Refresh held rootfs ancestors after sibling staging

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-25

The H18 private replay durably reached `RUNTIME_STAGED_V3` and started and retained the private containerd daemon. The subsequent complete rootfs verification rejected its own held chain. Rootfs content, root inode, mode, ownership, link count, size, mtime, and ctime still exactly matched the leased identity. The expected mutation was to the sibling `kata-runtime-v1` under `completion-v1`; adding daemon configuration and sockets changed the held ancestor directory generation while leaving the rootfs subtree unchanged.

Before each complete postwalk, refresh only generations observed through the already-held base identity and operation descriptors. Require every mount/device/inode/kind key, mode, uid, and gid to remain identical. Continue to reconstruct the state, rootfs operation, and root nodes independently, verify their exact durable generations, walk and hash every rootfs object, enforce metadata/xattr/link invariants, and revalidate the refreshed chain before and after the walk.

This accepts no pathname replacement and no rootfs mutation. It permits only generation changes on descriptor-held ancestors caused by the reviewed sibling runtime transaction. H18 failed and grants no qualification or promotion claim; its tokenized network and fixed state were privately inventoried, removed, and independently checked for zero residue.

This decision grants no retry, production fast path, evidence, promotion, AWS, provider, deployment, or release authority.

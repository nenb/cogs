# ADR 0093 launcher API note

This note replaces the ADR 0092 launcher handoff. It grants no native, sudo, workflow, provider, cloud, or AWS execution authority.

## Sole operation issuer

`invoke_fixed_admitted_operation` and its caller-derived tree authority no longer exist. Importing or compiling the launcher as an ambient module exposes no production invocation API.

The sole production entry is the fixed launcher bootstrap CLI, `_bootstrap_main()`. Its independently authenticated issuer must, before starting tracked launcher or client code:

1. fix one job/profile and one separately authenticated 40-hex Git head;
2. hold the four `_FIXED_SOURCE_SET` generations and the selected fixed client generation;
3. obtain their `100644` blob object IDs from that exact Git tree, never derive object IDs from supplied bytes;
4. compare every held generation and complete byte string with those tree objects;
5. execute the held launcher generation with fixed `/usr/bin/python3 -I -B`, empty environment, and exactly descriptors 0–4; and
6. supply the closed canonical admission on fd 3 and the sealed held-source/client capsule on fd 4.

The bootstrap revalidates capsule framing, exact source/client path order, Git blob identities, per-object digests, aggregate source-set digest, launcher digest, fixed profile, and result type. It dispatches exactly one of A, B, C, D, E, or integration and emits the unchanged canonical result on stdout. The exact result classes, fields, versions, and CLI exit meanings are unchanged.

A bytes mapping, digest, revision argument, caller-created `MappingProxyType`, or private helper call is not operation authority. Portable `_with_ops` functions are syscall seams only and are not production invocation APIs.

## Independent root pin

The E command no longer contains caller-rendered Python or caller-rendered authority. It is exactly:

```text
/usr/bin/sudo -n --close-from=3 /usr/bin/env -i \
  /usr/bin/python3 -I -B \
  /usr/local/libexec/cogs-native-root-bootstrap-v1.py
```

Before any authorized E execution, an independently privileged provisioning decision must install:

- exact `_ROOT_BOOTSTRAP` bytes as root-owned, regular, non-group/world-writable `/usr/local/libexec/cogs-native-root-bootstrap-v1.py`; and
- a root-owned, regular, non-group/world-writable canonical JSON pin at `/etc/cogs/native-root-authority-v1.json`.

The closed pin fields are:

```text
bootstrap_sha256 revision root_bootstrap_sha256
source_set_sha256 sources version
```

`version` is exactly `cogs.root-capsule-authority/v1`. `sources` is the exact ordered four-row `path/sha256/size` inventory. The bootstrap opens both fixed root-owned names with `O_NOFOLLOW`, completely reads and generation-checks them, verifies its own SHA-256 against `root_bootstrap_sha256`, then compares the capsule revision, launcher digest, source-set digest, and all source rows with the independent pin before compiling supplied launcher bytes.

The unprivileged capsule cannot select, render, replace, or transport this authority. Missing/mismatched provisioned state fails closed. This repository change does not provision the files or grant sudo execution authority.

## B and integration tool-child ownership

The namespace creator retains each atomically returned tool-child pidfd while that child remains behind its creation gate. A dedicated credentialed `SCM_RIGHTS` transfer binds nonce, sequence, `tool:<gzip|zstd>` case, `tool` role, PID, parent, start time, executable, session, and process group.

The outer surviving owner leases the received pidfd, rereads exact identity, records the descendant edge, verifies stable identity census and transfer EOF, and acknowledges registration. Only then may the creator release the child, close its duplicate pidfd, and drop local ownership. There is no secondary `pidfd_open(child_pid)` registration. Send, receive, identity, EOF, or acknowledgement failure leaves the child gated under creator-owned cleanup.

## D lifecycle ownership

Each D leader and descendant is created with `_ProcessOwner.spawn()`. The descendant first blocks on its registration gate. Before it can arm PDEATHSIG, change TERM handling, publish readiness, or consume the case gate, the creator transfers its atomic pidfd and complete case/role/credential/identity packet; the outer owner registers it and acknowledges.

Creator primary and cleanup failures are retained and sent as categorical failure packets when the control channel survives. Outer cleanup, endpoint cleanup, subreaper restoration, and final fd/child baselines continue after primary failure. Signal evidence requires exact `si_pid`, expected `si_uid`, `CLD_KILLED`, and `SIGKILL`, followed by matching nonblocking `waitpid` reap.

The three result transactions and the exact `LifecycleQualificationResult` remain before-release, after-release, and TERM-then-KILL.

## E inner ownership

The E inner process remains behind its `_ProcessOwner.spawn()` registration gate while the leader transfers the creator-held pidfd. The root outer owner validates credentials, sandbox case/inner role, complete identity, stable descendant census, and transfer EOF before acknowledging. The leader releases the inner only after that acknowledgement, then closes its duplicate authority.

Thus chroot, mount finalization, capability drop, seccomp installation, post-entry reporting, and final-gate behavior cannot begin in the inner before the surviving outer owner has exact pidfd/identity authority. Creator cleanup failures remain categorical rather than being silently discarded.

## Working-tree content identities

These values identify the corrected launcher content before this note's commit metadata is added:

- launcher SHA-256: `58e455583df0e4e0023e4cb9a80ad5633d4fd15a88bede28155cb98630590049`
- launcher Git-blob SHA-1: `665a61f14f5315fca0d55813ff7f55cee9684b13`
- four-source framed SHA-256: `a13e2d47afe91dc5272ee95156257f1b94984eca0d2ffe9904fd46cc541a5c6f`
- fixed root-bootstrap SHA-256: `815b3f941f8092be5ea51c7a6f1b180c1ee69093f73b45f9ee44f691bbeb5e44`

A later exact-head review must recompute all four. Hashes alone grant neither bootstrap-issuer authority nor root provisioning/sudo authority.

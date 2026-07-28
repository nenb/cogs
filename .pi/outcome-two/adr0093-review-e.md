# ADR 0093 fresh exact-head hostile review — E

- **Exact reviewed head:** `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`
- **Branch:** `review/o2-93-e`
- **Scope:** independent root source authority, fixed sandbox-only root dispatch, inner transfer-before-effects, post-chroot readback, E cleanup, Job E/common receipt provenance, and the complete E portable corpus.
- **Execution boundary:** static and portable only. No sudo, namespace, mount, seccomp, native selector/workflow, network acquisition, provider, cloud, AWS, deployment, production, or release action was invoked.
- **Verdict:** **BLOCKED — no ADR 0093 E signoff**

## Severity summary

| Severity | Count |
| --- | ---: |
| P0 | 0 |
| P1 | 2 |
| P2 | 1 |
| P3 | 0 |

## P0

None.

## P1

### P1-1 — The pre-transfer leader-death window still has no surviving owner for the inner child

The inner is created under the leader-local `_ProcessOwner` and blocks on that owner's gate (`completion_trusted_runtime_launcher.py:2737-2752`). The outer knows only the leader until `receive_descendant()` has received and registered the transferred pidfd at `:2871-2879`. If readiness/receive/ancillary/packet validation times out or rejects before that registration, outer cleanup at `:2905-2910` stops the leader by pidfd. A TERM/KILL exit bypasses the leader's Python exception cleanup at `:2793-2817`.

Closing the killed leader's inherited write gate makes the inner's read at `:2647` return EOF. The inner safely performs no sandbox effect, but exits 125 at `:2648,2685-2686`. Because the root outer is already a child subreaper, it can adopt that inner. It has no inner lease or pidfd, performs no recursive post-stop census/adoption, and restores subreaper state before raising. Thus the exact all-path reap authority rejected in the ADR 0092 E review remains absent; moving effects behind the gate does not close ownership or reap.

This violates ADR 0093 §§5 and 8. Transfer failure does not always execute a creator-owned cleanup path, and the surviving outer owner cannot prove settlement of the blocked inner.

### P1-2 — A fallible root-object open after successful creation leaves a persistent root-owned path

`_RootOwner.prepare()` records only creation intent, creates `/tmp/.cogs-runtime-root`, and then opens it (`completion_trusted_runtime_launcher.py:1257-1260`). If the `open` at `:1259` fails after `mkdir` succeeds, `self.identity` has not been set. Recovery observes the directory but deliberately rejects it because `self.identity is None` (`:1275-1286`), then raises cleanup uncertainty without removing it (`:1291`).

The failed root capsule therefore leaves a root-owned mode-0700 path that blocks later E attempts and violates exact path restoration. The portable fixture has a `mkdir` failure but no post-create `open`/identity-acquisition cut, so this production gap is green.

## P2

### P2-1 — The E corpus is causal for its selected rows, but is not the required complete cut corpus and cannot expose P1-1

The 22 E rows in `test/fixtures/outcome-two/launcher/sandbox-process-cases.jsonl` omit the central transfer send, receive, credentials, rights, identity, EOF, census, acknowledgement, and release cuts. They also omit transfer-socket creation as a distinct second socketpair, inner parent/PDEATHSIG, result/final gates, inner exit and wait/reap status, root open after mkdir, most namespace-handle/open/ioctl/close cuts, and per-descriptor cleanup failures. This does not satisfy ADR 0093 §§8 and 10's explicit every-transfer/chroot-readback/mount/exit/reap/namespace/restoration requirement.

The success oracle only requires an unordered set containing chroot and two exit events (`test/outcome-two-trusted-launcher-portable.py:1666-1669`); it does not prove transfer acknowledgement precedes chroot. The modeled baseline also treats every exited process as absent without recording a wait/reap (`:1531-1538,1558-1563`). Consequently an adopted exited-but-unreaped inner such as P1-1 can satisfy the cleanup oracle. Declared/selected/consumed/oracle equality at `:1676-1677` proves only that the incomplete declared set ran.

## P3

None.

## Confirmed properties

- Root authority is no longer caller-rendered. The fixed sudo command names `/usr/local/libexec/cogs-native-root-bootstrap-v1.py`; the root bootstrap independently reads root-owned fixed bootstrap/authority paths, generation-checks them, authenticates revision/launcher/source-set/all rows, and does so before compiling capsule launcher bytes. Missing provisioning fails closed and grants no execution authority.
- Root dispatch is sandbox-only: `_root_capsule_entry()` authenticates the capsule and directly invokes `_sandbox_only_transaction`; it neither loads the runtime closure nor reopens checkout source paths.
- On the nominal path, the outer receives and identity-checks the exact inner pidfd, proves stable descendant census and transfer EOF, and acknowledges before the leader releases the inner. Chroot and later effects are therefore ordered after outer authority on that path.
- The inner reports only after remount/chroot/capability/seccomp transitions, then remains behind its final gate while the outer reads namespace ownership, mount flags, `/proc/<pid>/root`, and checkout/host-path absence.
- Job E is unprivileged and receipt-only. It invokes one common-owned operation, does not inspect the returned result, settles once, and supplies only failure phase/diagnostic/primary error to publication.
- Common now retains workflow/common/driver/schema identities and admitted schema bytes before effects, derives E checks and fixed policy metadata from the private operation receipt, and validates publication against those retained identities rather than post-operation source rereads.
- Relevant gross additions remain within ADR 0093 highs: launcher `3523/4700`, trusted-launcher portable `2219/2300`, Job E driver `95/620`, Job E focused test `87/500`, and fixture aggregate `502/1700` lines.

## Exact-head identities

Recomputed at the reviewed head:

- launcher SHA-256: `987d6080aad83c18783898df9338bd84febe165cf46912847d027c8eeb24852e`
- launcher Git blob: `e5d27b13a4a514f80e6e0b20c6ce3e12d36b32fe`
- four-source framed SHA-256: `dde990d2e7adde92be4ef63b1e72042cfdb64232a73a4361863c7ceae68935bc`
- fixed root-bootstrap SHA-256: `815b3f941f8092be5ea51c7a6f1b180c1ee69093f73b45f9ee44f691bbeb5e44`

The older values in the launcher API note are explicitly pre-follow-up-content identities and are not execution authority.

## Verification

- `git rev-parse HEAD` — exact reviewed head.
- `git diff --check 3846383..HEAD` and `git diff --check HEAD^..HEAD` — pass.
- `git fsck --no-progress --no-dangling` — pass.
- Python AST parse for launcher, common, Job E, trusted-launcher portable, and recovery portable — pass.
- `/usr/bin/python3 -I -B test/outcome-two-trusted-launcher-portable.py` — pass.
- `/usr/bin/python3 -I -B test/outcome-two-recovery-portable.py` — pass.
- `/usr/bin/python3 -I -B test/outcome-two-lifecycle-portable.py` — pass.
- Focused TypeScript/AST/accounting tests — not run because local `tsx` is absent; no dependency acquisition was attempted.

The passing portable suites do not override the omitted cuts or production cleanup findings.

# SIGNOFF: BLOCKED

Do not authorize native execution, sudo/bootstrap provisioning, workflow dispatch/rerun, artifact reliance, production, release, issue closure, provider/cloud/AWS/OpenTofu/deployment activity, or an ADR 0093 E completion claim at `0db8c26`.

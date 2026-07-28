# ADR 0092 exact-head hostile review — production API and Jobs A/B

- **Reviewed implementation head:** `3846383f0d88c190226356ca9aeeeda402943aaa`
- **Scope:** A/B production owners, held-source/client admission, exact A mapping evidence, B parser/top-closure/mask-63/fixed-output evidence, A/B clients, schema/common bindings, and focused portable companions
- **Method:** fresh static/source review and portable non-native tests only
- **Native/cloud execution:** **not performed**. No `--workflow-bound` selector, sudo, namespace, mount, seccomp, `map_files`, compression executable, workflow, provider, cloud, or AWS operation was invoked.
- **Verdict:** **BLOCKED**

## P0

No P0 finding.

## P1 findings

### P1-1 — The launcher’s “admitted” public entry can self-sign arbitrary caller bytes and execute them from an ambient module

Common’s intended route does authenticate held source/client bytes against `context.head_sha` before compiling the held launcher (`scripts/native-qualification/common.py:363-368`). The launcher entry does not retain or require that authenticated caller authority, however. `invoke_fixed_admitted_operation()` accepts a caller-created `MappingProxyType` and digest, then manufactures both source and client tree identities directly from those same supplied bytes with `_transport_tree()` (`completion_trusted_runtime_launcher.py:2379-2407`). `_prepare_client_from_admitted_bytes()` consequently validates caller bytes against caller-derived object IDs, packages the supplied launcher as its own bootstrap authority, and `_invoke_prepared_client()` executes that generation (`:2225-2255`, `:2332-2337`).

There is no exact synthetic-module check, private one-shot caller receipt, or fixed-head tree identity at this public boundary. An ambient import can therefore call the production entry with four self-consistent unauthorized generations, an arbitrary 40-hex revision, and an arbitrary client; `MappingProxyType` and `source_set_digest` are format checks, not admission authority. The inner capsule only repeats the self-signed identities. This violates ADR 0092 section 2’s requirement that exact Git admission precede tracked execution and the retained A/B rule that an ambient module reject before its first authority-bearing effect.

The authentic common route being correct does not close the second ambient production route. The launcher entry must consume non-caller-forgeable, one-shot authority bound to common’s exact Git-tree observations (or otherwise prove it is the exact admitted synthetic module) before preparing or executing supplied bytes.

### P1-2 — A/B and held-admission portable acceptance still substitutes completed results and private helpers for the complete production paths

The required production-path matrices are absent:

- The A maps corpus invokes private mapping branches and `_mapped_closure`; its only complete-owner call is a replay rejected before effects. Complete owner composition is asserted by source token searches (`test/outcome-two-mapped-closure-portable.py:249-276`), not by driving `_qualify_fixed_python_mapping_with_ops` through resolve, registration, helper release, mapping, stop/reap, close, and baseline cuts.
- `common_production_adapters()` replaces `module.invoke_fixed_admitted_operation` with a local function returning fabricated typed A/B results (`test/outcome-two-trusted-launcher-portable.py:762-850`). It therefore stops exactly above the held launcher, bootstrap dispatcher, A owner, and B owner that the acceptance rule requires.
- `fixed_bootstrap_modes()` checks only a dictionary and ordinary-result field inventory (`:736-751`). It does not execute mapping/compression bootstrap modes, remove their selected owner edge, or challenge parser/closure/schema/client generations, mode substitution, replay, or authority-before-effect ordering.
- The A/B TypeScript companions build completed dictionaries and test client normalization plus source regexes. They do not invoke either production owner. B has no production cut corpus for closure preparation, issuance, both tools, final mappings, six individual seal bits, fixed-byte comparison, or cleanup.
- The outer-process ledger reaches `_run_held_python_with_ops`, but its modeled clone takes only the parent branch and returns `{}`; it proves selected outer mechanics, not held bootstrap/owner execution or result authenticity.

Thus ADR 0092 section 9’s declared = selected = consumed = oracle requirement is not an accepting gate for A, B, or held-source admission. The green tests cannot detect P1-1 and cannot establish that removing an A mapping edge, B parser/top-closure edge, mask-63 check, or fixed-byte producer comparison fails the complete production transaction.

## P2 findings

### P2-1 — The frozen ADR 0092 launcher/source identities describe the parent, not exact head

`.pi/outcome-two/adr0092-launcher-api.md:48-51` freezes launcher and four-source identities, but exact head has different bytes:

| Identity | Frozen note | Exact head `3846383` |
| --- | --- | --- |
| launcher SHA-256 | `9291ca06ba4d5721b35a1c1c950cfd3d33d93b34e740760684f7bd018d3b97ec` | `7ab2a2892aac4c561144592ec1b5ed83360222f86d2e6ccaa85f596ec7d43065` |
| launcher Git-blob SHA-1 | `2114d47ec917582c6e47e2e9696e28602efb1442` | `500849612c939f4a038bc201f04199ee74b232ca` |
| four-source framed SHA-256 | `25aeb9d764dbe12dec330d408ddccd9f75fba986cd02b4ce132c6c6b7b016447` | `5844f093e09913bd9d4345edc49994527ee8b826c85f7d21fb68fe0868ca40b7` |

The frozen root-bootstrap template hash still matches `73434c215c43d9806129961246933237a197d1c2455355e098965bebd5af09f2`. The other values are the `5367cdf` parent identities and were not refreshed after this commit changed the launcher. Runtime common admission derives current exact-head blobs, so this is not an immediate bypass, but the API note cannot serve as the claimed exact source/sudo handoff freeze or as input to a later execution ADR.

## P3 findings

### P3-1 — The mandatory readable-transition gate is not implemented

ADR 0092 requires AST/static checks over closure, launcher, common, and all six clients that reject multiple fallible effects or claim derivations packed onto one physical line. The only purported gate checks just `common.py`, only `Try`/`With` nodes at line 800 or later, and merely requires those statements to span more than one line (`test/native-qualification-common.test.ts:393-407`). It examines none of the required effect/lease transitions and none of closure, launcher, or the clients.

Packed authority transitions remain, for example `FdRegistry.adopt()` performs `_numbers.add` and `_leases.append` on one line (`scripts/native-qualification/common.py:116`), where failure between the two leaves split registry state. Common is exactly `1250/1250` and the launcher exactly `3500/3500`; a width-only/non-single-line-`Try` check is not the accepted readability guard at those highs.

## Verified positive properties

- The intended common route holds no-follow source/client descriptors, verifies exact Git blob IDs at the requested head, checks retained generations, and compiles the held launcher only after that admission.
- A dispatch reaches the closure-owned `_qualify_admitted_fixed_python_mapping`; the obsolete launcher mapping coordinator is absent. The owner resolves fixed Python, uses the production helper/mapping machinery, compares the exact mapped role/digest sequence, and closes/reaps before result construction.
- A client, common semantics, and schema independently enforce ordered executable/loader/libraries, dependency/provider closure, digest-role conflict rejection, exact mapped sequence, and recomputed closure/mapping summaries.
- B’s production result contains the closed parser observation. Driver/common recompute parser, per-tool, and aggregate parser/zstd/gzip closure digests; runtime and top-level closure identities are bound.
- Producer, decoder, driver, common, schema, and focused tests retain seal mask `63`. Production compares actual output bytes with `b"cogs-runtime-qualification-v1\n"`; driver/common bind both output digests to `6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8`.
- A/B clients are thin fixed-operation callers, publish only closed metadata, catch `Exception` around their workflow bodies, and preserve successful exit zero.
- Measured relevant additions remain within ADR 0092 highs: closure `2647/2650`, launcher `3500/3500`, common `1250/1250`, A driver/test `194/360` and `176/240`, B driver/test `284/430` and `205/280`, trusted-launcher portable `1200/1650`, mapped-closure portable `288/550`, and runtime-closure portable `700/700`.

## Portable/static verification

- Exact clean head before review: **PASS** — `3846383f0d88c190226356ca9aeeeda402943aaa`.
- Python compile for closure, launcher, common, A, and B: **PASS**.
- `test/outcome-two-runtime-closure-portable.py`: **PASS**, but not A/B production acceptance under P1-2.
- `test/outcome-two-mapped-closure-portable.py`: **PASS**, non-accepting under P1-2.
- `test/outcome-two-trusted-launcher-portable.py`: **PASS**, non-accepting for held A/B owner composition under P1-2.
- `node --test test/native-qualification-a.test.ts test/native-qualification-b.test.ts`: **PASS, 10/10**, non-accepting for production-owner reachability under P1-2.
- `git diff --check 3846383^..3846383`: **PASS**.
- `git fsck --no-progress --no-dangling`: **PASS**.
- Locked `node_modules/.bin/tsx` is absent; no dependency or network acquisition was attempted.
- Native selectors, privileged primitives, workflow/provider/cloud/AWS operations: **not run**.

## Signoff

**BLOCKED.** Exact head `3846383f0d88c190226356ca9aeeeda402943aaa` has unresolved P1, P2, and P3 findings. It does not qualify for ADR 0092 A/B signoff, native execution authority, artifact reliance, production/release/issue closure, or cloud/AWS action.

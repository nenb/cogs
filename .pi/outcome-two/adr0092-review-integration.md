# ADR 0092 hostile review — integration/common report boundary

**Disposition: BLOCKED**

- **Exact implementation head reviewed:** `3846383f0d88c190226356ca9aeeeda402943aaa`
- **Exact tree:** `b188cbea24b8abe8a4a46814f7337ddca90cddcb`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Scope:** thin integration, admitted ordinary production owner/result/digests, common operation/result authority, integration report metadata, durable report cleanup, focused/portable acceptance, and exact deterministic identities.
- **Method:** fresh hostile static and portable review. No `--workflow-bound` selector, native primitive, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, or AWS operation was invoked.

## Severity verdict

| Severity | Count | Verdict |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 2 | **blocking** |
| P2 | 0 | none additional |
| P3 | 1 | unresolved |

ADR 0092 requires no unresolved P0–P3. This head is not eligible for signoff or later native-execution authority.

## Findings

### P1-1 — Common still trusts duplicated caller check authority for integration and can publish a false ordinary result

**Requirements:** ADR 0092 sections 3, 5, and 9: the immutable production receipt is the sole pass authority; publication recomputes checks from that exact result; caller-fabricated operations cannot publish; portable acceptance must reject completed-claim substitution.

`NativeSession` stores the receipt at `scripts/native-qualification/common.py:1143-1146`, but settlement requires only that `_receipt` be non-`None` (`:1157-1159`). At publication, `_bind_candidate()` accepts the caller-created `production_checks` merely because every value is the string `"pass"` (`:1178-1180`). The integration branch binds only the four metadata rows and source-set digest (`:1194-1197`); unlike the C/D fallback at `:1198-1200`, it never derives or verifies the ordinary result's boolean observations, version, marker, revision, or fixed outputs from the receipt. `publish()` then copies those caller checks into the authoritative report (`:1203-1224`).

A portable counterexample ran the common state machine, replaced its accessible `_receipt` with an internally hash-consistent integration receipt having `pid_one=False`, supplied all-pass integration checks and exact receipt-derived digest metadata, settled an unchanged baseline, and published:

```text
pass {'id': 'closure_prepared', 'outcome': 'pass'} forged_pid_one= False
```

This is the same mutation model the checked-in common test intentionally applies to C at `test/native-qualification-common.test.ts:236-242`; C rejects because the fallback inspects every observation, while integration accepts. The exact launcher normally decodes all-true runtime results, and `thin-integration.py:50-97` independently rejects a false field, but those are not a repair: common's publication authority must bind its own private receipt rather than trust duplicated driver check claims. A fabricated/replaced receipt or caller bypass can therefore produce pass authority for an ordinary result that the thin integration itself would reject.

**Required correction:** make the private one-shot receipt non-replaceable from the caller boundary and have common derive every integration check and deterministic metadata row from the exact receipt. At minimum, common must independently validate the complete ordinary inventory, exact version/marker/revision/source identity, all observations, both fixed outputs, and digest-role relations before publication. Add the integration analogue of the existing false-C receipt mutation and a skip/fabricated-receipt case.

### P1-2 — The durable cleanup receipt is self-authorizing and does not retain the report generation/digest it claims

**Requirements:** ADR 0092 section 4: one durable generation custodian, an opaque cleanup capability, closed receipt state/identities, exact retained transaction or baseline restoration, and preservation of foreign/replaced state.

The receipt publishes the raw cleanup capability as well as its digest (`common.py:839-848`). Any same-UID process that can read the mode-0700 report directory therefore has the supposed opaque authenticator. Cleanup derives the abstract socket and request authority from that receipt-selected raw value (`:1046-1069`), with only same-UID peer authentication at the live custodian (`:1027-1032`). This preserves the substitute-custodian shape rather than separating durable public identity from an opaque custodian capability.

More directly, `_read_receipt()` checks only key cardinality, version/job, capability self-hash, a self-declared directory identity, and current code hashes (`:898-920`). It does **not** validate:

- `state == "publish-intent"` or any legal durable state;
- the recorded socket against `_socket_name(context, capability)`;
- `report_sha256`, `report_size`, or their types/bounds;
- the recorded report/slot identity shapes;
- the slot bytes against the capability; or
- the published report bytes against the recorded digest and size.

A portable probe created a canonical receipt with exact current code hashes but `state="forged-state"`, `socket="forged-socket"`, `report_sha256="not-a-digest"`, and `report_size=-1`; `_read_receipt()` accepted it and printed:

```text
forged-state forged-socket not-a-digest -1
```

The later classifier does not close this gap. `_identity()` records only device/inode/mode/owner/group/size (`:756-758`), omitting timestamps and content digest, and `_cleanup_owned()` compares only those receipt-selected identities before exchange/unlink (`:951-984`). Thus an in-place same-size modification of `report.json` is not a generation mismatch, the recorded report digest is never rechecked, and a self-consistent replacement directory/receipt can select the generations cleanup removes. The durable classifier test at `test/native-qualification-common.test.ts:288-336` mocks exactly these shallow identities and never mutates receipt state, capability, report bytes, digest, or size.

This breaks exact report authority across upload and the requirement that foreign/replaced generations be preserved. It affects integration's report exactly as it affects A–E.

**Required correction:** keep the raw capability outside the readable receipt (record only its digest and independently retained custodian authority); validate a closed receipt schema/state; bind socket/context independently; open and generation-check the slot/report; recompute report bytes, size, canonical schema/semantics, and digest immediately before cleanup/retirement; include complete generation fields; and make crash fallback require the same non-self-signed authority. Add before/after mutation, same-inode same-size rewrite, forged receipt, forged endpoint, whole-directory replacement, and capability-disclosure cases to the declared/selected/consumed/oracle corpus.

### P3-1 — The frozen launcher/source identity note is stale at the exact reviewed head

`.pi/outcome-two/adr0092-launcher-api.md` records launcher SHA-256 `9291ca06...`, launcher Git-blob SHA-1 `2114d47e...`, and four-source digest `25aeb9d7...`. At exact head `3846383`, the corresponding deterministic values are:

- launcher SHA-256: `7ab2a2892aac4c561144592ec1b5ed83360222f86d2e6ccaa85f596ec7d43065`
- launcher Git-blob SHA-1: `500849612c939f4a038bc201f04199ee74b232ca`
- four-source framed SHA-256: `5844f093e09913bd9d4345edc49994527ee8b826c85f7d21fb68fe0868ca40b7`

The root-bootstrap template SHA-256 remains the documented `73434c21...`. The note says it freezes the corrected launcher handoff, so leaving three exact identities stale undermines deterministic review metadata even though the note correctly says its template hash alone grants no sudo authority.

## Confirmed properties

- `thin-integration.py` is thin: it invokes exactly `session.run_fixed_operation("integration")`, owns no source bootstrap, process supervisor, sudo path, or native primitive, and delegates cleanup/reporting to common.
- Common authenticates and retains the exact four source generations and integration client against the exact Git head before compiling the held launcher (`common.py:355-375`).
- Launcher operation mapping binds `integration -> runtime -> RuntimeQualificationResult`; the ordinary bootstrap reaches `_launch_admitted_fixed_runtime_qualification`, not the sandbox-only owner.
- The thin result decoder requires the exact ordered ordinary inventory, exact version/marker/revision/source digest, exact types, every boolean true, and both fixed marker-output digests.
- Integration metadata construction is deterministic in the order `closure`, `gzip_output`, `source_set`, `zstd_output`; common binds those rows to its receipt and independently rejects marker/closure/source role aliasing in report semantics.
- There is no second production/native owner in the thin client. The blocking duplicated authority is the caller-supplied pass-check path inside common, not a duplicate runtime implementation.
- Exact ADR 0092 line highs are met for the reviewed surfaces: launcher `3500/3500`, common `1250/1250`, thin integration `188/430`, common test `408/1000`, and integration test `138/300` gross additions from the accounting predecessor.

## Verification

Passed:

- `git diff --check 3846383^..3846383`
- Python AST parsing for launcher, common, and thin integration
- `/usr/bin/python3 -I -B test/outcome-two-trusted-launcher-portable.py`
- `node --test --experimental-strip-types test/native-qualification-integration.test.ts` — 5/5
- hostile portable false-integration-receipt publication probe — reproduced P1-1
- hostile canonical forged-receipt probe — reproduced P1-2

Not run:

- `test/native-qualification-common.test.ts` could not start because the clean workspace has no `ajv/dist/2020.js`; no dependency/network acquisition was attempted.
- No native, sudo, workflow, provider, cloud, or AWS operation was run.

A broad predecessor-range `git diff --check` also encounters historical trailing whitespace in unrelated pre-existing `.pi/outcome-two/*.md` files; the exact reviewed commit diff itself passes.

# Final verdict: BLOCKED

Exact head `3846383f0d88c190226356ca9aeeeda402943aaa` retains two P1 authority failures and one P3 deterministic-identity defect. Do not sign off ADR 0092, name this head in a native-execution ADR, invoke native selectors, dispatch/rerun the workflow, rely on artifacts, or authorize cloud/AWS/production/release/issue-closure activity.

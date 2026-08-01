# Security evidence

Cogs conformance runs emit one JSON report validated by `schemas/security-report-v1alpha1.json` and one human-readable Markdown rendering derived from that JSON. Release-candidate reports are committed here; routine CI reports remain immutable workflow artifacts.

## Result semantics

| Result | Meaning | Release eligible |
|---|---|---:|
| `pass` | The test executed against every declared real applicable dependency and met its assertion. | Only on an authoritative applicable profile |
| `fail` | The test executed and an assertion failed. | No |
| `stubbed` | One or more mandatory dependencies were replaced by a stub. | No |
| `not-applicable` | The claim does not exist for this stage/profile. This is not a skip. | No |
| `skipped-with-approved-reason` | An applicable test was not run under a named, expiring approval. | No |

A test whose `dependency_modes` contains `stubbed` must itself report `stubbed`, never `pass`. `release_eligible: true` requires `result: pass`, no stubbed test dependency, and an authoritative profile. The report validator enforces these cross-field rules in addition to JSON Schema.

`insecure-container` and `macos-vm-dev` always use `authority: functional-only`. They cannot establish guest-root isolation, host-network default deny, secret confinement, or VM-boundary claims. A `linux-kvm` report is invalid unless its metadata proves `/dev/kvm`/KVM presence, active KVM acceleration, guest root, and distinct boot identities. Stage 0's GitHub KVM qualification proves runner capability only; authoritative guest-root bypass claims begin with the Stage 1 `linux-kvm` suite.

Diagnostics must be redacted. Reports and logs must never include credentials, placeholders, prompts, source, query strings, request bodies, raw tool output, or session exports.

## Authority domains are disjoint

`schemas/stage4-static-preparation-evidence-v1.json` is a separate, static-only contract. Its authority is fixed to `static-only-stage4-preparation`; `qualified`, `campaign_authorized`, `cloud_execution_observed`, `stage4_exit_satisfied`, and `release_eligible` are all fixed to `false`. Its `asserted_static_outcome` and every static-check outcome are **trusted caller assertions**. Schema validity and validator acceptance establish only consistency with the supplied assertions and exact digest-bound source, chart, values, and byte-identical renders; they do not establish that `conforming` or any asserted check is true.

The pure validator in `scripts/stage4-static-evidence.ts` accepts canonical JSON bytes plus bounded caller-supplied artifact bytes and `trustedExpectedStaticOutcomes`. It performs no rendering, outcome derivation, assertion authentication, process execution, environment lookup, network access, or cloud/provider operation. It is not a Helm producer and does not create authoritative evidence. Digest possession alone does not establish that a check was satisfied.

`schemas/stage4-teardown-verdict-v1.json` is another disjoint local domain. Every verdict fixes `authority: local-teardown-order-classifier`, `cloud_inventory_observed: false`, `cloud_execution_observed: false`, `stage4_exit_satisfied: false`, and `release_eligible: false`. Its only terminal result is `evidence-order-complete` / `STAGE4_EVIDENCE_ORDER_COMPLETE`; that result proves neither inventory zero nor cleanup. `producer_class` in the plan is only a claimed fixed category and never an identity, provenance, custody, separation, or observation-authority claim.

Teardown `plan_sha256` and `evidence_root_sha256` are domain-separated deterministic bindings over the strict decoded semantic plan and ordered claimed artifact digests, including `uncertainty_artifact_sha256`. They are not bindings to original JSON bytes and do not authenticate artifacts or establish provider truth. The teardown plan, teardown verdict, static-preparation report, and security report are mutually non-substitutable; unknown fields and authority-domain collisions are rejected by dedicated schema tests.

A static Stage 4 preparation report or local teardown verdict cannot be converted or promoted into an `eks-kata` security report, cannot make any test or report release eligible, and cannot satisfy Stage 0, 1, 3, 4, or 5 applicability or exit rules. In particular, all 13 future EKS checks are fixed as `required-for-future-exact-run-eks`, `unexecuted`, and `not-observed`. `not-applicable`, `skipped`, `stubbed`, `pass`, and `satisfied` are forbidden labels for those required but unexecuted checks.

`schemas/stage4-policy-contract-v1.json`, `schemas/stage4-policy-payload-v1.json`, and `schemas/stage4-policy-probe-suite-v1.json` add a fourth disjoint static domain for issue #356. Their authority is fixed to `static-only-stage4-policy` and qualification is fixed to `pending-exact-eks-cni-runtime`. Validator and probe decisions always fix cloud execution, CNI/runtime qualification, Stage 4 exit, and release eligibility to false. Every supplied probe expectation is recomputed through the pure evaluator, and audit-WAL records use only fixed categories/scalars plus exact domain-separated digest references. An `allow` probe means only that the static expected-policy graph selects the assigned same-session proxy; it is not an enforcement observation. See [`docs/test-reports/stage-4-static-policy-contracts.md`](../test-reports/stage-4-static-policy-contracts.md).

Only a separately authorized future exact-run EKS campaign, under a new authority and schema, may observe the cloud/runtime checks needed for Stage 4 exit. This repository slice provides no campaign approval, cloud workflow, Helm producer, or cloud evidence and may be validated without AWS or Kubernetes credentials.

`schemas/stage4-storage-launch-contract-v1.json` and `schemas/stage4-storage-launch-verdict-v1.json` define another disjoint local domain for issue #355. It fixes authority to `local-static-storage-launch-classifier` and every qualification, campaign, cloud, Kubernetes, provider-truth, Stage 4 exit, and release claim to false. Its pure classifier checks only bounded caller-supplied metadata: exact separate 20 GiB workspace and 5 GiB trusted session-state roles, one fenced writer, one worker/proxy resource, one Kata sandbox, one immutable single-admission launch-document digest, host-key match state, out-of-band ephemeral identity policy, and uncertainty-preserving cleanup shape. It neither launches nor observes any resource. `cleanup-order-complete` is semantic ordering only and is not cleanup evidence. See [`docs/operations/stage-4-storage-launch-contract.md`](../operations/stage-4-storage-launch-contract.md) and [`docs/test-reports/stage-4-static-storage-launch-contract.md`](../test-reports/stage-4-static-storage-launch-contract.md).

The NIC node-group contract adds another disjoint local domain. `schemas/stage4-nic-sandbox-node-group-contract-v1.json` describes exact static semantics and `schemas/stage4-nic-sandbox-node-group-verdict-v1.json` fixes authority to `local-static-nic-contract-classifier`. Its verdict always fixes campaign, cloud, Stage 4 exit, and release claims to false. This v1 classifier has no ready status: it can only report the exact pinned release's missing capability or reject drift. Any capable future NIC revision requires a new schema/classifier review and still would not prove provider/runtime state or launch-template preservation in an applied environment.

The checked contract pins the externally authenticated public source `nebari-dev/nebari-infrastructure-core` `v0.11.0` (commit `28221c652c56bb8d48a92538c01503a82f2f9321`, tree `4dfb0333e5d91003e69881ca1dcf66e1ea9ff6c2`), relevant file digests, and its `nebari-dev/eks-cluster/aws` `0.7.0` module closure. That exact source supports ordinary managed-node-group fields but lacks custom launch-template ID/version and `CpuOptions.NestedVirtualization` inputs; its module auto-creates a fixed launch template. The local verdict is therefore `blocked-missing-capability`, and an exact EKS AMI/release/kernel pin also remains unresolved. Spot, bare metal, scaling expansion, launch-template latest/default selection, runc, TCG, source/module digest drift, and trusted/sandbox scheduling overlap classify as hostile drift. The classifier is pure and cannot authenticate the supplied public-source observations, render NIC source, execute a transition, or promote its verdict into static-preparation, teardown, security-report, campaign, or release evidence.

`schemas/stage5-api-key-release-matrix-draft-v1.json` defines another disjoint domain: a provisional local/static requirements inventory for issue #363. Its committed instance fixes every authority, observation, finalization, and eligibility field to `false`, fixes `go_no_go` to `not-available`, and records S4-11 as required but not observed. It maps all 22 `DESIGN.md` acceptance criteria and all 13 Stage 5 exit criteria individually. Every release-candidate, authenticated-principal, identity, criterion-evidence, provider-evidence, and evidence-reference binding is null or empty and explicitly blocking. Schema validity proves only bounded inventory consistency; it supplies no Stage 4 result, identity, independence, approval, execution evidence, final decision, or release authority.

The Stage 5 draft is API-key-only. Anthropic, OpenAI, and OpenRouter are explicit provisional provider candidates, remain unadvertised, and each requires future real-provider evidence before any support advertisement. Subscription OAuth is fixed to disabled and unadvertised, worker refresh tokens are forbidden, and #13 remains deferred outside the release gate. Daemon, ingress, sanitizer, apps, indexing, other-cloud production, GA, and compliance claims are explicitly unsupported/unadvertised. The marked support section in the human draft is an exact deterministic rendering of machine data; machine JSON is authoritative and no arbitrary-prose blacklist claim is made.

The provisional draft intentionally defines no evidence-reference instance or schema surface. A separate future authority must introduce a new schema and reusable semantic validator that binds every criterion to its exact profile, lane, evidence category, producer role, authenticated identities, and applicable campaign approval/run while rejecting duplicate IDs/evidence and conflicting results. Future S4-11 acceptance still cannot promote this draft; finalization also requires stable separated principals and later Stage 5 evidence under that future contract.

## Human-readable rendering

A renderer must preserve, at minimum:

1. report ID, source revision, profile, and authority;
2. timestamps and duration;
3. component versions and image digests;
4. environment and runtime versions;
5. real/stubbed/not-applicable dependency matrix;
6. test table with group, result, release eligibility, and redacted diagnostic;
7. skip owner/reason/review date;
8. known limitations.

The JSON report remains authoritative when the two forms disagree.

## Stage 0 gate control inventory

The Stage 0 gate review must account for these unique controls, even when evidence comes from separate reports:

- `pi.closed-loader` — the trusted session uses the custom closed loader;
- `pi.discovery-canaries` — pinned Pi default discovery positively loads valid global/project extension and package canaries, while the closed loader does not;
- `pi.runtime-auth` — runtime-only auth reaches the fake stream and creates no durable auth/session value;
- `pi.native-jsonl` — pinned Pi library and CLI reopen Cogs-produced JSONL with tool messages and both branches;
- `images.base-digest` — every external Dockerfile base is an immutable SHA-256 reference and every registry lock entry has SRI;
- `runner.kvm-acceleration` — `/dev/kvm` is usable, QEMU starts with KVM-only acceleration, QMP reports `present=true` and `enabled=true`, and a root guest has a distinct boot identity.

Omitting a control from the Stage 0 gate matrix is a failure, not `not-applicable`. Individual mechanism reports include only the controls they execute; the gate matrix links them without relabelling unexecuted work as pass.

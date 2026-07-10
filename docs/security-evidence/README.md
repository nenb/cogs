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

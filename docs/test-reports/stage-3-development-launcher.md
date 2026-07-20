# Stage 3 development launcher report

Commit/component matrix:

| Component | Commit | Scope |
| --- | --- | --- |
| launcher core/supervisor/dispatcher | `0ecb1539676e82ff0611219a63c7e9f2d9eda37b` base plus final workflow/docs slice | development-only local launcher |
| insecure-container profile | `0ecb1539676e82ff0611219a63c7e9f2d9eda37b` | functional-only SSH/SFTP container profile |
| linux-kvm profile | `0ecb1539676e82ff0611219a63c7e9f2d9eda37b` | authoritative-local KVM qualification profile |

Validation status for this slice:

- Unit/static suite: `npm run check` expected to run 753+ tests plus schema, preset, image, lock, license, and audit checks.
- Local real macOS observation from the prerequisite slice: `insecure-container create` completed in about 17 seconds, produced no `.npm` control pollution after the repo-local `tsx` invocation fix, and `destroy` removed exact owned state.
- Local full-start observation on macOS: fail-closed before security evidence because `/run/cogs`, `/run/cogs/egress`, and `/run/cogs/ssh` Linux tmpfs prerequisites were absent. This is not security evidence and makes no isolation claim.
- GitHub workflow launcher smoke is pending until CI runs this slice. The workflows generate applicability-aware `cogs.security-report/v1alpha1` reports and upload only metadata reports, never prompt/event/export contents.

Applicability semantics:

- `insecure-container` remains `functional-only`; network isolation/default-deny evidence is not applicable.
- `linux-kvm` is the only `authoritative-local` development profile, and still does not imply release eligibility or production readiness.
- `macos-vm` has no fallback path in this stage.

No cloud statement: issue #70 launcher evidence performs no AWS, cloud provisioning, deployment, release, or production authentication operation.

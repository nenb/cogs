# ADR 0127: Make KVM admission the first workflow step

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Sole replacement local KVM workflow admission and measured line accounting
- Supersedes: ADR 0126's workflow placement and workflow hash

## Context

Final hostile review of revision `1cbbb4828baadd5e1714f52f99e7652bb8803131` found two pre-dispatch blockers. First, `actions/checkout` ran before admission and implicitly defaulted its token input to the job token, so authenticated source effects could fail and consume the event before the first-created decision. Second, the API snapshots discarded `run_attempt` and a hostile test accepted an attempt-two row. No local KVM workflow had been dispatched.

## Decision

Make an inline, reviewed, bounded Python pre-admission program the first workflow step. Before any `uses:` action, checkout, Git fetch, source read, KVM, runtime, or lifecycle mutation it must:

- reject cloud, OIDC, provider, proxy, ambient GitHub-token, and Python-override environment names;
- bind workflow-dispatch, protected `main`, exact configured H/G, actor, current SHA, event repository, and event inputs;
- accept the job token only through one step-scoped `ACTIONS_READ_TOKEN`, with ASCII/length/character bounds;
- use only the fixed same-repository HTTPS Actions endpoint with no proxy and fatal redirects;
- require complete bounded history, every row at `run_attempt == 1`, unique `(id, attempt)` rows, current `(id, 1)` visibility, two consecutive identical snapshots, and the current ID as the earliest ID;
- emit only the admitted run ID.

After admission, acquire exact public G and H with explicit unauthenticated `git fetch`, `GIT_TERMINAL_PROMPT=0`, no credential environment, no checkout action, and no persisted credentials. The checked-in post-acquisition guard must reject `ACTIONS_READ_TOKEN`, require the exact pre-effect run-ID marker, and revalidate event/H/G/actor/control/workflow bytes before H acquisition or mutation.

The reviewed qualification-workflow SHA-256 becomes `64a54854c6dc82e16d62e90f82529135021eac653a36140e653bfbfc0069ee43`. The measured workflow correction high increases from 1,000 to 1,100 lines solely for the readable inline admission. The 11,000 global correction high and 67,000 hard limit do not change.

## Authority boundary

This correction grants no extra dispatch. It preserves exactly one first-created attempt-one replacement Stage 2 local KVM/Kata qualification after exact-head review and CI. It grants no AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, or release authority.

# ADR 0314: Raise final hostile integration ceilings

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through advance approval for every required non-AWS correction before the authoritative chain
- Inputs: measured correction handoffs `/tmp/cogs42-{lifefix,envoyfix,driverfix,govfix}.md`

## Context

Four independent hostile reviews of the first integrated endpoint reproduced actual-work and resource-ownership defects not covered by its green tests. ADR 0313 authorized their correction before implementation. Isolated whole-file owners then added permanent regressions and measured fixes for OpenBao cancellation/identity custody, watcher/action and factory reentry, requested-shutdown classification, Envoy configuration/literal headers/extraction custody, and local network/smoke/helper generations.

Adding the measured fixes to the 14,340-line first endpoint is forecast to exceed ADR 0308's original 16,000-line remediation ceiling while remaining well inside tracked-source byte/cardinality limits and the separate Stage2 retained-line hard limit. Deleting hostile tests or compressing ownership logic to fit would weaken the accepted security contract. The blocked OpenBao derivative recipe is not being integrated under this Stage2-only path.

## Decision

Raise the global baseline-to-endpoint gross no-deletion remediation ceiling once from 16,000 to **18,000** lines. Supersede owner ceilings as follows:

| Owner | Ceiling |
|---|---:|
| route | 1,800 |
| revocation | 2,900 |
| relay | 1,800 |
| lifecycle | 6,700 |
| completion | 2,000 |
| integration | 2,800 |

The owner ceilings sum to 18,000. Capacity remains non-transferable without another accepted decision. Keep the exact baseline `242bbefeae5444118d9e97b46597130b509ca253`, whole-file assignment, rename detection disabled and no deletion credit.

Release all seven absent first-party OpenBao derivative recipe/document reservations. The bounded research remains under `/tmp` and ADRs 0309–0310; no candidate was admitted. Reduce the allocated new-file total from forty to thirty-four. Use one released slot for this ADR and retain exact reservations for the thirteen future v5 members and future ADR 0315/0316. No wildcard or unassigned file permission is created.

All Stage2 deploy/retained/workflow/global, hard `<95,900`, mutable-owner, source-byte, serialized-inventory, per-file and final-v5 limits remain unchanged. ADR 0309's post-H 150/500/350/1,000 reserves remain machine-enforced.

Integrate only the four reviewed correction commits, resolve conflicts under one lead, rerun their exact reproducers, and obtain fresh hostile review. Any new P0–P2, budget breach, runtime uncertainty or evidence mismatch stops the freeze.

## Authority boundary

This is a measured source-accounting increase, not functional acceptance or authority. It permits local integration, tests, final evidence regeneration and ordinary protected Linux/root/KVM CI. It grants no producer, publisher, preflight, qualification, OpenBao image admission/publication, AWS credential/API, provider/OpenTofu, SSM, inventory, deployment, campaign, production, release, Stage4 exit or Issue #42 closure authority. Work stops before the authoritative chain.

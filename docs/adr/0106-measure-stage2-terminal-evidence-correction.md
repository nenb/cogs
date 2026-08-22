# ADR 0106: Measure the Stage 2 terminal-evidence correction

- Status: Accepted by explicit owner instruction in this conversation
- Date: 2026-08-21
- Scope: ADR 0105 accounting correction and bounded local terminal-evidence hardening

## Context

Hostile review of exact head `b5750556bfd8a65b3cd32b9c7179e438b74c3611` found three concrete gaps. The independent outer settlement did not recognize the production token families `c42h*`, `c42n*`, `c42q*`, and `c42t*` across complete interface, network-namespace, nftables, and traffic-control observations. The private V2 route could mint a pass after exact cleanup but could not retain a canonical transactional failure for a certain terminal execution failure. ADR 0105 also omitted workflow security text from both physical and no-deletion-credit accounting, and its deployment slice measured 5,017 gross added lines against a 5,000-line high.

At the ADR 0105 Gate 0 commit `6f7d5c4dfdbf9f5ee4b4be0dc7d54839eac07f57`, the ten tracked workflows contain 2,989 physical lines. Adding those inherited lines corrects Gate 0 from 50,363/52,365 to **53,352 current physical lines** and **55,354 conservative no-deletion-credit lines**. At `b5750556`, all eleven tracked workflows contain 3,352 lines. The post-Gate-0 slices measure:

| Slice | Gross added lines |
| --- | ---: |
| Deployment implementation | 5,017 |
| Retained scripts, schemas, and other explicitly retained security surfaces | 1,555 |
| Workflows | 363 |
| Global | 6,935 |

The corrected `b5750556` measurements are therefore **59,955 current physical lines** and **62,289 conservative no-deletion-credit lines**. The latter exceeds ADR 0105's 62,000 hard limit by 289 lines. This is an omitted-surface correction, not deletion credit or retrospective compression authority.

## Decision

Count every tracked `.yml` or `.yaml` file under `.github/workflows` as a physical security surface. The centralized checker must require the complete tracked workflow inventory, report its file and line counts, and measure deployment, retained, workflow, and global gross additions independently from the exact Gate 0 commit. Every slice and the global limit are mandatory and non-transferable.

Set the readable gross-addition highs to:

| Counted correction slice | Gross added-line high |
| --- | ---: |
| Deployment implementation under `deploy/aws-feasibility` | 5,750 |
| Explicitly retained scripts, schemas, configuration, and retained security files | 2,500 |
| All tracked workflows | 500 |
| Global post-Gate-0 correction | 8,750 |

Set the Stage 2 preferred limit to **64,500** and mandatory hard limit to **65,000** for both complete current physical and conservative no-deletion-credit measurements. The global high projects at most `55,354 + 8,750 = 64,104`, below the corrected preferred limit. These values permit ordinary readable correction code. Compression, multi-effect lines, relocation, renaming, generated/data indirection, test relocation, and deletion remain ineligible for credit.

The outer settlement correction must parse complete bounded command output with duplicate-key, byte, row, depth, and node rejection. It must independently cover tokenized production host interfaces, active and quarantined network namespaces, nftables tables, and traffic-control references. Missing, malformed, truncated, excessive, or failed observation is uncertainty and fails closed; it is never absence.

After exact owner cleanup and exact independent residue absence, a certain terminal execution failure may produce the existing canonical V2 `failure` result through the same closure-private typed evidence and transactional custody receipt route as a pass. Its first failure is recomputed from the typed complete durable journal history. No caller report, dictionary, status string, exception classification, workflow outcome, or recovery result may select or replace that history. Uncertain durable history, cleanup error, residue, custody-close error, malformed history, or missing typed lineage mints no receipt and cannot claim cleanup or pass. A canonical failure may be uploaded with its separate upload-binding receipt, but the workflow remains failed.

Recovery remains cleanup-only. It may neither enter the evidence producer nor mint, consume, or transform a receipt, and exact recovery absence never becomes a pass. The preparation and recovery owner reconstructors remain unchanged.

## Authority boundary

This ADR authorizes only the measured local correction, hostile portable tests, centralized accounting enforcement, and the workflow handling needed to upload a certain typed failure while retaining a failed terminal outcome. It does not consume or add a static event, KVM qualification, retry, rerun, replacement, controller, seven-cycle campaign, AWS credential/API/provider/OpenTofu/SSM action, deployment, publication, readiness promotion, issue closure, production, or release authority. ADR 0105's exact-head review and mandatory controller/AWS stop remain binding.

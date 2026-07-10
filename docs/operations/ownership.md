# Initial ownership and approval register

| Responsibility | Owner |
|---|---|
| Product and scope decisions | Nick Byrne (`@nenb`) |
| Security and ADR review | Nick Byrne (`@nenb`) |
| Stage gate approval | Nick Byrne (`@nenb`) |
| Future AWS feasibility engineer | Nick Byrne (`@nenb`) |
| Future AWS manual apply approver | Nick Byrne (`@nenb`) |
| Future AWS budget/spend approval | Nick Byrne (`@nenb`) |
| Subscription OAuth broker and terms, interim | Nick Byrne (`@nenb`), to be reassigned to the daemon/platform team when it exists |

## AWS rule

Stage 0 uses no AWS resources or credentials. The first permitted AWS action is the separately reviewed Stage 2 single-instance nested-virtualization campaign—not EKS. Before apply, Nick Byrne must approve the account, region, instance candidate, one-instance maximum, budget, expiry, TTL cleanup, and destroy plan. The campaign ends with explicit zero-resource evidence. Any later AWS activity requires another named, time-boxed approval.

## Paid CI rule

Standard GitHub-hosted runners are used initially. Paid larger runners or third-party runners require Nick Byrne's approval before configuration or spend.

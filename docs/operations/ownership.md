# Initial ownership and approval register

| Responsibility | Current owner |
|---|---|
| Product and scope decisions | Nick Byrne (`@nenb`) |
| Security and ADR review | Nick Byrne (`@nenb`) |
| Stage gate approval | Nick Byrne (`@nenb`) |
| Stage 2 issue #42 campaign operator | Nick Byrne (`@nenb`) |
| Stage 2 issue #42 manual approver and budget approver | Nick Byrne (`@nenb`) |
| Stage 4 local/static preparation technical owner | Nick Byrne (`@nenb`) |
| Stage 4 NIC integration owner | Nick Byrne (`@nenb`) |
| Stage 4 cloud campaign operator | Nick Byrne (`@nenb`) |
| Stage 4 fresh manual campaign approver | Nick Byrne (`@nenb`) |
| Stage 4 budget/spend approver | Nick Byrne (`@nenb`) |
| Stage 4 security and evidence reviewer | Nick Byrne (`@nenb`) |
| Stage 4 teardown and zero-inventory verifier | Nick Byrne (`@nenb`) |
| Subscription OAuth broker and terms, post-MVP interim | Nick Byrne (`@nenb`), to be reassigned to the daemon/platform team when it exists |

One person may hold multiple responsibilities initially, as recorded above, but one person does not satisfy independent security review or independent zero-inventory observation. This register identifies responsibility only: it is not an authenticated principal binding or standing cloud authority. The current readiness package therefore records every concrete principal binding as unobserved and separation as blocking. Before any campaign request, stable authenticated bindings must separate the campaign operator from the campaign approver, budget approver, security/evidence reviewer, and zero-inventory observer; the zero-inventory observer must also be distinct from the approver and security/evidence reviewer. Role labels or this register do not prove that separation. Every cloud campaign requires a fresh, named, issue-specific approval that records the exact revision, operator, approver, account binding, region, resource ceiling, spend cap, expiry, destroy path, and independent read-only zero-inventory procedure. Approval for one attempt or stage never authorizes a retry or later campaign.

## AWS rule

Stage 0 used no AWS resources or credentials. Accepted historical evidence from a bounded standalone EC2 campaign selected the initial `c8i-flex.large` candidate in `us-east-1`; that evidence does not claim current resources or authorize EKS. Issue #42 is closed with its exact historical Stage 2 closure record. Its offline Cosign and bounded injected-verifier checks grant no current cloud authority.

The owner declares AWS account `372495030090`, region `us-east-1`, and commitment `65eb8fbcacd1a51be6de86ac302df96a98a41c6190a4a161bf720592bf6a2bb7`; no provider observation confirms that binding. The Stage 4 owner must request a separate fresh approval for one exact campaign. Closure, ownership, a merged change, or an earlier approval is never sufficient authority. Every approved campaign stops on failure or cleanup uncertainty, destroys its bounded state, and finishes with independently produced read-only zero-inventory evidence. Subscription OAuth issue #13 is post-MVP and does not gate API-key-only Stages 4 or 5.

## Paid CI rule

Standard GitHub-hosted runners are used initially. Paid larger runners or third-party runners require Nick Byrne's approval before configuration or spend.

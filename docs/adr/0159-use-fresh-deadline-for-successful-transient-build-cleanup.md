# ADR 0159: Use a fresh deadline for successful transient-build cleanup

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

Repeated private Linux execution and bounded instrumentation proved first-build work completed successfully: all 4,353 manifest entries, metadata, hardlink, candidate tar, and candidate manifest records were durable. The non-retained build then attempted mandatory deletion using the nearly exhausted 900-second work deadline. Cleanup rejected the expired control, after which the failure path's fresh cleanup correctly removed all 4,353 entries and retired the operation. Increasing work time would conceal this lifecycle-boundary defect.

After successful candidate creation and cache revalidation, run transient-build cleanup under the same fresh bounded cleanup control already required for failed work. Ordinary local builds receive a new at-most-600-second cleanup deadline; native-package builds retain their pre-reserved absolute cleanup boundary. Candidate construction, materialization, metadata, tar creation, and cache validation remain under the original work deadline. Cleanup remains single-pass, exact-ledger, descriptor-relative, and mandatory before the second build; it is not a retry and grants no extra build work.

No AWS, provider, deployment, evidence, promotion, or release authority follows.

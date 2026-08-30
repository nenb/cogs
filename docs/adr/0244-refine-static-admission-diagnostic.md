# ADR 0244: Refine the static-admission diagnostic

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Diagnostic run `33295310633`, attempt 1, reproduced the formal pre-operation block on the same hosted runner image and then removed all immutable state. Its bounded cause was `AdmissionError: untrusted admitted directory`; the exact Osito path still passed. The run grants no qualification or replacement authority.

Refine the existing no-lifecycle diagnostic to identify whether the rejected directory belongs to the control package, complete fixed source, active observer configuration, or final package/rootfs validation. Invoke the same internal validators read-only, close all retained descriptors, then retain the exact coordinator claim as the final comparison. Keep lifecycle entry, KVM/Kata launch, SSH, QMP, report publication, providers, and AWS unreachable.

This additional decision raises only the complete tracked-source cardinality bound from 1,205 to exactly 1,206 files and the measured workflow correction high from 1,400 to 1,420 gross lines for the 21-line diagnostic refinement. All byte bounds, other line highs, and complete-inventory rules remain unchanged. Authorize one refined diagnostic observation only; it grants no AWS, provider, deployment, campaign, production, release, qualification, retry, or promotion operation.

# ADR 0183: Raise the native integration correction bounds

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

The measured post-H25 correction inventory is 19,440 global gross lines against a 19,500 high and 14,142 deployment gross lines against a 14,500 high. Native Kata execution has now exposed reviewed integration corrections through real QEMU/KVM launch, but QMP, SSH, workload, and full teardown convergence remain. The remaining 60-line global margin cannot contain even one tested correction and its decision record.

Raise the correction global high from 19,500 to 20,500 and the deployment high from 14,500 to 15,500. Keep the 76,000 preferred physical limit, 78,000 hard limit, 6,500 retained-file high, 1,400 workflow high, and 2,000 mutable-owner limit unchanged. At the measured head, the additional allocation would still remain below the preferred physical limit even if consumed completely.

The increase is bounded to the current non-AWS native integration closure. It does not authorize unrelated features, production fast paths, AWS, providers, deployment, campaigns, or release operations.

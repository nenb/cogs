# ADR 0136: Require mixed H/G preflight before KVM

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22

Run `32602439014` failed in the combined preparation step before KVM. No artifact was produced; the entry was skipped; residue observation failed at the coarse network stage, so cleanup certainty is not claimed. Private failure-custody SHA-256 is `ac9e3127a49054cbd572c0ba0a4ca01e30c957e8c173e64541fcf19d31063d64`. Component tests and the static producer did not execute H immutable preparation while consuming staged G control on the GitHub runner.

Add one manual, no-secret, no-artifact Ubuntu 24.04 workflow that materializes exact H, stages exact G through the production owner, executes immutable preparation, deliberately stops before `completion_local_full.py`, and runs production recovery, cleanup, and residue twice across normal/always paths. Root-owned run/source markers distinguish partial source publication from an authenticated completed source, so partial materialization is deleted without executing its bytes and fixed-root recovery executes only after exact source authentication. An allowlisted process environment, complete credential denylist, closed Bash startup files, owned timeout groups, and non-borrowing job reserve bound the observation. It grants no KVM or promotion claim. Docker remains supplementary because the pinned image lacks zstd and differs from the runner host.

Add bounded phase markers around qualification preparation and split settlement network diagnostics by fixed observer. Bind `32602439014` as the fourth exact completed/failure predecessor. Correct executable checks to use root authority for root-owned mode-0500 files.

Measured workflow gross additions rise from 1,124 to 1,196 lines. Raise only the workflow correction high from 1,150 to 1,250. Global correction remains 10,766, below 11,000, and conservative total remains below the 67,000 hard stop.

This authorizes the diagnostic preflight and a later reviewed local replacement only. It grants no AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, promotion, or release authority.

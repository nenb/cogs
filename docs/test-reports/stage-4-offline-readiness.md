# Stage 4 bounded offline preflight/readiness evidence

## Scope

- Issue: #357.
- Authority: `local-static-stage4-readiness-package` / `local-static-stage4-readiness-classifier`.
- Local preparation complete: true.
- Campaign request ready / approved / cloud authorized: false / false / false.
- Provider/cloud/Kubernetes/current-resource/zero-resource observation: none.
- Stage 4 exit / release eligible: false / false.

This report records package assembly and local/static checks only. No AWS/provider API or CLI, provider discovery, OpenTofu init/plan/apply, SSM, EKS, Kubernetes API, `kubectl`, Helm install/apply, deployment, external model, price/quota discovery, campaign, or inventory operation was used.

## Bound artifacts

The canonical package binds the exact source inventory, chart inventory, synthetic values, byte-identical repeated NOTES render, image lock, NIC contract, runtime-pin record, Stage 4/5 schema inventory, and local-validation receipt. The local-validation artifact also binds the exact package classifier, schemas, registry test, and hostile package test sources. A domain-separated semantic root covers all digest references and the complete proposal/blocker/authority/revalidation shape.

Schema validity alone does not authenticate source provenance or local-check execution. The pure classifier recomputes byte digests and consistency only. The committed receipt and this report are local claims, not provider or campaign evidence.

## Honest result

The package can say `local_preparation_complete=true` because its closed structure and bound local checks pass. It cannot say `campaign_request_ready=true` because #42 is open, NIC `v0.11.0` / module `0.7.0` lacks the mandatory launch-template and nested-CPU-options interface, the EKS AMI/image/kernel pin is absent, account and separated identities are absent, price/quota are undiscovered, and no campaign envelope or approval exists.

Worker/sandbox image references are synthetic `.invalid` placeholders. Runtime version strings do not substitute for EKS binary identity. No current resources or zero inventory are claimed.

## Hostile coverage

Tests cover canonical whitespace/newline/BOM/duplicate-key aliases; every artifact digest and render repeat; binding-root replay after source, validation, pin, price/quota, and campaign-shape mutation; omitted blockers and invented account/identity/AMI/kernel values; authority promotion, two-attempt approval, prior-approval retry, and executable-route mutations; unknown fields and arbitrary diagnostics; byte/aggregate limits; inherited/custom prototypes; symbols; getters without invocation; root and recursive Proxy traps without invocation; and strict verdict/schema registration.

All invalid or uncertain inputs preserve uncertainty and keep campaign request, approval, cloud authority, provider truth, current/zero resources, Stage 4 exit, and release eligibility false.

## Required future work

After #42 closure—and after any source, pin, price, quota, or campaign-shape change—the complete package must be freshly regenerated and locally revalidated. A future review must resolve NIC capability and EKS AMI/kernel pins, bind an account and separated authenticated identities, perform explicitly authorized current price/quota/support discovery, and create a new one-attempt campaign envelope. Any later campaign still requires separate approval and independent inventory; this package cannot be promoted into either.

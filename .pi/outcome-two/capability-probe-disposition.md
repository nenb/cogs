# Outcome 2 capability-probe disposition

## Decision

The proposed hosted-runner capability observation is abandoned without execution. No label was applied, no probe event ran, and no observation, retry, evidence, Phase B, provider, OpenTofu, deployment, cloud, or AWS authority was consumed.

The five capability implementation surfaces are removed. Closed PR #260 is not an accepted decision and grants no authority.

## Basis

Two independent five-way hostile reviews blocked exact implementation heads `9c86bc5` and `ab57831`. The second review confirmed that the attempted correction still lacked:

- an outer recovery supervisor with authority established before child release;
- exact pre-effect descriptor, process, mount, namespace, name, rlimit, and checkout baselines;
- identity-bound cleanup after supervisor crash;
- production-path injected lifecycle and cleanup qualification;
- complete status/prerequisite/postcondition semantics; and
- a credential-admission gate with executable hostile challenges.

The setuid transition required to characterize root-only runner behavior also creates a period in which a non-root outer process cannot prove exact termination authority. Reporting those cases as successful would be false, and executing them merely to discover whether cleanup is possible would violate the fail-closed boundary.

## Plan effect

`OUTCOME-TWO-PLAN.md` section 4 described the probe as preliminary characterization intended to replace trial-and-error architecture changes. It is not listed in the section 10 Outcome 2 completion gate. ADR 0087 already fixes the production architecture independently of favorable hosted-runner capabilities: trusted host preparation resolves and seals the runtime closure before the zero-capability sandbox receives fixed descriptors and canonical metadata.

Therefore the safe fallback is:

1. preserve the reviews as negative design evidence;
2. remove the unsafe executable probe rather than weaken its contract;
3. implement and qualify the production closure with portable hostile adapters;
4. qualify Linux primitives independently in native Jobs A–E; and
5. allow native jobs to report unavailable capabilities categorically without treating absence as success.

This does not weaken any Outcome 2 completion criterion. Native Jobs A–E and thin integration remain mandatory, as do exact baseline restoration and exact-head hostile signoff.

## Preserved boundaries

- Runtime discovery remains trusted host preparation.
- Zero-capability code does not rediscover unrestricted host state.
- Unknown, ambiguous, unavailable, or uncertain state fails closed.
- No runner disposal is treated as cleanup proof.
- No capability report or log is evidence authority.
- AWS/provider/OpenTofu/deployment activity remains prohibited.

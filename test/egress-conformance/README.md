# Egress conformance harness

This directory contains test infrastructure for the executable Stage 1 egress contract. It is not production Cogs code and does not make an isolation claim by itself.

## Trust boundary

The controller is trusted. Proxy candidates and upstream behavior run out of process behind `ConformanceAdapter`. Adapter methods only orchestrate external processes or VMs; they must not run blocking candidate work in the Node.js controller. For each executed case the controller:

1. supplies an immutable case definition;
2. applies a case deadline and abort signal;
3. requires bounded `cleanup()` to forcibly terminate and acknowledge all per-case resources;
4. stops executing later applicable cases if cleanup fails;
5. applies an independent final teardown deadline.

A timeout, malformed adapter result, cleanup failure, or teardown failure produces failed evidence. Any lifecycle failure clears release eligibility from all results. Software emulation or a different profile is never a fallback.

## Applicability and evidence

`schemas/egress-case-manifest-v1alpha1.json` defines the versioned case metadata contract. The complete immutable case set and case-specific observations will be added with the conformance groups in issue #22; schema validity alone is never interpreted as suite completeness or conformance success.

Profile mismatch or an unavailable/not-applicable required dependency yields `not-applicable` without invoking the adapter. A successful case backed by a stub is `stubbed`, not `pass`. Skips require a non-empty owner and reason plus a strict UTC review timestamp that remains unexpired when the report completes.

Reports use `cogs.security-report/v1alpha1`. `writeReports()` validates schema and cross-field semantics before atomically renaming machine JSON and human Markdown into place. Consumers must still apply the stage/profile-specific acceptance policy; a schema-valid report may correctly contain failures, stubs, or non-applicable cases.

## Profiles

- `insecure-container`: functional proxy/protocol evidence only.
- `macos-vm-dev`: optional functional convenience evidence only.
- `linux-kvm`: authoritative local evidence only after KVM and guest-root qualification.

The Stage 1 Linux/KVM driver and host-enforced default-deny network are tracked separately in issue #23.

## Proxy candidates

Candidate-specific immutable configuration and external-process lifecycle adapters live under `proxy-adapters/`. The pinned Envoy candidate uses native gRPC `ext_authz`; the pinned mitmproxy alternate requires a measured Python addon over parsed flows. Both validate capability and authorization/audit hooks fail closed, expose no administration endpoint, and run the same guest-root candidate smoke. Their security-labelled CI reports remain functional-only and stub-aware. The complete shared black-box case matrix is tracked in issue #22; candidate smoke is not proxy-selection evidence by itself.

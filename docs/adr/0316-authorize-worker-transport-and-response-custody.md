# ADR 0316: Authorize worker transport and response custody

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through advance approval for required non-AWS corrections
- Input: independent final lifecycle review `/tmp/cogs42-final-life-review.md`

## Context

ADR 0315 retained actual workload-identity, unpinned model-read and egress-OTLP work. Re-review confirms those exact defects are fixed and found two adjacent gaps: worker trace/metric OTLP still certifies production cleanup before original transports retire, and OpenBao metadata/PKI readers can skip response cancellation when hostile header access or reader acquisition throws.

Optional delivery failure may remain nonfatal. The missing fact is actual transport retirement, not successful telemetry export.

## Decision

Authorize regression-first changes to the already allocated worker telemetry/OTLP source and tests and OpenBao revocation/PKI source and tests:

1. register each worker telemetry fetch/read/first cancellation owner before callbacks or abort reentry;
2. cap outstanding actual transports independently of bounded observation queues;
3. expose private identity-bound retirement and join it in production/development composite actual cleanup;
4. retain bounded loss accounting and nonfatal ordinary collector outage;
5. acquire response-level custody before header validation or `getReader()` and always initiate/join original body cancellation on exceptional exits;
6. preserve generic errors, sticky uncertainty, credential/material/WAL barriers and fresh close observers.

Held fetch or cancellation must keep manager/worker actual retirement pending and prevent dependent release. Later settlement may complete actual retirement but cannot heal a failed lifecycle attempt.

Raise only completion's owner ceiling from 2,300 to 2,600 lines. Keep the global 18,500 ceiling and every other owner/Stage2/post-H/source/v5 limit. Allocate one additional decision-file slot, bringing the exact new-file ceiling to thirty-six, still below the original forty. Future freeze/control and Q/qualification records move to ADR 0317 and ADR 0318.

## Validation

Permanent tests and independent reproductions must cover held worker fetch, held 503-body cancellation, actual-capacity saturation, hostile header/getReader throws, cancellation rejection, close reentry, ordinary outage and final dependent release. Full checks, deterministic evidence regeneration, accounting and final hostile review remain required.

## Authority boundary

This ADR grants local correction, testing and ordinary protected CI only. It grants no producer, publisher, preflight, qualification, OpenBao image admission, AWS credential/API, provider/OpenTofu, SSM, inventory, deployment, campaign, production, release or Stage4 authority. Work stops before the authoritative chain.

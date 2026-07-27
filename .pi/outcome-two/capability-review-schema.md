# Outcome 2 capability schema/driver hostile review

**Review target:** `9c86bc5add169fadd86574fd8468422a46ee3ed0` (`review/cap-schema`)  
**Authorities:** accepted `docs/adr/0087-prepare-runtime-closure-before-capability-drop.md`, `OUTCOME-TWO-PLAN.md`, and `.pi/outcome-two/capability-implementation-gate.md`  
**Implementation reviewed:** the five capability surfaces authorized by ADR 0087  
**Disposition:** review only; no production or workflow implementation changed

## Verdict

**BLOCK.** There are unresolved P1–P3 findings. The implementation remains non-authoritative (`authority="none"`, `qualified=false`) and source/envelope fields remain structurally separate, but the public schema discloses prohibited IDs and the production semantic validator can accept impossible complete reports.

## P0

No findings.

## P1

### P1-1 — The public report discloses UID/GID mappings forbidden by ADR 0087

**Lines:**

- `schemas/runner-capability-probe-v1alpha1.json:190-200`
- `scripts/runner-capability-probe.py:687`
- `scripts/runner-capability-probe.py:1316`
- `scripts/runner-capability-probe.py:1409-1415`

The schema requires `uid_map` and `gid_map`; the fixed helper reads the numeric triples from procfs; and the driver copies them into the report and validates their numeric ranges. A successful user-namespace case therefore places concrete UID/GID values in the ordinary public job log. ADR 0087 line 217 explicitly prohibits UID/GID output. Retaining the earlier field inventory does not override that controlling disclosure restriction.

Remove numeric map rows from the public schema/report and retain only reviewed categorical status/postcondition metadata.

### P1-2 — The production semantic validator accepts `ok` operations with false required postconditions and other impossible complete reports

**Lines:**

- `scripts/runner-capability-probe.py:804-818`
- `scripts/runner-capability-probe.py:1382-1465`
- `test/runner-capability-probe.test.ts:234-259`
- `test/runner-capability-probe.test.ts:352-363`

`sudo_descriptor_case()` labels every decoded helper result `ok`, including results where fd 3 or fd 4 has the wrong state. `validate_report()` applies `validate_observation()` only to namespace, descriptor, tmpfile, and O_PATH subsets; it never couples the sudo, map-files, user-map, combined namespace/proc, seccomp, or KVM statuses to their postconditions and prerequisites. The independent TypeScript semantics likewise check only one descriptor case.

A direct mutation check against the current `validate_report()` accepted all of these:

- `sudo.close_from_3.invocation=ok` with `fd3_closed=false`;
- `map_files_opened=8` with `executable_mappings_selected=0`;
- `seccomp.install_filter=ok` with `network_syscalls_policy="filter-unavailable"`; and
- `close_range_low=blocked` while its fixed prerequisite remains successful.

Such a report can still be `outcome="complete"`. This violates ADR 0087 C14's exact status/errno/postcondition coupling and defeats the required independent semantic challenge. Validate every fixed case and add adjacent mutations for every status-bearing field.

### P1-3 — Prerequisite failures are reported as failures of operations that were never attempted

**Lines:**

- `scripts/runner-capability-probe.py:567-578`
- `scripts/runner-capability-probe.py:697-703`
- `scripts/runner-capability-probe.py:1238-1242`

When mount-namespace creation or propagation fails, the driver copies that status into `open_otmpfile` and `open_opath_directory`, although neither operation ran. Likewise, a helper seccomp-setup failure is returned as the helper result and then copied into `host_map.maps_read`, although maps were not read. A denied setup can therefore be reported as a denied tmpfile/O_PATH/maps operation.

ADR 0087 C14 requires an unattempted operation to be `blocked` with null errno and a named fixed non-`ok` prerequisite. Preserve the prerequisite result separately and classify downstream unattempted operations as blocked; do not transfer an upstream errno to them.

## P2

### P2-1 — Complete reports can contain fabricated or permanently unobserved seccomp/proc fields

**Lines:**

- `schemas/runner-capability-probe-v1alpha1.json:279-299`
- `scripts/runner-capability-probe.py:970-983`
- `scripts/runner-capability-probe.py:1268-1275`
- `scripts/runner-capability-probe.py:1296-1302`
- `scripts/runner-capability-probe.py:1331-1334`

The schema makes initial seccomp mode and initial NNP non-null. If either query fails—or the whole child fails—the driver writes `0`, turning an unobserved value into an observed-looking value. Separately, `child_proc_distinct_from_parent` is always null, even after a successful combined proc case. `complete` is computed only from host/bootstrap and cleanup state, so neither condition prevents a complete report.

This conflicts with C14's requirements that unobserved postconditions be null and that every fixed case be categorically classified before `complete`. Make observation fields nullable where failure is representable, couple them to their status, actually measure the proc distinction, and include full categorical completeness in outcome derivation.

## P3

### P3-1 — Envelope numeric domains differ between schema, driver, and golden test

**Lines:**

- `schemas/runner-capability-probe-v1alpha1.json:120-123`
- `scripts/runner-capability-probe.py:1088-1090`
- `test/runner-capability-probe.test.ts:97-101`

The schema and golden report accept `run_id="0"`, while the workflow-bound driver rejects zero. Conversely, the driver accepts ten-digit PR numbers through `9,999,999,999`, while the schema caps the value at `2,147,483,647`; the driver does not run schema validation before emission. These are presently unlikely GitHub values, but they make the claimed schema/driver contract non-exact.

Use one shared documented domain in schema, production parsing, and fixtures, and test both boundaries.

## Explicit no-findings areas

- **Canonical emitted bytes:** no finding. `scripts/runner-capability-probe.py:94-115` rejects non-JSON Python values/floats, uses strict UTF-8, lexical key sorting and compact separators, appends exactly one LF, and enforces the 32,768-byte bound.
- **Source/envelope separation:** no structural finding. `scripts/runner-capability-probe.py:1093-1113` and schema lines 95-124/301-312 keep source-head identities and GitHub envelope identities separately named.
- **Authority:** no finding. Schema constants, driver construction, and the three-step workflow retain `authority="none"`, `qualified=false`, and no artifact/upload route.

## Checks performed

- `/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test` — passed.
- Direct production-validator mutation check — reproduced the four P1-2 acceptances listed above.
- Capability gross additions from `bec0a19b0b984f88ab9c2effc5059f3737915caa` — 2,744 lines across the five authorized surfaces, below the 2,830 aggregate high; each listed surface is below its file high.
- TypeScript/schema/format/typecheck commands could not run because this clean worktree has no installed `tsx` (`tsx: command not found`).

No capability workflow was triggered, no report was uploaded, and no production file was changed.

CAP-REVIEW-SCHEMA COMPLETE

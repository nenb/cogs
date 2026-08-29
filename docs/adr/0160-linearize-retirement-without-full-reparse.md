# ADR 0160: Linearize retirement without a full reparse

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

Private execution proved fresh transient cleanup deleted all 4,353 rootfs entries and durably appended `operation-absent` and `retired`, but then reopened and fully reparsed the 58 MiB, 39,210-record ledger before unlinking it. That redundant fold exhausted the cleanup deadline. Crash recovery of the same valid retired ledger took 319 seconds, while the workflow exposed only 300 of ADR 0047's authorized 600 seconds.

`_session_append("retired")` already validates the exact previous phase, appends and fsyncs the record, reads back exact bytes, advances the validated legal history, and rebinds the ledger and state parent at phase `retired`. Advance that same poisoned cleanup session's status and pass it directly to the unchanged `_unlink_ledger` checks. Do not reconstruct a second cleanup model before unlink. A restart still performs the complete independent fold.

Expose the full existing 600-second recovery ceiling in the workflow and raise only its enclosing job/step bounds accordingly. This is cleanup capacity, not build work or retry authority. No AWS, provider, evidence, promotion, or release authority follows.

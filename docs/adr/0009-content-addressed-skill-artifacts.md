# ADR 0009: Transport skills as verified content-addressed artifacts

- Status: Proposed
- Date: 2026-07-10
- Reviewer: Nick Byrne

## Context

Platform and private user skills must be reproducible and available both to Pi as instructions and to scripts in the guest, without exposing registry/object-store credentials or trusting a guest-modified copy.

## Decision

- Publish shared skills as immutable OCI artifacts pinned by SHA-256 digest.
- Snapshot private skills as content-addressed archives in S3-compatible object storage.
- A trusted materializer fetches and verifies artifacts without exposing its credentials to the guest.
- Cogs parses bounded skill instruction text only from the trusted verified copy; it never imports the artifact as a Pi package or extension.
- The materializer rejects traversal, absolute paths, links, devices, duplicate normalized paths, unsupported media types, and file/count/compressed/uncompressed size limit violations.
- Transfer the exact verified archive into the guest over SFTP and record the digest in session/export metadata.
- Local development uses filesystem storage or MinIO while preserving the digest/manifest contract.

Skills are always untrusted instruction content; any scripts execute only through sandbox tools.

## Consequences

Guest root can mutate its own delivered view. “Same skill” therefore means that Pi loaded the trusted bytes matching the recorded digest and those same bytes were initially transferred; it does not claim the guest copy remains immutable. Updates become visible only on resource restart in the MVP.

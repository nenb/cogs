# ADR 0166: Linearize operation append readback

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

A native input observation reached 1,397 durable operation records before the 3,470-second lifecycle bound. The first 150-record interval took 8 seconds and the last took 177 seconds. Every append performed complete legal-history validation before the effect, then reread, reparsed, and legally revalidated the entire growing journal after fsync, and repeated legal validation during layout checking. This produced quadratic work without adding an independent mutation boundary.

Keep one complete legal-history validation before every append. Open the authenticated mode-0600 root-owned journal generation read/write with append semantics, append at the exact expected offset, fsync, derive and verify the new generation, read back exactly the appended canonical bytes with `pread`, require EOF at that generation, and re-observe the exact child identity. Construct the new in-memory record from those already validated bytes and pass the precomputed legal phase to unchanged layout validation. Recovery, fresh process open, retirement, and evidence still read and parse the entire journal.

The prefix cannot be mutated by an untrusted principal: its parent and journal are root-owned and non-writable, and trusted host/root administrators remain in the threat model. Any offset, generation, identity, size, readback, fsync, layout, or later full-parse mismatch remains uncertainty. This grants no batching, omitted fsync, retry, AWS, provider, deployment, evidence, promotion, or release authority.

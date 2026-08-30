# ADR 0247: Normalize hosted opt for qualification

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

Final path diagnostic run `33298455621`, attempt 1, identified the exact mismatch: the hosted runner presents root-owned `/opt` as mode 0777 while every descendant in the reviewed Kata configuration path is root-owned and non-writable. Static admission correctly rejects traversal through that replaceable parent. Osito presents a non-writable `/opt`, explaining the private pass. All diagnostic cleanup passed.

For the local qualification workflow only, require the exact hosted baseline `root:root:777`, change `/opt` to 0755 before immutable publication, and verify 0755 before any static custody or lifecycle entry. After recovery, fixed cleanup, independent residue, publication/readback processing, and removal of `/opt/kata`, restore only the exact root-owned `/opt` parent to 0777 in an always-run bounded step. Accept an already-restored 0777 parent, reject every other owner or mode, bind restoration into the final custody-chain outcome, and never restore while `/opt/kata` remains. This removes the pathname-replacement surface during qualification without weakening admission.

Bind failed qualification run `33292919137`, attempt 1, exact H `89243c8d9f7a946aefdaa4c445a5cfe1e0fe7e14`, control head `54973848cac9b2ce168b539fff4b03802fb514aa`, and failed conclusion as the tenth non-authorizing predecessor. After review and a new protected-main G, authorize one replacement attempt-1 qualification observation. The earlier run and all diagnostics grant no retry or promotion claim.

This decision raises only the complete tracked-source cardinality bound from 1,208 to exactly 1,209 files and the measured workflow correction high from 1,420 to 1,460 gross lines. All other bounds and complete-inventory rules remain unchanged. This grants no AWS, provider, deployment, campaign, production, or release operation.

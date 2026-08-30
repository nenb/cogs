# ADR 0178: Canonicalize ctr bootstrap and consume network grant shape

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-25

H21 crossed containerd readiness and both pre-launch container/task absence probes, then reached `CTR_RUN` intent validation. The fixed bootstrap was a multiline shell argument, while the operation journal correctly rejects control characters in every argv element. Express the same fixed `set -eu` bootstrap as one canonical semicolon-delimited argument; do not weaken the journal text grammar.

The failure cleanup also exposed a type mismatch in process observation. Runtime network verification deliberately returns a closed dictionary containing operation token, exact nsfs identity, and path, but process census treated it as the internal parser object. Convert only that exact dictionary shape to `net:[positive-inode]`, requiring the tokenized namespace name and matching `/run/netns/<name>` path. Continue comparing QEMU and virtiofsd procfs namespace roots against that derived value.

Focused tests reject multiline bootstrap policy, malformed paths, zero inodes, and foreign names. H21 was a non-authoritative diagnostic and grants no qualification or promotion claim.

This decision grants no retry within an observation, production fast path, evidence, promotion, AWS, provider, deployment, or release authority.

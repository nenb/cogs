# ADR 0169: Provision the NFT owner and read complete mountinfo

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

A complete input observation reached baseline capture, which proved the fixed NFT writer owner had never been provisioned by the formal workflow. After diagnostic provisioning, the next observation passed baseline capture and reached network setup. Its raw unbuffered `/proc/self/mountinfo` reader made one `read()` call; procfs returned a newline-terminated 4,083-byte prefix of the 6,411-byte file, so the newly created `/run/netns` parent mount was falsely reported absent.

After immutable source preparation and before the sole qualification entry, run the existing zero-input, fixed-path fresh-host NFT owner provisioner under a 45-second command inside a one-minute workflow step. It requires absent state and refuses reuse or partial provisioning. Read mountinfo in bounded chunks through EOF, retaining the existing four-megabyte maximum, terminal newline, strict parser, cardinality, and identity checks.

The durable NFT owner returns to `FREE`; an ephemeral qualification host owns that fixed infrastructure. This grants no caller-selected path, incomplete procfs observation, retry, AWS, provider, deployment, promotion, or release authority.

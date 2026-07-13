# Insecure container driver

This Stage 1 development driver exercises the production SSH/SFTP and explicit-proxy contracts in a plain Debian container. It has **no VM-isolation or external default-deny claim**. Every container, command result, and evidence report is labelled `insecure-container` / `functional-only`.

## Lifecycle

```bash
dev/insecure-sandbox/driver.sh create
dev/insecure-sandbox/driver.sh verify
dev/insecure-sandbox/driver.sh reset
dev/insecure-sandbox/driver.sh destroy
```

`create` generates a host key and client key before container startup. Only the host private key, client public key, and public egress CA enter the container. The controller constructs `known_hosts` from the pre-generated host public key; it never uses `ssh-keyscan`, trust-on-first-use, an SSH agent, or forwarding. `verify` checks root SSH command execution, proxy/CA inputs, workspace persistence, SFTP round-trip, and a host-key-mismatch positive control. `reset` destroys and recreates all state. `destroy` verifies removal of the container and temporary workspace volume.

The container has a read-only root filesystem, bounded tmpfs mounts, a temporary workspace volume, and no privileged/host mounts. It intentionally retains ordinary Docker bridge networking: guest root can bypass proxy variables, so this profile cannot support a network-isolation claim.

Set `COGS_PUBLIC_CA_FILE` to inject an existing **public** test CA. Otherwise the launcher generates an ephemeral CA, deletes its private key before container startup, and injects only the certificate. `COGS_HTTP_PROXY` / `COGS_HTTPS_PROXY` set the explicit proxy variables; absent values use a non-resolving placeholder until a proxy adapter is available. Real integration credentials and CA private keys are forbidden.

The image uses a digest-pinned Debian base and a dated Debian snapshot. It contains OpenSSH plus curl, Git, pip/Python, npm/Node, Java, HTTP/2-capable curl, DNS/raw-network utilities, and the root tooling needed for compatibility and bypass probes.

The label-gated CI workflow currently runs the SSH/SFTP driver smoke and publishes applicability-aware functional evidence. Once the first proxy adapter exists, that workflow is extended to run the `insecure-container` conformance profile; smoke evidence alone never selects a proxy or satisfies Stage 1 security acceptance.

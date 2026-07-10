Goal: Build a scalable personal assistant inspired by OpenClaw, backed by the coding agent Pi, but minimal, k8s-friendly and crucially, designed securely to protect against threat model

Threat Model
- Coding agents run code that is **untrusted by default**: prompt injection, dependency chains pulled by the agent, ... .
- The failure modes that matter include secret exfiltration, source code theft, kernel exploit from inside container/VM.

Ideal Design to protect against threat model
- VM for agent actions but that has secret injection outside the VM. The secret injection taking place outside the VM is
motivated by the fact that the Agent will likely need to run root in VM and that a standard container Envoy model only handles
header-replacement auth anyway. See SECRET-INJECTION.md for more details.

Feature Requests
- An agent that can be deployed on a k8s platform like NIC. The number of agents should be scalable to the number of users of the platform.
- Prompt-to-commit synchronisation. From any git commit, ability to restore correct chat session log state up to that point.
- Session sharing. Users can export chat sessions to share with other developers along with ability to sanitize these sessions to remove PII.
- There are shared skills that the agent can discover available on the platform.
- Observability. Both users and admins have insight into both token and resource usage, that contains sufficient information to build dashboards on top of.
- Agent Observability. The agent needs to be able to get feedback on all events in its VM, along with the ability to get information required for debugging for externally deployed apps.
- Apps. An ability for the agent to request its own resources for deploying apps - these are admin approved after some limit
- User filesystem with ability to add search functionality like FTS and vector databases and indexing later.
- The technology to run agents as personal assistants **already exists**. To maximize adoption, our goal instead is to try and keep the platform as simple, dumb and hackable as possible, and to try and leverage only well-established tools. **This lowers adoption friction for organizations with significant process overhead.**
- Filesystem allowlist?
- Network audit (e.g.HTTP request (URL, method, status, latency, which secrets were injected))?
- Execution log and fs audit (which files accessed and with what operations) would also be a bonus?
- Auditability. Ideally it will be possible to enforce policy via something like Open Policy Agent. Can we wrap tools and actions in a middleware layer to allow logging all actions, or is this likely too expensive?

Previous Design - currently released products that may or may not act as inspiration
- Lefos can only execute Python code. Has a bunch of tools already installed. Compute resources are modest - sandboxed for data wrangling, scripting and analysis.
- Docker Sandboxes uses a custom VMM, not Firecracker. Inside each microVM, the sandbox runs a complete Docker Engine. Outbound HTTP/HTTPS traffic routes through a proxy on the host, accessible from inside the VM at host.docker.internal:3128. UDP and ICMP are blocked at the network layer and can’t be allowed by policy. Non-HTTP TCP (like SSH) needs explicit IP+port rules. DNS resolution goes through the proxy. If a request can’t go through the proxy, it doesn’t leave. The proxy terminates TLS, inspects the host header, applies your policy, and re-encrypts with its own certificate authority that the sandbox trusts. Docker keeps credentials on the host and has the proxy inject them into outbound requests transparently. Docker, Lefos and many others attempt to design their systems so that secrets never exist in the sandbox. Related to this they also have network allowlists.
- Unix made a design decision 50 years ago: everything is a text stream. Programs don't exchange complex binary structures or share memory objects — they communicate through text pipes. Small tools each do one thing well, composed via | into powerful workflows. Programs describe themselves with --help, report success or failure with exit codes, and communicate errors through stderr. LLMs made an almost identical decision 50 years later: everything is tokens. They only understand text, only produce text. Their "thinking" is text, their "actions" are text, and the feedback they receive from the world must be text.
- Lefos gives access to email history, attachments, web, Google Workspace, a filesystem, allows scheduling and skills. User storage is scoped to a subdomain. For Google Workspace, only metadata is stored locally and is fetched only when triggered.
- Lefos addresses prompt injection through several mechanisms: the rules-based policy layer restricts what actions can be triggered and by whom; untrusted content (like forwarded emails from unknown senders) is handled with additional scrutiny; and the architecture separates reasoning from execution in a way that limits what injected instructions can actually do. I won't claim any system is perfectly immune, but the design explicitly accounts for this threat.
- pi-chat routes bash, read, write, and edit into a per-conversation micro-VM.
- pi-chat has account-wide skills in /shared/skills/ and channel-specific skills in /workspace/skills/. Skills are markdown files or SKILL.md directories with frontmatter. They are auto-discovered and injected into
 the prompt.
- mounts in pi-chat are Per conversation: /workspace maps to the channel workspace. Per account: /shared maps to shared storage. Attachments land under /workspace/incoming; runtime secrets under /workspace/.secrets; memory under
 /workspace/memory.md and /shared/memory.md.
- memory.md in pi-chat is used to store information, consider how this might be expanded to be more dynamic and to involve search and retrieval algorithms
- pi-chat mounts /shared into every chat
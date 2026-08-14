# Potential Cogs Extensions

## Trusted platform tools and Gatekeeper-style integrations

**Status:** Design idea only. None of this is currently implemented. This document grants no cloud, deployment, production, retry, or release authority.

Cogs currently gives each Pi session four fixed tools: `read`, `write`, `edit`, and `bash`. A future extension could let a platform administrator install trusted tools and select an exact, fixed tool set before a session starts.

Examples include:

- `read_email`;
- `list_calendar_events`;
- `create_calendar_event`;
- `read_slack_channel`;
- `query_metrics`; and
- `create_support_ticket`.

This proposal covers only tools installed and trusted by the platform administrator. It does not allow users, agents, repositories, or workspace files to add tool code.

## Motivation

The existing sandbox proxy is appropriate for ordinary programs that need HTTP access, including Git, npm, and PyPI. It can restrict destinations, methods, paths, and credentials while keeping real credentials outside the sandbox.

Sensitive business integrations often need rules that are difficult to express as HTTP routes. For example:

```text
Read at most ten messages from the Support label.
Do not return attachments.
Do not read Spam or deleted messages.
Only read messages from the last 30 days.
Require approval before sending anything.
```

An email-specific tool can understand and enforce these rules. A generic proxy understands hosts, methods, paths, and queries, but not the full meaning of mailboxes, labels, messages, or attachments.

Platform tools would also let different sessions receive different authority:

```text
Coding session:
  read
  write
  edit
  bash

Email-reading session:
  read_email

Operations session:
  read_incident
  query_metrics
  create_ticket

Mixed session:
  read
  write
  edit
  bash
  read_email
  query_metrics
```

The selected tool set must not change after the session starts.

## Cloudflare Gatekeepers as prior art

This proposal is informed by Cloudflare OS Gatekeepers, reviewed at commit `1cb5e3d9096589e38f3fcfaf3f2191aa95a4c592`. Cogs does not need to copy Cloudflare Workers, Durable Objects, Facets, or Cap'n Web to adopt the useful security ideas.

A Gatekeeper is a trusted adapter between an untrusted agent or generated application and an external service:

```text
Agent or application
        |
        | searchMessages({sender, limit})
        v
Trusted email Gatekeeper
        |
        | uses OAuth credential
        v
Gmail
```

The agent receives a narrow operation. It does not receive the OAuth credential or general Gmail network access.

A Gatekeeper normally provides several related functions:

1. It connects a user's external account and owns the credential lifecycle.
2. It grants a particular resource, rather than every resource in that account.
3. It exposes a small, typed interface to the agent or application.
4. It records reads before protected data is returned.
5. It queues changes for approval before applying them.
6. It may simulate pending changes when it can do so reliably.
7. It may undo an applied change when the vendor supports a safe inverse operation.
8. It can help verify that collaborators may see data previously read through the integration.

Cloudflare OS runs each integration as a separate trusted Worker. Generated application code has no general outbound network access and can reach external systems only through named bindings such as `TEAM_CALENDAR` or `PROJECT_GITHUB`.

### Reads and changes

Gatekeepers distinguish two kinds of operation:

- An **observation** reads protected information.
- An **action** changes an external system.

For example:

```text
read_email             observation
list_calendar_events   observation
send_email             action
create_calendar_event  action
delete_calendar_event  destructive action
```

A read must be recorded and authorised before its result is returned. An action must enter an approval and audit path, even when policy later permits automatic approval.

### Simulation and undo

Some Gatekeepers can show the agent what the world would look like if a pending action were approved. This lets the agent continue working while the user reviews actions later.

This is optional and specific to each integration. A calendar event may be represented as pending and later deleted. A sent email generally cannot be recalled reliably. No integration framework should promise generic simulation or undo.

### Collaboration checks

Suppose Alice's application reads a private document and Alice then shares the application with Bob. Cloudflare's observer design asks whether Bob can independently access the information the application already read. It can also block a future read when an existing collaborator is not allowed to see the new result.

This is stronger than checking only whether Bob may open the application. It protects data that has already passed through an integration and may now be stored in application or chat state.

### Gatekeeper limits

Gatekeepers reduce authority but do not make an agent trustworthy. A malicious or prompt-injected agent may still:

- misuse every operation it has been granted;
- call a read operation repeatedly;
- copy returned data into another permitted system;
- provide misleading but valid inputs; or
- abuse a change that a user approves.

The integration implementation is also trusted. An incorrect read/write classification or resource check can weaken the intended protection.

## Proposed Cogs platform-tool model

A platform administrator should be able to install a trusted tool and select it through a strict session configuration:

```json
{
  "version": "cogs.platform-tools/v1",
  "tools": [
    {
      "module": "/opt/cogs/platform-tools/read-email.mjs",
      "sha256": "<exact module digest>",
      "export": "createReadEmailTool",
      "binding": "WORK_EMAIL",
      "configuration": {
        "account_handle": "users/alice/integrations/work-email",
        "max_messages": 10,
        "max_response_bytes": 262144,
        "attachments": false
      }
    }
  ]
}
```

For this example, Pi would receive `read_email` but not `bash` unless `bash` was also selected.

Configuration selects installed authority; it does not create authority by itself. The external platform must still authenticate the user, validate the account and resource binding, and approve the exact launch document.

## Platform-tool contract

A platform module would export a versioned factory that returns:

- a unique tool name;
- a short description for the model;
- a strict input schema;
- whether it reads data or changes something;
- a stable resource or binding name;
- optional action properties such as whether approval is required; and
- the code that performs the operation.

Conceptually:

```ts
export function createReadEmailTool(config) {
  return {
    name: "read_email",
    description: "Read a limited selection of messages from the configured mailbox.",
    operation: "observation",
    resource: "WORK_EMAIL",
    parameters: {
      query: "string",
      limit: { type: "integer", minimum: 1, maximum: config.max_messages }
    },
    async execute(input, context) {
      return context.email.read({
        accountHandle: config.account_handle,
        query: input.query,
        limit: input.limit,
        attachments: config.attachments,
        signal: context.signal
      });
    }
  };
}
```

The exact interface would be versioned. Unknown fields, unknown versions, duplicate names, invalid schemas, unsupported action claims, and invalid configuration would stop startup.

## Trusted installation

Platform tool source may be written in TypeScript, but production should normally load compiled JavaScript or an immutable bundled artifact. This avoids compiling code during startup and makes the exact deployed bytes easier to verify.

A production tool must:

- be installed outside the sandbox and user workspace;
- be owned and writable only by the platform administrator;
- be read-only to the Cogs process;
- have an exact expected digest or immutable artifact identity;
- be included in dependency, vulnerability, license, source, and release review; and
- never be discovered from `/workspace`, project packages, Pi extensions, or environment search paths.

Loading a module into Cogs is equivalent to adding trusted Cogs code. The module becomes part of the trusted system.

## Startup flow

Before creating the Pi session, Cogs would:

1. securely read and validate the platform-tool configuration;
2. verify each configured module's identity and exact bytes;
3. load each module from an administrator-controlled location;
4. validate its exported tool definition;
5. apply common policy, timeout, cancellation, output-size, telemetry, audit, and cleanup wrappers;
6. register only the selected tools with Pi; and
7. fail startup if any required tool cannot be prepared safely.

No module would be added, removed, or replaced while the session is running.

## Relationship to the sandbox proxy

Cogs can support two integration paths.

### Ordinary development traffic

```text
Sandbox -> trusted proxy -> Git, npm, PyPI, approved HTTP APIs
```

This path supports existing command-line tools and SDKs. The permission applies to all untrusted processes in that session's sandbox.

### Sensitive structured operations

```text
Pi -> Cogs platform tool -> trusted integration code or service -> vendor API
```

This path supports narrow business operations. The sandbox does not receive the credential or network route.

If `read_email` is intended to be the only email capability, Gmail and the email service must not also be reachable from the sandbox. Otherwise `bash` or a malicious dependency could bypass the tool and exercise the same authority through the proxy.

Using the proxy for Gmail remains a valid choice when the intended permission is: "all code in this session may use these limited Gmail routes." A platform tool is preferable when the intended permission is: "the agent may perform only this named, structured email operation."

## Benefits compared with proxy-only access

Trusted platform tools could provide many of the most useful Gatekeeper properties:

- **Explicit access:** each session receives only the named tools it needs.
- **No automatic account access:** connecting an account does not expose it to every session.
- **Clear inputs:** `read_email` accepts email concepts instead of arbitrary HTTP requests.
- **Detailed limits:** a tool can enforce mailbox, label, date, count, attachment, and result-size limits.
- **Credentials outside the sandbox:** guest processes cannot read or directly use the credential.
- **Clear records:** audit events can say that five messages were read without centrally storing their contents.
- **Read/change distinction:** reads can be observations, while changes enter an approval path.
- **Different authority per session:** one session may read email while another may also draft or send it.
- **Bounded discovery:** the model can see a short description of configured bindings without seeing every account or every possible vendor operation.

## Functionality not provided by module loading alone

### In-process access

A module loaded into the Cogs process can potentially access the same memory, files, credentials, and internal connections as Cogs. Configuration does not isolate one module from another.

This is a larger failure scope than a separate Gatekeeper service. It is acceptable only for code reviewed and trusted by the platform operator.

For stronger separation, a Cogs tool could be a thin client for a separate trusted service:

```text
Cogs -> email service -> Gmail
Cogs -> calendar service -> calendar provider
Cogs -> Slack service -> Slack
```

Each service could hold only its own credentials and permissions. This is optional additional hardening, not required for a first platform-module version.

### Account connection and OAuth

A tool configuration can name an account, but it does not provide the user interface or service needed to connect that account. A separate trusted component may still need to own:

- login and consent;
- refresh-token rotation;
- access-token refresh;
- revocation; and
- account selection.

Several Cogs sessions must not independently update the same rotating refresh token. A single account service or integration service should own that state.

### Resource-specific grants

An account handle may still be broad. A stronger design binds a session to an exact resource, such as one repository, calendar, mailbox, Slack channel, or database project.

The launch document should record that immutable binding. The tool must reject requests outside it rather than silently widening access.

### Durable approval of changes

Declaring `send_email` as an action does not create an approval system. Cogs would still need an external durable queue and user interface.

A possible flow is:

1. Cogs validates the exact proposed action.
2. Cogs stores or submits an immutable pending-action record.
3. Cogs emits `approval_required` and settles or pauses according to the tool contract.
4. The external daemon obtains a user decision.
5. A fresh, exact authorisation applies or rejects that action.

The action must not happen before approval. Failure or uncertainty must not become approval, success, or permission to retry. Changed inputs require a new action and new approval.

### Automatic approval

If automatic approval is added, it should require both:

- the integration marking that exact action safe for automatic application; and
- the user or administrator enabling automatic approval for that action class.

Actions must remain ordered. A later automatic action must not skip past an earlier manual decision or failed action.

### Preview and undo

Some integrations can preview a proposed change or undo it later. Others cannot. Each tool must implement and test these properties separately.

For example, a newly created calendar event may be removable, while a sent email generally cannot be recalled reliably. Cogs must not promise generic simulation or undo.

### Collaboration and sharing

A typed tool can report which protected resource was read, but Cogs does not currently use that information to control sharing.

A future observation record could contain only protected metadata:

```json
{
  "tool": "read_email",
  "binding": "WORK_EMAIL",
  "resource_type": "gmail.message",
  "resource_id": "<opaque message identity>",
  "observed_at": "<timestamp>"
}
```

It should not centrally store the message content.

Before sharing a session, a future collaboration service may need to ask the relevant integration whether each recipient can independently access all protected resources already read. It may also need to block a later read when an existing collaborator cannot see the result.

Without these checks, a shared session could reveal data that a collaborator could not access directly.

### Information leaving through another allowed tool

A narrow `read_email` tool does not prevent the model from sending returned email content to another permitted destination. A session with both `read_email` and a write-capable ticket tool could copy email text into a ticket.

Preventing this requires information-flow or content-inspection policy beyond tool selection. The initial design must state this limitation clearly.

### Untrusted returned content

Email, documents, tickets, and chat messages may contain prompt injection. Tool results must be treated as untrusted data, bounded in size, and clearly identified to the model.

This does not make prompt injection harmless. Security still comes from limiting the operations available to the session and requiring approval for consequential changes.

### Independent integration updates

In-process modules normally follow the Cogs worker release lifecycle. Updating one module may require rebuilding or requalifying the worker and its complete trusted source and dependency set.

Separate trusted services can be versioned, revoked, and deployed independently, but add authenticated protocols, deployment, monitoring, and failure handling.

### Tool provenance and review

A path alone is not evidence of what code ran. Production evidence would need to bind the configuration to exact module bytes, dependencies, source, review, and the worker image or immutable external artifact that supplied them.

Local loading success would not establish production readiness or release eligibility.

## Comparison summary

| Concern | Cogs proxy | In-process platform tool | Separate Gatekeeper-style service |
|---|---|---|---|
| Works with ordinary CLI tools | Yes | No, unless wrapped | No, unless wrapped |
| Understands vendor concepts | Limited | Yes | Yes |
| Credential enters sandbox | No | No | No |
| Any sandbox process can use granted route | Yes | No | No |
| Per-session named capability | Route group | Yes | Yes |
| Integration isolated from Cogs memory | Yes for proxy secret handling, but the session can use the route | No | Yes |
| OAuth/account lifecycle included | No | Only if module implements it | Usually |
| Durable approval queue included | No | No | Can be added |
| Simulation and undo included | No | Only per tool | Only per integration |
| Collaboration checks included | No | No | Can be added |
| Operational cost | Existing | Low | Higher |

## Suggested delivery order

1. Add a strict, administrator-only toolset configuration.
2. Make the four existing tools selectable rather than mandatory.
3. Define a versioned platform-tool module interface.
4. Load exact administrator-installed modules before Pi starts.
5. Add common policy, bounds, telemetry, audit, cancellation, and cleanup wrappers.
6. Implement one read-only tool, such as `read_email`, with no sandbox route to the same service.
7. Add bounded named-binding and tool-description discovery.
8. Add a single trusted account service for OAuth-based tools if needed.
9. Add durable approval handling before enabling tools that change external systems.
10. Add optional simulation and undo only for integrations that can prove correct behavior.
11. Move high-risk integrations into separate services when reduced in-process access justifies the cost.
12. Add observation-based collaboration checks before sharing sessions containing protected data.

The first six steps provide most of the immediate least-access and audit benefits. Later steps add the broader Gatekeeper behavior incrementally.

## Non-goals

This proposal does not allow:

- user-authored or agent-authored tools;
- modules loaded from a repository or workspace;
- automatic package or extension discovery;
- arbitrary installation while a session is running;
- configuration to count as authorisation by itself;
- tool descriptions or third-party annotations to establish that an operation is safe;
- generic claims that actions can be simulated or undone;
- a claim that tool restrictions prevent all data leakage; or
- local tool loading to establish deployment, production, or release authority.

## Summary

Cloudflare Gatekeepers combine typed access, credential ownership, resource-specific grants, read tracking, action approval, optional simulation and undo, collaboration checks, and separate integration services.

Cogs can gain the core benefits with a smaller first step: trusted platform modules selected through an immutable startup configuration. Common observation and action rules can follow. OAuth ownership, durable approvals, separate integration services, and collaboration enforcement can then be added only when needed.

This approach preserves Cogs' Pi, VM, SSH/SFTP, proxy, OpenBao, and Kubernetes design while allowing much narrower tools for sensitive business systems.

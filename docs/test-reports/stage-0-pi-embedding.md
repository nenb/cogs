# Stage 0 Pi embedding spike

- Pi packages: `@earendil-works/pi-coding-agent`, `pi-agent-core`, and `pi-ai` 0.80.6
- Node.js: 22.22.2
- Profile: local functional test; no VM or network security claim
- Automated test: `test/pi-embedding.test.ts`

## Proven

1. `createAgentSession()` runs headlessly with explicitly constructed in-memory `AuthStorage`, `ModelRegistry`, settings, a persistent `SessionManager`, and a closed custom `ResourceLoader`.
2. The active tool set contains exactly four custom harmless stubs named `read`, `write`, `edit`, and `bash`; the fake model invokes the custom `read` stub and receives its tool result.
3. A non-secret runtime API key supplied through in-memory `AuthStorage.setRuntimeApiKey()` is resolved for each fake stream call, creates no `auth.json`, and is absent from JSONL.
4. Executable global/project extension canaries and global/project Pi-package extension canaries do not execute during resource construction, prompting, tool execution, or pinned CLI export.
5. The pinned `DefaultResourceLoader` then runs against the same trusted project/global paths and package settings as a positive control, discovers all four valid extensions, and produces each unique marker. This proves the negative test cannot pass because inert or undiscoverable canaries were used.
6. Pi writes native version 3 JSONL. `SessionManager.open()` reloads it, navigates the original and alternate branches, and preserves both after an append-only alternate entry.
7. The pinned `pi --export` CLI opens the resulting JSONL and produces HTML without executing discovery canaries.

## Pi APIs relied upon

- `createAgentSession()`
- `AuthStorage.inMemory()`, `setRuntimeApiKey()`, `getApiKey()`, and `getAuthStatus()`
- `ModelRegistry.inMemory()`
- `SessionManager.create()`, `open()`, `getEntries()`, `getLeafId()`, `branch()`, and `appendCustomEntry()`
- `SettingsManager.inMemory()`
- the public `ResourceLoader` interface and `createExtensionRuntime()`
- `defineTool()` and `customTools`
- `tools` allowlisting with `noTools: "builtin"`
- the public `session.agent.streamFn` property for deterministic Stage 0 fake streaming only
- `createAssistantMessageEventStream()` from `pi-ai`

## Unsupported assumptions rejected

- Cogs cannot safely use `DefaultResourceLoader` and then attempt to filter discovered extensions afterward; extension factories are executable during loading.
- Project trust is not a Cogs security boundary and is not used.
- Disabling only built-in tools is insufficient unless the final active tool names and custom execution are tested.
- Pi package settings/install discovery is not allowed in the trusted worker.

## Upgrade gate

Any Pi upgrade must rerun this test unchanged or document and review the necessary contract change. Discovery execution, loss of native JSONL compatibility, inability to replace built-ins, or loss of runtime-only auth is a design blocker rather than a reason to weaken the test.

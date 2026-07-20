# Development launcher

`dev/launcher` is a development-only CLI for exercising reviewed Stage 3 pieces on local/CI hosts. It is not a daemon, scheduler, cloud provisioner, AWS path, deployment system, release gate, compliance claim, production authentication service, or production-readiness signal.

Run it through the shipped entrypoint:

```sh
npm run launcher -- --profile insecure-container --state demo create --timeout-ms 600000
```

Syntax:

```text
npm run launcher -- --profile <insecure-container|linux-kvm|macos-vm> --state <name> <op> [flags]
```

Operations:

| Operation | Flags | Meaning |
| --- | --- | --- |
| `create` | `--timeout-ms N` | Create and verify the profile sandbox, ending at `sandbox-ready`. |
| `start` | `--timeout-ms N` | Start the launcher worker from `sandbox-ready`, ending at `worker-ready`. |
| `run` | `--prompt-file REL --timeout-ms N` | Submit one bounded UTF-8 prompt file under the repo. Stdout is metadata only. |
| `history` | `--after CURSOR --limit N --timeout-ms N` | Return bounded metadata/history entries through the API contract. |
| `export` | `--out REL --timeout-ms N` | Write one sensitive local export under `.cogs-dev/exports`; stdout reports only metadata. |
| `abort` | `--timeout-ms N` | Request the current run abort. |
| `status` | `--json --timeout-ms N` | Report launcher inventory only: phase, descriptor class, live flag, recovery, cleanup-required, and driver-state class. |
| `shutdown` | `--timeout-ms N` | Gracefully request API shutdown, then always attempt exact supervisor stop. |
| `destroy` | `--timeout-ms N` | Destroy only exact owned sandbox state when worker controls are already clean. |
| `smoke` | `--timeout-ms N` | Fixed create/start/run/history/export/abort/shutdown/destroy smoke. |

Prompt and export paths are relative, bounded, repo/export-root contained, and reject traversal, symlinks, unsafe modes, oversized data, and hostile JSON shapes. API tokens are callback-scoped; token bytes, prompt text, event contents, tool output, paths, and credentials are not returned in stdout/status/evidence.

## Phase model and cleanup

The core phases are `sandbox-ready` and `worker-ready`. Worker startup writes exact control descriptors; recovery markers block new starts until exact cleanup is known. Unknown controls, malformed descriptors, hostile recovery files, replacement races, or uncertain cleanup fail closed with generic errors and preserve state for operator review.

Operator response:

1. Run `status --json` for metadata-only inventory.
2. If a worker is live, run `shutdown`; stop failures remain authoritative.
3. If inventory is clean, run `destroy` to remove exact owned sandbox state.
4. Do not recursively delete discovered state or runtime roots as a recovery shortcut.

`smoke` intentionally creates `launcher-smoke.json` as a sensitive local export. CI validates that exact current-user mode-`0600`, link-count-1 file, unlinks that exact file, fsyncs the parent, proves absence, and never uploads it.

## Linux runtime roots

Full trusted composition requires two separate externally provisioned Linux tmpfs roots before launcher use:

| Root | Required pre/post state |
| --- | --- |
| `/run/cogs/egress` | canonical non-symlink tmpfs directory, current uid/gid, mode `0700`, empty |
| `/run/cogs/ssh` | canonical non-symlink tmpfs directory, current uid/gid, mode `0700`, empty |

Host setup may use explicit workflow/operator `sudo` to create and mount those roots. The launcher itself must not mount them, use hidden `sudo`, weaken modes, fall back to repo paths, bypass Envoy, or switch profiles. Cleanup removes only exact recorded runtime files and proves the external roots empty; unmounting remains external host setup/teardown.

## Profile applicability

| Profile | Applicability | Authority |
| --- | --- | --- |
| `insecure-container` | Linux functional smoke when both runtime roots exist. Native macOS cannot complete full start because Linux runtime roots are absent. | `functional-only`; no isolation/default-deny evidence claim. |
| `linux-kvm` | Linux host with KVM/QMP/root-network prerequisites plus both runtime roots. | only `authoritative-local` profile; still not production/release evidence. |
| `macos-vm` | Optional absent-fail profile; native full trusted composition unsupported in this stage. | functional only if a reviewed driver is later added. |

There is no macOS fallback, cloud fallback, open-egress fallback, anonymous-auth fallback, or production-profile fallback.

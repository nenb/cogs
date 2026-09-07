import { createHash, randomBytes } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  rmdir,
  statfs,
  unlink,
  writeFile,
} from "node:fs/promises";
import { Socket } from "node:net";
import { dirname, join } from "node:path";
import type { EgressAuditWalRecord } from "../../src/egress/audit-wal.ts";
import type { CogsEgressCompletion } from "../../src/egress/completion-queue.ts";
import type {
  CogsEgressPkiMaterial,
  CogsEgressPkiRequest,
  CogsEgressPkiSource,
} from "../../src/egress/egress-material.ts";
import { createNodeCogsEnvoyProcessPort } from "../../src/egress/envoy-process.ts";
import { OpenBaoEgressPkiSource } from "../../src/egress/openbao-pki.ts";
import { lowerLaunchEgressRoutePlan } from "../../src/egress/route-policy.ts";
import {
  type CogsEgressRuntimeManager,
  type CogsEgressRuntimeManagerOptions,
  failedCogsEgressRuntimeManagerRetirement,
  observeCogsEgressRuntime,
  startCogsEgressRuntimeManager,
} from "../../src/egress/runtime-manager.ts";
import {
  beginRegisteredClose,
  closeObservationContext,
  createCloseOwner,
  joinCloseWork,
  observeClose,
  registerCloseOwner,
} from "../../src/launch/close.ts";
import { type LaunchConfig, validateLaunchConfig } from "../../src/launch/config.ts";
import { otlpEndpoint } from "../../src/telemetry/otlp-http.ts";
import type { LauncherProfile } from "./contract.ts";
import { createLinuxKvmRelay, type KvmRelay } from "./kvm-relay.ts";
import type { OpenBaoHandle, SecretHolder } from "./openbao.ts";
import { commandDescriptor, runCommand } from "./runner.ts";
import type { LauncherState } from "./state.ts";
import { readManifest } from "./state.ts";

const ENVOY_IMAGE = "envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb";
const ENVOY_IMAGE_DIGEST = "sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb";
const ENVOY_LABEL_KEY = "cogs.dev.launcher.envoy";
const EGRESS_TMPFS_ROOT = "/run/cogs/egress";
const USER_ID = "alice";
const MODEL_HANDLE = "users/alice/anthropic";
const INTEGRATION_ID = "stage3-localhost";
const EGRESS_HANDLE = "users/alice/integrations/stage3-localhost";
const MODEL_PROVIDER = "anthropic";
const MODEL_ID = "claude-sonnet-4-5";
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const MIN_ENVOY_BINARY_BYTES = 1024 * 1024;
const MAX_ENVOY_BINARY_BYTES = 256 * 1024 * 1024;
const LINUX_TMPFS_MAGIC = 0x01021994;

type DeadlineOptions = Readonly<{ signal?: AbortSignal; deadlineAt?: number }>;
export type GuestProxyMaterial = Readonly<{ ca: Buffer; config: Buffer; assertCurrent(): void }>;
type ExecOptions = Readonly<{ signal?: AbortSignal; deadlineAt?: number }>;
type Exec = (args: readonly string[], options?: ExecOptions) => Promise<{ status: number; stdout: string }>;

const abortSignalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get as
  | ((this: AbortSignal) => boolean)
  | undefined;

export type EnvoyEgressSeams = Readonly<{
  docker?: Exec;
  runVersion?: (path: string, options?: DeadlineOptions) => Promise<string>;
  startManager?: typeof startCogsEgressRuntimeManager;
  relay?: () => KvmRelay;
  validateTmpfs?: (root: string) => Promise<void>;
  proveClosed?: (port: number) => Promise<void>;
}>;

export type EnvoyBinaryDescriptor = Readonly<{
  path: string;
  sha256: string;
  image: typeof ENVOY_IMAGE;
  cleanup: "owned";
}>;

type S309PendingReason =
  | "relay-zero-wal-zero"
  | "relay-zero-wal-pass"
  | "relay-one-wal-zero"
  | "relay-one-wal-pass"
  | "wal";

export type S309CompletionProof = Readonly<
  | { version: "cogs.launcher.s3-09-trusted-proof/v1alpha1"; outcome: "pending"; reason: S309PendingReason }
  | {
      version: "cogs.launcher.s3-09-trusted-proof/v1alpha1";
      outcome: "pass";
      runtime_observers_consistent: true;
      completion_observer_consistent: true;
    }
  | { version: "cogs.launcher.s3-09-trusted-proof/v1alpha1"; outcome: "fail"; reason: "generation" | "total-count" }
>;

export type EnvoyEgressHandle = Readonly<{
  snapshot(): Readonly<{
    ready: boolean;
    profile: LauncherProfile;
    listenerPort: number;
    replacementRequired: boolean;
    replacementEvents: number;
    authority: {
      user: "alice";
      modelHandle: typeof MODEL_HANDLE;
      egressHandle: typeof EGRESS_HANDLE;
      pkiMount: "pki";
      pkiRole: "cogs-egress";
    };
    envoy: { image: typeof ENVOY_IMAGE; binarySha256: string };
    completions: { drained: number; classification: "none" | "present" | "replacement-required" };
  }>;
  armS309(): void;
  withGuestProxyMaterial<T>(signal: AbortSignal, consume: (material: GuestProxyMaterial) => Promise<T>): Promise<T>;
  s309CompletionProof(): S309CompletionProof;
  proxyCapability: SecretHolder;
  close(options?: DeadlineOptions): Promise<void>;
}>;

type Options = Readonly<{
  state: LauncherState;
  profile: LauncherProfile;
  openbao: OpenBaoHandle;
  fixturePort: number;
  launchDocument: unknown;
  listenerPort: number;
  otlpLogsEndpoint: string;
  binary?: EnvoyBinaryDescriptor;
  seams?: EnvoyEgressSeams;
  signal?: AbortSignal;
  deadlineAt?: number;
}>;

type DockerInspection = Readonly<{
  id: string;
  name: string;
  image: string;
  label: string;
}>;

type ManagerProofResult = Readonly<{
  clean: boolean;
  failed: boolean;
  closeResolved: boolean;
}>;

export async function prepareEnvoyBinary(
  state: LauncherState,
  optionsOrSeams?: EnvoyEgressSeams | (DeadlineOptions & { seams?: EnvoyEgressSeams }),
  maybeSeams?: EnvoyEgressSeams,
): Promise<EnvoyBinaryDescriptor> {
  let ownerCreated = false;
  let finalCreated = false;
  let extractionUncertain = false;
  try {
    await validateState(state);

    const prepareOptions = capturePrepareOptions(optionsOrSeams, maybeSeams);
    checkCooperative(prepareOptions);
    const capturedSeams = captureSeams(prepareOptions.seams);
    const docker = (args: readonly string[]) =>
      runDocker(capturedSeams.docker ?? defaultDocker(state.dir), args, prepareOptions);
    const stateRuntimeDir = runtimeDir(state);
    const ownerSentinel = ownerPath(state);
    const finalBinaryPath = binaryPath(state);

    await createRuntimeDirectory(state, stateRuntimeDir);
    await writeFile(ownerSentinel, `${state.stateId}\n`, { mode: 0o600, flag: "wx" });
    ownerCreated = true;
    await fsyncPath(ownerSentinel);
    await fsyncPath(stateRuntimeDir);
    await validateOwnerSentinel(state);
    await requireExactEntries(stateRuntimeDir, [".cogs-envoy-owner"]);

    const dockerLabel = `${ENVOY_LABEL_KEY}=${state.stateId}`;
    await proveNoExistingExtractionContainer(docker, dockerLabel);
    await provePinnedImagePresent(docker);

    const containerName = `cogs-envoy-extract-${state.stateId}`;
    const tempBinaryPath = join(stateRuntimeDir, `.envoy.${randomBytes(16).toString("hex")}.tmp`);
    const custodyPath = join(stateRuntimeDir, ".cogs-envoy-extraction.jsonl");
    // Claim before invoking any producer. Incomplete writes/observations are sticky:
    // no caller receives a binary owner until this separate Docker owner retires.
    extractionUncertain = true;
    await writeFile(
      custodyPath,
      `${JSON.stringify({
        version: "cogs.envoy-extraction/v1",
        phase: "create-intent",
        stateId: state.stateId,
        name: containerName,
        label: dockerLabel,
        image: ENVOY_IMAGE,
        tempBinaryPath,
      })}\n`,
      { mode: 0o600, flag: "wx" },
    );
    await fsyncPath(custodyPath);
    await fsyncPath(stateRuntimeDir);
    const record = async (phase: string, id?: string) => {
      const file = await open(custodyPath, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
      try {
        await file.writeFile(`${JSON.stringify({ phase, ...(id === undefined ? {} : { id }) })}\n`);
        await file.sync();
      } finally {
        await file.close();
      }
    };
    // Await actual command work, not a deadline race. A failed/malformed create
    // cannot prove non-acquisition. Its intent remains for exact operator recovery.
    const created = await docker([
      "create",
      "--network",
      "none",
      "--name",
      containerName,
      "--label",
      dockerLabel,
      ENVOY_IMAGE,
    ]);
    const containerId = /^[a-f0-9]{64}\n?$/.test(created.stdout) ? created.stdout.trim() : undefined;
    await record(created.status === 0 && containerId ? "created" : "create-uncertain", containerId);
    if (created.status !== 0 || !containerId) fail();
    // Rollback is independent of the cancelled acquisition observation. Every
    // inspect/rm is joined and targets the immutable full ID, never a name inverse.
    const cleanupDocker = (args: readonly string[]) =>
      runDocker(capturedSeams.docker ?? defaultDocker(state.dir), args);
    let removalStarted = false;
    let extractionRetired = false;
    let localWorkUncertain = false;
    const retireExtraction = async () => {
      removalStarted = true;
      await record("inspect-intent", containerId);
      await proveExtractionContainerIdentity(cleanupDocker, containerName, containerId, state.stateId);
      await record("remove-intent", containerId);
      await requireDockerSuccess(cleanupDocker(["rm", containerId]));
      await record("absence-intent", containerId);
      await proveNoExistingExtractionContainer(cleanupDocker, dockerLabel);
      const remaining = await requireDockerSuccess(
        cleanupDocker(["ps", "-a", "--no-trunc", "--filter", `id=${containerId}`, "--format", "{{.ID}}"]),
      );
      if (remaining.stdout.trim() !== "") fail();
      await record("retired", containerId);
      extractionRetired = true;
    };
    try {
      checkCooperative(prepareOptions);
      await record("inspect-intent", containerId);
      localWorkUncertain = true;
      await proveExtractionContainerIdentity(docker, containerName, containerId, state.stateId);
      localWorkUncertain = false;
      checkCooperative(prepareOptions);
      await requireFinalBinaryAbsent(finalBinaryPath);
      await record("copy-intent", containerId);
      localWorkUncertain = true;
      await requireDockerSuccess(docker(["cp", `${containerId}:/usr/local/bin/envoy`, tempBinaryPath]));
      localWorkUncertain = false;

      const binaryHash = await validateExtractedTempBinary(tempBinaryPath);
      await chmod(tempBinaryPath, 0o500);
      await validateSecureFile(tempBinaryPath, 0o500);
      await fsyncPath(tempBinaryPath);
      await rename(tempBinaryPath, finalBinaryPath);
      finalCreated = true;
      await fsyncPath(stateRuntimeDir);

      const descriptor = Object.freeze({
        path: finalBinaryPath,
        sha256: binaryHash,
        image: ENVOY_IMAGE,
        cleanup: "owned" as const,
      });
      await validateBinary(state, descriptor);

      checkCooperative(prepareOptions);
      await record("version-intent", containerId);
      localWorkUncertain = true;
      const versionOutput = await (capturedSeams.runVersion ?? runEnvoyVersion)(finalBinaryPath, prepareOptions);
      localWorkUncertain = false;
      const versionMatch = versionOutput.match(
        /^\n(.+\/envoy) {2}version: [a-f0-9]{40}\/1\.38\.3\/Clean\/RELEASE\/BoringSSL\n\n$/u,
      );
      if (versionMatch?.[1] !== finalBinaryPath) fail();

      await retireExtraction();
      checkCooperative(prepareOptions);
      await unlink(custodyPath);
      await fsyncPath(stateRuntimeDir);
      extractionUncertain = false;
      return descriptor;
    } catch (error) {
      if (localWorkUncertain) throw error;
      if (!removalStarted) await retireExtraction();
      else if (!extractionRetired) throw error;
      await rm(tempBinaryPath, { force: true });
      await unlink(custodyPath);
      await fsyncPath(stateRuntimeDir);
      extractionUncertain = false;
      throw error;
    }
  } catch {
    if (!extractionUncertain) await cleanupPreparedBinaryAfterFailure(state, ownerCreated, finalCreated);
    throw fail();
  }
}

export async function startEnvoyEgress(rawOptions: Options): Promise<EnvoyEgressHandle> {
  let manager: CogsEgressRuntimeManager | undefined;
  let relay: KvmRelay | undefined;
  let internallyPreparedBinary: EnvoyBinaryDescriptor | undefined;
  let proxyCapability = randomSecret(32);
  let closed = false;
  let drainedCompletions = 0;
  let completionOutcome: S309CompletionProof["outcome"] = "pending";
  let completionPendingReason: S309PendingReason = "relay-zero-wal-zero";
  let completionMatchesSeen = 0;
  let generation: object | undefined;
  let finalValidated = false;
  let armed = false;
  let relayBaseline: ReturnType<KvmRelay["snapshot"]> | undefined;
  let walBaseline = "";
  let matchedIntent: string | undefined;
  let matchedCompletion: string | undefined;
  let publicCa: string | undefined;
  let pkiIssued = false;
  let pkiActive = false;
  let completionFailReason: "generation" | "total-count" = "generation";
  let replacementEvents = 0;
  let capturedSeams: EnvoyEgressSeams = Object.freeze({});
  let capturedState: LauncherState | undefined;

  try {
    const options = captureOptions(rawOptions);
    checkCooperative(options);
    const seams = captureSeams(options.seams);
    capturedSeams = seams;
    capturedState = options.state;

    await validateState(options.state, options.profile);
    await (seams.validateTmpfs ?? validateTmpfs)(EGRESS_TMPFS_ROOT);

    const openbaoSnapshot = options.openbao.snapshot();
    validateOpenBaoAuthority(openbaoSnapshot);

    const launch = validateLaunch(options.launchDocument, options.state, options.fixturePort);
    const s309RouteId = s309CredentialRouteId(launch);
    let binary = options.binary;
    if (!binary) {
      internallyPreparedBinary = await prepareEnvoyBinary(options.state, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        ...(options.deadlineAt === undefined ? {} : { deadlineAt: options.deadlineAt }),
        seams,
      });
      binary = internallyPreparedBinary;
    }
    await validateBinary(options.state, binary);

    const openbaoOrigin = `http://127.0.0.1:${openbaoSnapshot.port}`;
    const openbaoIdentity = createOpenBaoIdentity(options.openbao.egressToken);
    const startManager = seams.startManager ?? startCogsEgressRuntimeManager;
    const managerOptions = createManagerOptions({
      options,
      launch,
      binary,
      openbaoOrigin,
      openbaoIdentity,
      proxyCapability,
      decoratePki: (source) =>
        Object.freeze({
          withPkiMaterial: <T>(
            request: CogsEgressPkiRequest,
            consume: (material: CogsEgressPkiMaterial) => Promise<T>,
          ) => {
            if (
              pkiIssued ||
              closed ||
              request.sessionId !== launch.session_id ||
              request.hosts.join(",") !== "localhost"
            )
              fail();
            pkiIssued = true;
            return source.withPkiMaterial(request, async (material) => {
              if (closed || pkiActive || material.caCertificatePem.length > 65536) fail();
              publicCa = material.caCertificatePem;
              pkiActive = true;
              try {
                return await consume(material);
              } finally {
                pkiActive = false;
                publicCa = undefined;
              }
            });
          },
        }),
      onReplacementRequired: async () => {
        replacementEvents = incrementSaturating(replacementEvents);
      },
    });

    manager = await startManager({
      ...managerOptions,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    checkCooperative(options);
    await validateManagerReady(manager, options.listenerPort, options);

    const proxyCapabilityHolder = secretHolder(
      () => proxyCapability,
      (value) => {
        proxyCapability = value;
      },
    );

    if (options.profile === "linux-kvm") {
      relay = (seams.relay ?? createLinuxKvmRelay)();
      relay.configureProxyCapability(proxyCapabilityHolder);
      await startLinuxKvmRelay(relay, manager.listenerPort, options);
    }
    checkCooperative(options);

    const observation = (retired: boolean) => {
      if (!manager || manager.replacementRequired || replacementEvents !== 0) fail();
      const snap = observeCogsEgressRuntime(manager);
      const a = snap.accounting;
      if (
        snap.generation !== generation ||
        snap.sessionId !== launch.session_id ||
        snap.retired !== retired ||
        a.failed ||
        snap.uncorrelated !== 0 ||
        a.dropped !== 0 ||
        ![a.accepted, a.drained, a.dropped, a.retained].every(
          (n) => Number.isSafeInteger(n) && n >= 0 && n <= 10_000,
        ) ||
        a.accepted !== a.drained + a.dropped + a.retained ||
        a.accepted !== snap.completions.length ||
        snap.records.length > 10_000
      )
        fail();
      return snap;
    };
    const handle: EnvoyEgressHandle = Object.freeze({
      snapshot: () =>
        Object.freeze({
          ready: !closed && manager?.ready === true,
          profile: options.profile,
          listenerPort: relay?.snapshot().bindPort ?? manager?.listenerPort ?? 0,
          replacementRequired: manager?.replacementRequired ?? false,
          replacementEvents,
          authority: {
            user: "alice",
            modelHandle: MODEL_HANDLE,
            egressHandle: EGRESS_HANDLE,
            pkiMount: "pki",
            pkiRole: "cogs-egress",
          } as const,
          envoy: { image: ENVOY_IMAGE, binarySha256: binary.sha256 } as const,
          completions: {
            drained: drainedCompletions,
            classification: completionClassification(manager, drainedCompletions),
          } as const,
        }),
      withGuestProxyMaterial: async (signal, consume) => {
        const ca = publicCa;
        const assertCurrent = () => {
          if (
            aborted(signal) ||
            closed ||
            !pkiActive ||
            !ca ||
            publicCa !== ca ||
            manager?.ready !== true ||
            manager.replacementRequired ||
            replacementEvents !== 0
          )
            fail();
        };
        assertCurrent();
        return await proxyCapabilityHolder.withSecret(async (secret) => {
          if (!/^[A-Za-z0-9_-]{43}$/u.test(secret)) fail();
          const caBytes = Buffer.from(ca as string);
          const config = Buffer.from(`proxy-user = "cogs:${secret}"\n`);
          try {
            const result = await consume(Object.freeze({ ca: caBytes, config, assertCurrent }));
            assertCurrent();
            return result;
          } catch {
            fail();
          } finally {
            caBytes.fill(0);
            config.fill(0);
          }
        });
      },
      armS309: () => {
        try {
          if (
            armed ||
            closed ||
            manager?.ready !== true ||
            manager.replacementRequired ||
            replacementEvents !== 0 ||
            !relay
          )
            fail();
          armed = true;
          relayBaseline = relay.snapshot();
          generation = observeCogsEgressRuntime(manager).generation;
          const initial = observation(false);
          const records = initial.records;
          if (initial.accounting.accepted !== 0) fail();
          // This launcher owns a dedicated generation, never a reused traffic prefix.
          if (
            records?.length !== 0 ||
            relayProof(relay, manager.listenerPort) !== "relay-zero" ||
            relayBaseline.activeSockets !== 0 ||
            manager.drainCompletions(64).length !== 0
          )
            fail();
          walBaseline = JSON.stringify(records);
        } catch {
          completionOutcome = "fail";
          fail();
        }
      },
      s309CompletionProof: () => {
        if (closed) {
          return Object.freeze({
            version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
            ...(finalValidated && completionOutcome === "pass"
              ? { outcome: "pass", runtime_observers_consistent: true, completion_observer_consistent: true }
              : { outcome: "fail", reason: "generation" }),
          }) as S309CompletionProof;
        }
        if (completionOutcome !== "fail") {
          try {
            if (
              !armed ||
              closed ||
              manager?.ready !== true ||
              manager.replacementRequired ||
              replacementEvents !== 0 ||
              !relayBaseline ||
              relay?.snapshot().switchedTargets !== relayBaseline.switchedTargets
            )
              throw new Error("bad state");
            const relayState = relayProof(relay, manager.listenerPort);
            const current = observation(false);
            const records = current.records;
            if (walBaseline !== "[]" || records === undefined) throw new Error("missing WAL");
            const walState = walProof(records, s309RouteId, launch.session_id);
            const record = walState === "pass" ? records[0] : undefined;
            const drained = manager.drainCompletions(64);
            drainedCompletions = addSaturating(drainedCompletions, drained.length);
            const matches = current.completions.filter(
              (item) => record !== undefined && completionMatches(item, record),
            ).length;
            if (matchedIntent !== undefined && `[${matchedIntent}]` !== JSON.stringify(records))
              throw new Error("changed intent");
            if (record && matches === 1) {
              matchedIntent = JSON.stringify(record);
              matchedCompletion ??= JSON.stringify(current.completions);
            }
            completionMatchesSeen = matches;
            if (
              relayState === "fail" ||
              walState === "fail" ||
              current.completions.length !== matches ||
              (matchedCompletion !== undefined && JSON.stringify(current.completions) !== matchedCompletion) ||
              completionMatchesSeen > 1
            ) {
              completionOutcome = "fail";
              completionFailReason = "total-count";
            } else if (relayState === "pass" && walState === "pass" && completionMatchesSeen === 1) {
              completionOutcome = "pass";
            } else {
              completionOutcome = "pending";
              completionPendingReason = pendingReason(relayState, walState);
            }
          } catch {
            completionOutcome = "fail";
            completionFailReason = "generation";
          }
        }
        return Object.freeze({
          version: "cogs.launcher.s3-09-trusted-proof/v1alpha1",
          outcome: completionOutcome,
          ...(completionOutcome === "pass"
            ? {
                runtime_observers_consistent: true as const,
                completion_observer_consistent: true as const,
              }
            : {}),
          ...(completionOutcome === "pending" ? { reason: completionPendingReason } : {}),
          ...(completionOutcome === "fail" ? { reason: completionFailReason } : {}),
        }) as S309CompletionProof;
      },
      proxyCapability: proxyCapabilityHolder,
      close: once(
        async (closeOptions = Object.freeze({})) => {
          const cleanup = cleanupOptions(closeOptions);
          let failed = false;
          if (armed && completionOutcome === "pass") {
            try {
              if (
                JSON.stringify(observation(false).records) !== `[${matchedIntent}]` ||
                relayProof(relay, manager?.listenerPort ?? 0) !== "pass" ||
                relay?.snapshot().switchedTargets !== relayBaseline?.switchedTargets
              )
                failed = true;
            } catch {
              failed = true;
            }
          }
          closed = true;
          let managerClean = false;

          try {
            if (relay) {
              await relay.clear();
            }
          } catch {
            failed = true;
          }

          if (manager) {
            const closeProof = await closeManagerAndProveCleanup(manager, seams, cleanup);
            failed = failed || closeProof.failed;
            managerClean = closeProof.clean;

            if (closeProof.closeResolved) {
              try {
                if (armed) {
                  const final = observation(true);
                  const record = final.records[0];
                  if (
                    completionOutcome !== "pass" ||
                    JSON.stringify(final.records) !== `[${matchedIntent}]` ||
                    walProof(final.records, s309RouteId, launch.session_id) !== "pass" ||
                    final.completions.length !== 1 ||
                    JSON.stringify(final.completions) !== matchedCompletion ||
                    !record ||
                    !completionMatches(final.completions[0] as CogsEgressCompletion, record)
                  )
                    failed = true;
                } else {
                  drainedCompletions = addSaturating(drainedCompletions, manager.drainCompletions(64).length);
                }
              } catch {
                failed = true;
              }
            }
          }

          try {
            if (relay) {
              await relay.close();
            }
          } catch {
            failed = true;
          } finally {
            proxyCapability = "";
          }

          if (managerClean) {
            try {
              await cleanupEnvoyBinary(options.state, binary);
            } catch {
              failed = true;
            }
          }

          if (armed) {
            const end = relay?.snapshot();
            if (
              !end?.closed ||
              end.poisoned ||
              end.activeSockets !== 0 ||
              end.activeTarget !== null ||
              end.registeredTargets.length !== 0 ||
              end.acceptedConnections !== 2 ||
              end.deniedConnections !== 0 ||
              end.switchedTargets !== relayBaseline?.switchedTargets ||
              completionOutcome !== "pass"
            )
              failed = true;
          }
          if (failed) fail();
          finalValidated = armed;
        },
        () => {
          closed = true;
        },
        () => {
          if (armed) completionOutcome = "fail";
        },
      ),
    });
    return registerCloseOwner(handle, () => beginRegisteredClose(handle.close));
  } catch (startupError) {
    const cleanup = cleanupOptions();
    let failed = false;
    try {
      try {
        await closeRelayAfterStartupFailure(relay);
      } catch {
        failed = true;
      }

      const managerClean = await closeManagerAfterStartupFailure(manager, startupError, capturedSeams, cleanup).catch(
        () => {
          failed = true;
          return false;
        },
      );
      if (managerClean && internallyPreparedBinary && capturedState) {
        try {
          await cleanupEnvoyBinary(capturedState, internallyPreparedBinary);
        } catch {
          failed = true;
        }
      }
    } finally {
      proxyCapability = "";
    }
    if (failed) throw fail();
    throw fail();
  }
}

export async function cleanupEnvoyBinary(state: LauncherState, binary: EnvoyBinaryDescriptor): Promise<void> {
  try {
    await validateState(state, undefined, true);
    await validateBinary(state, binary);
    await requireExactEntries(runtimeDir(state), [".cogs-envoy-owner", "envoy"]);
    await unlink(binary.path);
    await fsyncPath(runtimeDir(state));
    await unlink(ownerPath(state));
    await fsyncPath(runtimeDir(state));
    await rmdir(runtimeDir(state));
    await fsyncPath(state.dir);
  } catch {
    throw fail();
  }
}

function createManagerOptions(input: {
  options: Options;
  launch: LaunchConfig;
  binary: EnvoyBinaryDescriptor;
  openbaoOrigin: string;
  openbaoIdentity: ReturnType<typeof createOpenBaoIdentity>;
  proxyCapability: string;
  decoratePki: (source: CogsEgressPkiSource) => CogsEgressPkiSource;
  onReplacementRequired: () => Promise<void>;
}): CogsEgressRuntimeManagerOptions {
  return {
    launch: input.launch,
    walPath: join(input.options.state.dir, "egress-audit.wal"),
    listenerPort: input.options.listenerPort,
    maxSessionExpiresAtMs: Date.now() + 60 * 60 * 1000,
    completionCapacity: 64,
    revocation: {
      mode: "openbao",
      openbao: {
        origin: input.openbaoOrigin,
        mount: "model",
        identity: input.openbaoIdentity,
        allowLoopbackHttpDevelopment: true,
      },
    },
    telemetry: {
      mode: "otlp",
      endpoint: otlpEndpoint(input.options.otlpLogsEndpoint, "logs", true),
      allowLoopbackHttpDevelopment: true,
    },
    proxyCapability: input.proxyCapability,
    pkiSource: input.decoratePki(
      new OpenBaoEgressPkiSource({
        origin: input.openbaoOrigin,
        mount: "pki",
        role: "cogs-egress",
        identity: input.openbaoIdentity,
        allowLoopbackHttpDevelopment: true,
      }),
    ),
    envoyProcess: createNodeCogsEnvoyProcessPort({
      executablePath: input.binary.path,
      startupTimeoutMs: 5000,
      closeTimeoutMs: 5000,
    }),
    randomSecret,
    onReplacementRequired: input.onReplacementRequired,
    nowMs: () => Date.now(),
    timers: { setTimeout, clearTimeout },
    revocationPollIntervalMs: 1000,
    revocationMinPkiRemainingMs: 60000,
    operationTimeoutMs: 1000,
  };
}

async function createRuntimeDirectory(state: LauncherState, stateRuntimeDir: string): Promise<void> {
  await mkdir(stateRuntimeDir, { mode: 0o700, recursive: false }).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "EEXIST") {
      throw error;
    }
  });
  await validateSecureDirectory(stateRuntimeDir);
  await fsyncPath(state.dir);
  await requireExactEntries(stateRuntimeDir, []);
}

async function proveNoExistingExtractionContainer(docker: Exec, label: string): Promise<void> {
  const existingContainers = await docker(["ps", "-a", "--filter", `label=${label}`, "--format", "{{.ID}}"]).catch(
    () => ({
      status: 1,
      stdout: "",
    }),
  );
  if (existingContainers.status !== 0 || existingContainers.stdout.trim() !== "") {
    fail();
  }
}

async function provePinnedImagePresent(docker: Exec): Promise<void> {
  const imageInspection = await requireDockerSuccess(
    docker(["image", "inspect", ENVOY_IMAGE, "--format", "{{json .RepoDigests}}"]),
  );
  if (!hasExpectedRepoDigest(imageInspection.stdout)) {
    fail();
  }
}

async function requireFinalBinaryAbsent(finalBinaryPath: string): Promise<void> {
  await lstat(finalBinaryPath).then(
    () => fail(),
    (error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") {
        throw error;
      }
    },
  );
}

async function validateExtractedTempBinary(tempBinaryPath: string): Promise<string> {
  const beforeRead = await validateSecureFile(tempBinaryPath);
  if (beforeRead.size < MIN_ENVOY_BINARY_BYTES || beforeRead.size > MAX_ENVOY_BINARY_BYTES) {
    fail();
  }

  const bytes = await readFile(tempBinaryPath);
  const afterRead = await validateSecureFile(tempBinaryPath);
  if (afterRead.dev !== beforeRead.dev || afterRead.ino !== beforeRead.ino || afterRead.size !== beforeRead.size) {
    fail();
  }

  const hash = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  if (!SHA256_PATTERN.test(hash)) {
    fail();
  }
  return hash;
}

async function proveExtractionContainerIdentity(
  docker: Exec,
  containerName: string,
  containerId: string,
  stateId: string,
): Promise<void> {
  const metadata = await inspectContainer(docker, containerId);
  if (
    metadata.id !== containerId ||
    metadata.name !== `/${containerName}` ||
    metadata.image !== ENVOY_IMAGE ||
    metadata.label !== stateId
  ) {
    fail();
  }
}

async function cleanupPreparedBinaryAfterFailure(
  state: LauncherState,
  ownerCreated: boolean,
  finalCreated: boolean,
): Promise<void> {
  if (!ownerCreated) return;
  const dir = runtimeDir(state);
  await validateOwnerSentinel(state);
  const entries = await readdir(dir);
  if (finalCreated) {
    if (entries.length !== 2 || !entries.includes(".cogs-envoy-owner") || !entries.includes("envoy")) fail();
    await unlink(binaryPath(state));
  } else if (entries.length !== 1 || entries[0] !== ".cogs-envoy-owner") fail();
  await unlink(ownerPath(state));
  await rmdir(dir);
  await fsyncPath(state.dir);
}

function validateOpenBaoAuthority(snapshot: ReturnType<OpenBaoHandle["snapshot"]>): void {
  if (
    !snapshot.ready ||
    !Number.isSafeInteger(snapshot.port) ||
    snapshot.port < 1 ||
    snapshot.port > 65535 ||
    snapshot.egress.mount !== "model" ||
    snapshot.egress.credentialHandle !== EGRESS_HANDLE ||
    snapshot.egress.pkiMount !== "pki" ||
    snapshot.egress.pkiRole !== "cogs-egress"
  ) {
    fail();
  }
}

async function validateManagerReady(
  manager: CogsEgressRuntimeManager,
  expectedListenerPort: number,
  options: DeadlineOptions,
): Promise<void> {
  checkCooperative(options);
  if (manager.ready === true && manager.listenerPort === expectedListenerPort) return;
  await manager.close(cleanupOptions()).catch(() => undefined);
  fail();
}

async function startLinuxKvmRelay(relay: KvmRelay, listenerPort: number, options: DeadlineOptions): Promise<void> {
  checkCooperative(options);
  const cooperative = Object.freeze({
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...(options.deadlineAt === undefined ? {} : { deadlineAt: options.deadlineAt }),
  });
  await relay.start(cooperative);
  checkCooperative(options);
  relay.registerTarget(listenerPort);
  await relay.switchTo(listenerPort, cooperative);
  checkCooperative(options);
}

function relayProof(relay: KvmRelay | undefined, target: number): "relay-zero" | "relay-one" | "pass" | "fail" {
  if (!relay) return "relay-zero";
  const snap = relay.snapshot();
  if (
    snap.profile !== "linux-kvm" ||
    snap.bindHost !== "192.0.2.1" ||
    snap.bindPort !== 18080 ||
    !Number.isSafeInteger(snap.switchedTargets) ||
    snap.switchedTargets < 1 ||
    snap.ready !== true ||
    snap.poisoned !== false ||
    snap.closed !== false ||
    snap.activeTarget !== target ||
    snap.registeredTargets.length !== 1 ||
    snap.registeredTargets[0] !== target ||
    snap.deniedConnections !== 0 ||
    !Number.isSafeInteger(snap.acceptedConnections) ||
    snap.acceptedConnections < 0 ||
    snap.acceptedConnections > 2 ||
    snap.activeSockets !== 0
  )
    return "fail";
  return snap.acceptedConnections === 2 ? "pass" : snap.acceptedConnections === 1 ? "relay-one" : "relay-zero";
}

function pendingReason(
  relay: "relay-zero" | "relay-one" | "pass",
  wal: "missing" | "zero" | "pass",
): S309PendingReason {
  if (relay === "pass") return "wal";
  return `${relay}-wal-${wal === "pass" ? "pass" : "zero"}` as S309PendingReason;
}

function walProof(
  records: readonly EgressAuditWalRecord[] | undefined,
  routeId: string,
  sessionId: string,
): "missing" | "zero" | "pass" | "fail" {
  if (records === undefined) return "missing";
  if (records.length === 0) return "zero";
  if (records.length !== 1) return "fail";
  return walRecordMatches(records[0], routeId, sessionId) ? "pass" : "fail";
}

function walRecordMatches(input: EgressAuditWalRecord | undefined, routeId: string, sessionId: string): boolean {
  try {
    if (!input || typeof input !== "object" || Object.getOwnPropertySymbols(input).length !== 0) fail();
    const desc = Object.getOwnPropertyDescriptors(input);
    if (
      Object.keys(desc).sort().join(",") !==
      "credential_required,integration_id,intent_id,method,route_id,sequence,session_id,timestamp_ms,version"
    )
      fail();
    for (const d of Object.values(desc)) if (!d || !("value" in d) || d.enumerable !== true) fail();
    return (
      desc.version?.value === "cogs.egress-intent/v1alpha1" &&
      desc.session_id?.value === sessionId &&
      desc.integration_id?.value === INTEGRATION_ID &&
      desc.route_id?.value === routeId &&
      desc.method?.value === "GET" &&
      desc.credential_required?.value === true &&
      desc.sequence?.value === 0 &&
      typeof desc.intent_id?.value === "string" &&
      /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(desc.intent_id.value) &&
      Number.isSafeInteger(desc.timestamp_ms?.value) &&
      typeof desc.timestamp_ms?.value === "number" &&
      desc.timestamp_ms.value >= 0
    );
  } catch {
    return false;
  }
}

function completionMatches(input: CogsEgressCompletion, record: EgressAuditWalRecord): boolean {
  try {
    if (!input || typeof input !== "object" || Object.getOwnPropertySymbols(input).length !== 0) fail();
    const desc = Object.getOwnPropertyDescriptors(input);
    if (Object.keys(desc).sort().join(",") !== "completedAtMs,durationMs,intentId,responseCode,routeId,sequence")
      fail();
    for (const d of Object.values(desc)) if (!d || !("value" in d) || d.enumerable !== true) fail();
    return (
      desc.routeId?.value === record.route_id &&
      desc.responseCode?.value === 200 &&
      desc.intentId?.value === record.intent_id &&
      desc.sequence?.value === record.sequence &&
      Number.isSafeInteger(desc.durationMs?.value) &&
      typeof desc.durationMs?.value === "number" &&
      desc.durationMs.value >= 0 &&
      desc.durationMs.value <= 86_400_000 &&
      Number.isSafeInteger(desc.completedAtMs?.value) &&
      typeof desc.completedAtMs?.value === "number" &&
      desc.completedAtMs.value >= record.timestamp_ms
    );
  } catch {
    return false;
  }
}

function s309CredentialRouteId(launch: LaunchConfig): string {
  try {
    const routes = lowerLaunchEgressRoutePlan(launch).integrations.flatMap((integration) => integration.routes);
    const matches = routes.filter(
      (route) =>
        route.integrationId === INTEGRATION_ID &&
        route.ruleName === "credential" &&
        route.method === "GET" &&
        route.pathPattern === "/credential" &&
        route.credentialRequired === true,
    );
    if (matches.length !== 1) fail();
    return matches[0]?.routeId ?? fail();
  } catch {
    fail();
  }
}

function completionClassification(
  manager: CogsEgressRuntimeManager | undefined,
  drainedCompletions: number,
): "none" | "present" | "replacement-required" {
  if (manager?.replacementRequired) {
    return "replacement-required";
  }
  return drainedCompletions > 0 ? "present" : "none";
}

async function closeManagerAndProveCleanup(
  manager: CogsEgressRuntimeManager,
  seams: EnvoyEgressSeams,
  options: DeadlineOptions,
): Promise<ManagerProofResult> {
  let failed = false;

  try {
    void options;
    await joinCloseWork(beginRegisteredClose(manager));
  } catch {
    return { clean: false, failed: true, closeResolved: false };
  }

  let listenerClosed = false;
  try {
    await (seams.proveClosed ?? proveClosed)(manager.listenerPort);
    listenerClosed = true;
  } catch {
    failed = true;
  }

  let tmpfsClean = false;
  try {
    await (seams.validateTmpfs ?? validateTmpfs)(EGRESS_TMPFS_ROOT);
    tmpfsClean = true;
  } catch {
    failed = true;
  }

  return { clean: listenerClosed && tmpfsClean, failed, closeResolved: true };
}

async function closeRelayAfterStartupFailure(relay: KvmRelay | undefined): Promise<void> {
  if (relay) await relay.close();
}

async function closeManagerAfterStartupFailure(
  manager: CogsEgressRuntimeManager | undefined,
  startupError: unknown,
  seams: EnvoyEgressSeams,
  options: DeadlineOptions,
): Promise<boolean> {
  if (!manager) {
    const retirement = failedCogsEgressRuntimeManagerRetirement(startupError);
    if (retirement === undefined) return true;
    await retirement;
    try {
      await (seams.validateTmpfs ?? validateTmpfs)(EGRESS_TMPFS_ROOT);
      return true;
    } catch {
      return false;
    }
  }

  try {
    void options;
    await joinCloseWork(beginRegisteredClose(manager));
  } catch {
    return false;
  }

  let listenerClosed = false;
  try {
    await (seams.proveClosed ?? proveClosed)(manager.listenerPort);
    listenerClosed = true;
  } catch {}

  let tmpfsClean = false;
  try {
    await (seams.validateTmpfs ?? validateTmpfs)(EGRESS_TMPFS_ROOT);
    tmpfsClean = true;
  } catch {}

  return listenerClosed && tmpfsClean;
}

function captureOptions(input: Options): Options {
  if (!input || typeof input !== "object" || Object.getPrototypeOf(input) !== Object.prototype) {
    fail();
  }

  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Reflect.ownKeys(descriptors);
  const requiredKeys = [
    "fixturePort",
    "launchDocument",
    "listenerPort",
    "openbao",
    "otlpLogsEndpoint",
    "profile",
    "state",
  ];
  const allowedKeys = [...requiredKeys, "binary", "deadlineAt", "seams", "signal"];

  if (keys.some((key) => typeof key !== "string" || !allowedKeys.includes(key))) {
    fail();
  }
  if (requiredKeys.some((key) => !Object.hasOwn(descriptors, key))) {
    fail();
  }

  for (const key of keys as string[]) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) {
      fail();
    }
  }

  const values = Object.fromEntries((keys as string[]).map((key) => [key, descriptors[key]?.value])) as Options;
  if (!Object.isFrozen(values.state) || !Object.isFrozen(values.openbao)) {
    fail();
  }

  const profile = values.profile;
  if (profile !== "insecure-container" && profile !== "linux-kvm") {
    fail();
  }

  if (!validPort(values.fixturePort) || !validPort(values.listenerPort)) {
    fail();
  }
  validateCooperativeFields(values);

  try {
    otlpEndpoint(values.otlpLogsEndpoint, "logs", true);
  } catch {
    fail();
  }

  let launchDocument: unknown;
  try {
    launchDocument = structuredClone(values.launchDocument);
  } catch {
    fail();
  }

  return Object.freeze({
    state: values.state,
    profile,
    openbao: values.openbao,
    fixturePort: values.fixturePort,
    launchDocument,
    listenerPort: values.listenerPort,
    otlpLogsEndpoint: values.otlpLogsEndpoint,
    ...(values.binary === undefined ? {} : { binary: captureBinary(values.binary) }),
    ...(values.seams === undefined ? {} : { seams: captureSeams(values.seams) }),
    ...(values.signal === undefined ? {} : { signal: values.signal }),
    ...(values.deadlineAt === undefined ? {} : { deadlineAt: values.deadlineAt }),
  });
}

function validateLaunch(document: unknown, state: LauncherState, fixturePort: number): LaunchConfig {
  const launch = validateLaunchConfig(document);
  if (
    launch.user_id !== USER_ID ||
    launch.session_id !== `launcher-${state.stateId}` ||
    launch.model.provider !== MODEL_PROVIDER ||
    launch.model.id !== MODEL_ID ||
    launch.model.credential_handle !== MODEL_HANDLE ||
    launch.integrations.length !== 1
  ) {
    fail();
  }

  const integration = launch.integrations[0] as {
    id?: unknown;
    version?: unknown;
    dns?: { mode?: unknown; guest_resolution?: unknown };
    auth?: { type?: unknown; header?: unknown; prefix?: unknown; placeholder?: unknown; secret_handle?: unknown };
    rules?: unknown[];
  };

  if (
    integration.version !== "cogs.integration/v1alpha1" ||
    integration.id !== "stage3-localhost" ||
    integration.dns?.mode !== "proxy-connect-authority" ||
    integration.dns.guest_resolution !== false ||
    integration.auth?.type !== "bearer_header" ||
    integration.auth.header !== "Authorization" ||
    integration.auth.prefix !== "Bearer " ||
    integration.auth.placeholder !== "COGS_PLACEHOLDER_TOKEN" ||
    integration.auth.secret_handle !== EGRESS_HANDLE ||
    !Array.isArray(integration.rules) ||
    integration.rules.length !== 1
  ) {
    fail();
  }

  const rule = integration.rules[0] as {
    name?: unknown;
    host?: unknown;
    port?: unknown;
    methods?: unknown;
    path_patterns?: unknown;
    path_policy?: { strategy?: unknown; normalization?: unknown };
    query_policy?: { mode?: unknown };
    redirects?: { mode?: unknown; max_hops?: unknown; allowed_hosts?: unknown };
    inject_auth?: unknown;
  };

  if (
    rule.name !== "credential" ||
    rule.host !== "localhost" ||
    rule.port !== fixturePort ||
    JSON.stringify(rule.methods) !== '["GET","POST"]' ||
    JSON.stringify(rule.path_patterns) !== '["/credential"]' ||
    rule.path_policy?.strategy !== "exact" ||
    rule.path_policy.normalization !== "reject-ambiguous" ||
    rule.query_policy?.mode !== "deny" ||
    rule.redirects?.mode !== "deny" ||
    rule.redirects.max_hops !== 0 ||
    JSON.stringify(rule.redirects.allowed_hosts) !== "[]" ||
    rule.inject_auth !== true
  ) {
    fail();
  }

  return launch;
}

async function validateState(state: LauncherState, profile?: LauncherProfile, allowWorkerReady = false): Promise<void> {
  const manifest = await readManifest(state);
  const phaseOk = manifest.phase === "sandbox-ready" || (allowWorkerReady && manifest.phase === "worker-ready");
  if (
    !phaseOk ||
    manifest.sourceRevision !== state.sourceRevision ||
    (profile !== undefined && manifest.profile !== profile)
  ) {
    fail();
  }
}

async function validateBinary(state: LauncherState, binary: EnvoyBinaryDescriptor): Promise<void> {
  if (
    !binary ||
    binary.path !== binaryPath(state) ||
    binary.image !== ENVOY_IMAGE ||
    binary.cleanup !== "owned" ||
    !SHA256_PATTERN.test(binary.sha256)
  ) {
    fail();
  }

  await validateOwnerSentinel(state);
  const beforeRead = await validateSecureFile(binary.path, 0o500);
  if (beforeRead.size < MIN_ENVOY_BINARY_BYTES || beforeRead.size > MAX_ENVOY_BINARY_BYTES) {
    fail();
  }

  const bytes = await readFile(binary.path);
  const afterRead = await validateSecureFile(binary.path, 0o500);
  const actualHash = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  if (
    afterRead.dev !== beforeRead.dev ||
    afterRead.ino !== beforeRead.ino ||
    afterRead.size !== beforeRead.size ||
    actualHash !== binary.sha256
  ) {
    fail();
  }
}

async function validateOwnerSentinel(state: LauncherState): Promise<void> {
  const sentinelPath = ownerPath(state);
  const sentinel = await lstat(sentinelPath);
  if (
    !sentinel.isFile() ||
    sentinel.isSymbolicLink() ||
    sentinel.nlink !== 1 ||
    (sentinel.mode & 0o777) !== 0o600 ||
    (typeof process.geteuid === "function" && sentinel.uid !== process.geteuid()) ||
    (await realpath(sentinelPath)) !== sentinelPath ||
    (await readFile(sentinelPath, "utf8")) !== `${state.stateId}\n`
  ) {
    fail();
  }
}

async function validateTmpfs(root: string): Promise<void> {
  const rootStats = await lstat(root);
  const filesystemStats = await statfs(root);
  if (
    root !== EGRESS_TMPFS_ROOT ||
    !rootStats.isDirectory() ||
    rootStats.isSymbolicLink() ||
    (rootStats.mode & 0o777) !== 0o700 ||
    (typeof process.geteuid === "function" && rootStats.uid !== process.geteuid()) ||
    (await realpath(root)) !== root ||
    (await readdir(root)).length !== 0 ||
    filesystemStats.type !== LINUX_TMPFS_MAGIC
  ) {
    fail();
  }
}

async function validateSecureDirectory(path: string): Promise<void> {
  const stats = await lstat(path);
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (stats.mode & 0o777) !== 0o700 ||
    (typeof process.geteuid === "function" && stats.uid !== process.geteuid()) ||
    (await realpath(path)) !== path
  ) {
    fail();
  }
}

async function validateSecureFile(path: string, mode?: number) {
  const stats = await lstat(path);
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (mode !== undefined && (stats.mode & 0o777) !== mode) ||
    (typeof process.geteuid === "function" && stats.uid !== process.geteuid()) ||
    (await realpath(path)) !== path
  ) {
    fail();
  }
  return stats;
}

async function requireExactEntries(dir: string, names: readonly string[]): Promise<void> {
  const actualEntries = (await readdir(dir)).sort();
  const expectedEntries = [...names].sort();
  if (actualEntries.join("\0") !== expectedEntries.join("\0")) {
    fail();
  }
}

function captureBinary(binary: EnvoyBinaryDescriptor): EnvoyBinaryDescriptor {
  if (!binary || typeof binary !== "object" || Object.getPrototypeOf(binary) !== Object.prototype) {
    fail();
  }

  const descriptors = Object.getOwnPropertyDescriptors(binary);
  const keys = Reflect.ownKeys(descriptors);
  const requiredKeys = ["cleanup", "image", "path", "sha256"];
  if (keys.some((key) => typeof key !== "string" || !requiredKeys.includes(key))) {
    fail();
  }
  if (requiredKeys.some((key) => !Object.hasOwn(descriptors, key))) {
    fail();
  }

  for (const key of keys as string[]) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) {
      fail();
    }
  }

  const output = {
    path: descriptors.path?.value,
    sha256: descriptors.sha256?.value,
    image: descriptors.image?.value,
    cleanup: descriptors.cleanup?.value,
  };
  if (
    typeof output.path !== "string" ||
    typeof output.sha256 !== "string" ||
    output.image !== ENVOY_IMAGE ||
    output.cleanup !== "owned"
  ) {
    fail();
  }

  return Object.freeze({
    path: output.path,
    sha256: output.sha256,
    image: output.image,
    cleanup: output.cleanup,
  });
}

function captureSeams(seams?: EnvoyEgressSeams): EnvoyEgressSeams {
  if (seams === undefined) {
    return Object.freeze({});
  }
  if (!Object.isFrozen(seams) || Object.getPrototypeOf(seams) !== Object.prototype) {
    fail();
  }

  const descriptors = Object.getOwnPropertyDescriptors(seams);
  const allowedKeys = ["docker", "proveClosed", "relay", "runVersion", "startManager", "validateTmpfs"];
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string" || !allowedKeys.includes(key))) {
    fail();
  }

  for (const descriptor of Object.values(descriptors)) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      fail();
    }
    if (
      descriptor.value !== undefined &&
      (typeof descriptor.value !== "function" || !Object.isFrozen(descriptor.value))
    ) {
      fail();
    }
  }

  return seams;
}

function runtimeDir(state: LauncherState): string {
  return join(state.dir, "runtime");
}

function ownerPath(state: LauncherState): string {
  return join(runtimeDir(state), ".cogs-envoy-owner");
}

function binaryPath(state: LauncherState): string {
  return join(runtimeDir(state), "envoy");
}

async function fsyncPath(path: string): Promise<void> {
  const file = await open(path, constants.O_RDONLY);
  try {
    await file.sync();
  } finally {
    await file.close();
  }
}

function defaultDocker(cwd: string): Exec {
  return async (args, options) => {
    const result = await runCommand(
      commandDescriptor({
        executable: "/usr/bin/docker",
        args: [...args].slice(1),
        cwd,
        env: { PATH: "/usr/bin:/bin" },
        timeoutMs: remainingMs(options, 30000),
        maxOutputBytes: 8192,
        killGraceMs: 1000,
      }),
      { ...(options?.signal === undefined ? {} : { signal: options.signal }) },
    );
    return { status: result.status === "ok" && !result.cleanupUncertain ? 0 : 1, stdout: result.stdout };
  };
}

async function runEnvoyVersion(path: string, options?: DeadlineOptions): Promise<string> {
  const result = await runCommand(
    commandDescriptor({
      executable: path,
      args: ["--version"],
      cwd: dirname(path),
      env: {},
      timeoutMs: remainingMs(options, 5000),
      maxOutputBytes: 4096,
      killGraceMs: 1000,
    }),
    { ...(options?.signal === undefined ? {} : { signal: options.signal }) },
  );
  if (result.status !== "ok" || result.cleanupUncertain) {
    fail();
  }
  return result.stdout;
}

async function runDocker(
  exec: Exec,
  args: readonly string[],
  options?: ExecOptions,
): Promise<{ status: number; stdout: string }> {
  checkCooperative(options);
  return exec(Object.freeze(["/usr/bin/docker", ...args]), options);
}

async function requireDockerSuccess(
  command: Promise<{ status: number; stdout: string }>,
): Promise<{ status: number; stdout: string }> {
  const result = await command;
  if (result.status !== 0 || result.stdout.length > 8192) {
    fail();
  }
  return result;
}

function parseSingleLine(value: string): string {
  if (!/^[^\n\r]{1,8192}\n?$/u.test(value)) {
    fail();
  }
  return value.trim();
}

function hasExpectedRepoDigest(value: string): boolean {
  const repoDigests = JSON.parse(parseSingleLine(value));
  return Array.isArray(repoDigests) && repoDigests.includes(`envoyproxy/envoy@${ENVOY_IMAGE_DIGEST}`);
}

async function inspectContainer(exec: Exec, name: string): Promise<DockerInspection> {
  const inspection = JSON.parse(
    parseSingleLine((await requireDockerSuccess(exec(["inspect", name, "--format", "{{json .}}"]))).stdout),
  ) as {
    Id?: string;
    Name?: string;
    Config?: { Image?: string; Labels?: Record<string, string> };
  };

  return {
    id: inspection.Id ?? "",
    name: inspection.Name ?? "",
    image: inspection.Config?.Image ?? "",
    label: inspection.Config?.Labels?.[ENVOY_LABEL_KEY] ?? "",
  };
}

function createOpenBaoIdentity(holder: SecretHolder) {
  return Object.freeze({
    withToken: async <T>(signal: AbortSignal, operation: (token: string) => Promise<T>) => {
      if (signal.aborted) {
        fail();
      }
      return await holder.withSecret((secret) => operation(secret));
    },
  });
}

function secretHolder(get: () => string, set: (value: string) => void): SecretHolder {
  return Object.freeze({
    withSecret: Object.freeze(<T>(operation: (secret: string) => T) => {
      const secret = get();
      if (!secret) {
        fail();
      }
      return operation(secret);
    }),
    dispose: Object.freeze(() => set("")),
  });
}

function randomSecret(bytes: number): string {
  if (!Number.isSafeInteger(bytes) || bytes < 16 || bytes > 128) {
    fail();
  }
  return randomBytes(bytes).toString("base64url");
}

function incrementSaturating(value: number): number {
  if (Number.isSafeInteger(value) && value < Number.MAX_SAFE_INTEGER) {
    return value + 1;
  }
  return Number.MAX_SAFE_INTEGER;
}

function addSaturating(left: number, right: number): number {
  if (
    Number.isSafeInteger(left) &&
    Number.isSafeInteger(right) &&
    right >= 0 &&
    left <= Number.MAX_SAFE_INTEGER - right
  ) {
    return left + right;
  }
  return Number.MAX_SAFE_INTEGER;
}

function validPort(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 1 && value <= 65535;
}

async function proveClosed(port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const socket = new Socket();
    const timer = setTimeout(() => {
      socket.destroy();
      reject(fail());
    }, 500);

    socket.once("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      reject(fail());
    });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      error.code === "ECONNREFUSED" ? resolve() : reject(new Error("launcher egress failed"));
    });
    socket.connect(port, "127.0.0.1");
  });
}

function once(
  fn: (options?: DeadlineOptions) => Promise<void>,
  seal: () => void,
  onFailure: () => void,
): (options?: DeadlineOptions) => Promise<void> {
  const owner = createCloseOwner(() => Promise.resolve().then(() => fn()), seal);
  return registerCloseOwner((options: DeadlineOptions = Object.freeze({})) => {
    validateDeadlineOptions(options);
    return observeLauncherClose(joinCloseWork(owner()), options).catch(() => {
      onFailure();
      fail();
    });
  }, owner);
}

// Module-local observers: cancellation/deadlines never discard or repeat actual work.
export function observeLauncherClose(work: Promise<void>, options: DeadlineOptions = {}): Promise<void> {
  validateDeadlineOptions(options);
  return observeClose({ done: work, retired: work }, closeObservationContext(options, 15_000)).catch(() => fail());
}

function validateDeadlineOptions(options: unknown): asserts options is DeadlineOptions {
  if (!options || typeof options !== "object" || Object.getPrototypeOf(options) !== Object.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(options);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string" || !["deadlineAt", "signal"].includes(key)))
    fail();
  validateCooperativeFields(options);
}

function validateCooperativeFields(options: unknown): void {
  if (!options || typeof options !== "object" || Object.getPrototypeOf(options) !== Object.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(options);
  for (const key of ["signal", "deadlineAt"] as const) {
    const descriptor = descriptors[key];
    if (!descriptor) continue;
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
  }
  if (descriptors.signal?.value !== undefined && !(descriptors.signal.value instanceof AbortSignal)) fail();
  const deadlineAt = descriptors.deadlineAt?.value;
  if (deadlineAt !== undefined && (!Number.isSafeInteger(deadlineAt) || deadlineAt > Date.now() + 60_000)) fail();
}

function capturePrepareOptions(
  optionsOrSeams?: EnvoyEgressSeams | (DeadlineOptions & { seams?: EnvoyEgressSeams }),
  maybeSeams?: EnvoyEgressSeams,
): DeadlineOptions & { seams?: EnvoyEgressSeams } {
  if (maybeSeams !== undefined) {
    const source = optionsOrSeams ?? {};
    validateDeadlineOptions(source);
    const descriptors = Object.getOwnPropertyDescriptors(source);
    const signal = descriptors.signal?.value;
    const deadlineAt = descriptors.deadlineAt?.value;
    return Object.freeze({
      ...(signal === undefined ? {} : { signal }),
      ...(deadlineAt === undefined ? {} : { deadlineAt }),
      seams: maybeSeams,
    });
  }
  if (optionsOrSeams === undefined) return Object.freeze({});
  const descriptors = Object.getOwnPropertyDescriptors(optionsOrSeams);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.includes("signal") || keys.includes("deadlineAt") || keys.includes("seams")) {
    if (keys.some((key) => typeof key !== "string" || !["deadlineAt", "seams", "signal"].includes(key))) fail();
    for (const descriptor of Object.values(descriptors)) {
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    }
    validateCooperativeFields(optionsOrSeams);
    const signal = descriptors.signal?.value;
    const deadlineAt = descriptors.deadlineAt?.value;
    const seams = descriptors.seams?.value;
    return Object.freeze({
      ...(signal === undefined ? {} : { signal }),
      ...(deadlineAt === undefined ? {} : { deadlineAt }),
      ...(seams === undefined ? {} : { seams }),
    });
  }
  return Object.freeze({ seams: optionsOrSeams as EnvoyEgressSeams });
}

function cleanupOptions(options: DeadlineOptions = Object.freeze({})): DeadlineOptions {
  validateDeadlineOptions(options);
  return Object.freeze({ deadlineAt: Date.now() + 15_000 });
}

function checkCooperative(options?: DeadlineOptions): void {
  if (aborted(options?.signal) || (options?.deadlineAt !== undefined && Date.now() >= options.deadlineAt)) fail();
}

function remainingMs(options: DeadlineOptions | undefined, cap: number): number {
  const remaining = options?.deadlineAt === undefined ? cap : Math.min(cap, options.deadlineAt - Date.now());
  if (!Number.isSafeInteger(remaining) || remaining < 1) fail();
  return remaining;
}

function aborted(signal: AbortSignal | undefined): boolean {
  if (!signal) return false;
  try {
    return abortSignalAborted?.call(signal) === true;
  } catch {
    return true;
  }
}

function fail(): never {
  throw new Error("launcher egress failed");
}

export { ENVOY_IMAGE };

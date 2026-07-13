import type { FaultInjector, FaultState } from "../fault-injector/server.ts";
import type { Stage1CaseDefinition } from "./stage-1.ts";

const noFaults: FaultState = Object.freeze({
  authorizationOutage: false,
  auditUnwritable: false,
  auditFull: false,
  completionFailure: false,
  telemetryOutage: false,
  delayMs: 0,
});

export interface PreparedCase {
  capability: string;
  includeCredentialRoute: boolean;
  probeExpected: "allow" | "deny" | "normalize";
}

export function prepareStage1Case(
  test: Stage1CaseDefinition,
  injector: FaultInjector,
  currentCapability: string,
  wrongCapability: string,
  replacementCapability: string,
): PreparedCase {
  injector.setFaults(noFaults);
  injector.rotateCapability(currentCapability);
  const scenario = test.probe.scenario;
  if (scenario === "audit-unwritable") injector.setFaults({ auditUnwritable: true });
  if (scenario === "audit-full") injector.setFaults({ auditFull: true });
  if (scenario === "authorization-outage") injector.setFaults({ authorizationOutage: true });
  if (scenario === "telemetry-outage") injector.setFaults({ telemetryOutage: true });
  if (
    scenario === "secret-revoked" ||
    scenario === "deny-new" ||
    scenario === "direct-store-change" ||
    scenario === "old-capability-invalid"
  )
    injector.denyNew();
  if (scenario === "replacement-capability") injector.rotateCapability(replacementCapability);

  const wrong = new Set(["capability-malformed", "capability-expired", "capability-other-session"]);
  const capability =
    scenario === "replacement-capability"
      ? replacementCapability
      : wrong.has(scenario)
        ? wrongCapability
        : currentCapability;
  return Object.freeze({
    capability,
    includeCredentialRoute: scenario !== "secret-absent",
    probeExpected:
      test.probe.expected === "allow" || test.probe.expected === "normalize"
        ? test.probe.expected
        : test.probe.expected === "redacted"
          ? "allow"
          : "deny",
  });
}

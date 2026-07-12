export type SecurityResult = "pass" | "fail" | "stubbed" | "not-applicable" | "skipped-with-approved-reason";
export type SecurityDependencyMode = "real" | "stubbed" | "not-applicable";

export interface SecurityResultSemanticsInput {
  result: SecurityResult;
  release_eligible: boolean;
  dependency_modes: Record<string, SecurityDependencyMode>;
}

/** Cross-field result rules shared by report producers and standalone validation. */
export function validateSecurityResultSemantics(test: SecurityResultSemanticsInput): string[] {
  const errors: string[] = [];
  const modes = Object.values(test.dependency_modes);
  const hasStub = modes.includes("stubbed");
  if (hasStub && test.result === "pass") {
    errors.push("a passing test with a stubbed dependency requires result=stubbed");
  }
  if (test.result === "stubbed" && !hasStub) {
    errors.push("result=stubbed requires a declared stubbed dependency");
  }
  if (test.release_eligible && test.result !== "pass") {
    errors.push("release eligibility requires result=pass");
  }
  if (test.release_eligible && modes.some((mode) => mode !== "real")) {
    errors.push("release-eligible test dependencies must all be real");
  }
  return errors;
}

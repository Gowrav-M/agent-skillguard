import { describe, expect, it } from "vitest";
import { evaluateCapabilityContracts } from "../src/core/contract.js";
import { scanSkillPath } from "../src/core/scanner.js";

describe("capability contracts", () => {
  it("allows skills whose observed behavior stays within declared capabilities", async () => {
    const report = await scanSkillPath("examples/skills/safe-code-reviewer");
    const decision = evaluateCapabilityContracts(report);
    expect(decision.decision).toBe("allow");
    expect(decision.summary.violations).toBe(0);
  });

  it("blocks secret access that is not declared in the skill contract", async () => {
    const report = await scanSkillPath("examples/skills/prompt-injected-skill");
    const decision = evaluateCapabilityContracts(report);
    expect(decision.decision).toBe("block");
    expect(decision.contracts[0]?.undeclaredCapabilities).toContain("secret-access");
    expect(decision.reasons.some((reason) => reason.code === "contract.undeclared.secret-access")).toBe(true);
  });

  it("reports the observed capability surface separately from declared capabilities", async () => {
    const report = await scanSkillPath("examples/skills/dangerous-installer");
    const skill = report.bom.skills[0];
    expect(skill?.manifest.declaredCapabilities).toContain("network");
    expect(skill?.observedCapabilities).toContain("shell");
    expect(skill?.observedCapabilities).toContain("network");
  });
});

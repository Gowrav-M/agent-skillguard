import { describe, expect, it } from "vitest";
import { evaluateAdmission, defaultSkillGuardPolicy } from "../src/core/policy.js";
import { scanSkillPath } from "../src/core/scanner.js";

describe("skill admission policy", () => {
  it("allows a clean read-only skill", async () => {
    const report = await scanSkillPath("examples/skills/safe-code-reviewer");
    const decision = evaluateAdmission(report, defaultSkillGuardPolicy());
    expect(decision.decision).toBe("allow");
    expect(decision.reasons).toHaveLength(0);
  });

  it("blocks critical prompt-injection skills", async () => {
    const report = await scanSkillPath("examples/skills/prompt-injected-skill");
    const decision = evaluateAdmission(report, defaultSkillGuardPolicy());
    expect(decision.decision).toBe("block");
    expect(decision.reasons.some((reason) => reason.code === "finding.skill.prompt_injection")).toBe(true);
  });

  it("blocks denied capabilities even when configured severity would otherwise allow review", async () => {
    const report = await scanSkillPath("examples/skills/mcp-mutating-tool");
    const decision = evaluateAdmission(report, {
      ...defaultSkillGuardPolicy(),
      blockOnSeverity: "critical"
    });
    expect(decision.decision).toBe("block");
    expect(decision.reasons.some((reason) => reason.code === "capability.mcp-tool-mutation")).toBe(true);
  });

  it("can require a clean scan for enterprise mode", async () => {
    const report = await scanSkillPath("examples/skills/hidden-unicode");
    const decision = evaluateAdmission(report, {
      ...defaultSkillGuardPolicy(),
      blockOnSeverity: "critical",
      requireCleanScan: true
    });
    expect(decision.decision).toBe("block");
    expect(decision.reasons.some((reason) => reason.code === "policy.require_clean_scan")).toBe(true);
  });
});

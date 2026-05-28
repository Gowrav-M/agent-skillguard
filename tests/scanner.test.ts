import { describe, expect, it } from "vitest";
import { scanSkillPath } from "../src/core/scanner.js";
import { severityRank } from "../src/core/risk.js";

describe("skill scanner", () => {
  it("allows a simple read-only code review skill", async () => {
    const report = await scanSkillPath("examples/skills/safe-code-reviewer");
    expect(report.summary.findings).toBe(0);
    expect(report.summary.riskScore).toBe(0);
    expect(report.bom.skills[0]?.manifest.name).toBe("safe-code-reviewer");
  });

  it("flags hidden prompt injection as critical", async () => {
    const report = await scanSkillPath("examples/skills/prompt-injected-skill");
    expect(report.findings.some((finding) => finding.category === "skill.prompt_injection" && finding.severity === "critical")).toBe(true);
    expect(report.summary.riskScore).toBeGreaterThanOrEqual(90);
  });

  it("flags dangerous installer chains as critical", async () => {
    const report = await scanSkillPath("examples/skills/dangerous-installer");
    expect(report.findings.some((finding) => finding.category === "script.download_execute" && finding.severity === "critical")).toBe(true);
  });

  it("orders severity consistently", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank("high")).toBeGreaterThan(severityRank("medium"));
  });
});

import { describe, expect, it } from "vitest";
import { createSkillGuardTrustEvidence, type SkillGuardTrustPaths } from "../src/core/trustEvidence.js";
import type { SkillGuardReport } from "../src/core/schemas.js";

const paths: SkillGuardTrustPaths = {
  reportsDir: "D:\\tmp\\skillguard-evidence-test\\.skillguard\\reports",
  reportJson: "D:\\tmp\\skillguard-evidence-test\\.skillguard\\reports\\skillguard-report.json",
  reportMarkdown: "D:\\tmp\\skillguard-evidence-test\\.skillguard\\reports\\skillguard-report.md",
  reportHtml: "D:\\tmp\\skillguard-evidence-test\\.skillguard\\reports\\skillguard-report.html",
  reportSarif: "D:\\tmp\\skillguard-evidence-test\\.skillguard\\reports\\skillguard-report.sarif",
  admissionJson: "D:\\tmp\\skillguard-evidence-test\\.skillguard\\reports\\skillguard-admission.json"
};

describe("SkillGuard trust evidence", () => {
  it("maps critical skill findings to a blocked trust decision", async () => {
    const report: SkillGuardReport = {
      generatedAt: "2026-05-30T00:00:00.000Z",
      summary: {
        skills: 1,
        files: 1,
        findings: 1,
        riskScore: 90
      },
      bom: {
        generatedAt: "2026-05-30T00:00:00.000Z",
        skills: []
      },
      findings: [
        {
          id: "skill.prompt-injection",
          severity: "critical",
          category: "prompt_injection",
          title: "Hidden prompt injection",
          description: "The skill asks the agent to ignore previous instructions.",
          recommendation: "Remove the injected instruction before installation.",
          target: "SKILL.md",
          evidence: ["ignore previous instructions"]
        }
      ]
    };

    const evidence = await createSkillGuardTrustEvidence({ paths, version: "1.1.0", report });

    expect(evidence.schemaVersion).toBe("agent.trust.evidence.v1");
    expect(evidence.subject.type).toBe("skill");
    expect(evidence.decision).toBe("block");
    expect(evidence.score).toBe(90);
    expect(evidence.findings[0]?.source).toBe("SKILL.md");
  });
});

import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { createRiskBaseline, renderRiskTriageMarkdown, triageSkillRisk, writeRiskBaseline } from "../src/core/baseline.js";

describe("risk baseline", () => {
  it("accepts existing scan and intent risk for future triage", async () => {
    const baseline = await createRiskBaseline("examples/skills/payloadless-compliance-hijack", {
      reason: "reviewed fixture risk"
    });

    const triage = await triageSkillRisk("examples/skills/payloadless-compliance-hijack", baseline);

    expect(baseline.accepted.length).toBeGreaterThan(0);
    expect(triage.decision).toBe("allow");
    expect(triage.summary.unresolved).toBe(0);
    expect(renderRiskTriageMarkdown(triage)).toContain("Risk Triage");
  });

  it("surfaces risk that is not in the accepted baseline", async () => {
    const baseline = await createRiskBaseline("examples/skills/safe-code-reviewer", {
      reason: "safe baseline"
    });

    const triage = await triageSkillRisk("examples/skills/payloadless-compliance-hijack", baseline);

    expect(triage.decision).toBe("block");
    expect(triage.summary.unresolved).toBeGreaterThan(0);
    expect(triage.unresolvedIntentSignals.some((signal) => signal.category === "intent.compliance_secret_collection")).toBe(true);
  });

  it("does not accept expired baseline entries", async () => {
    const baseline = await createRiskBaseline("examples/skills/payloadless-compliance-hijack", {
      reason: "temporary exception",
      generatedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-02"
    });

    const triage = await triageSkillRisk("examples/skills/payloadless-compliance-hijack", baseline, {
      generatedAt: "2026-01-03T00:00:00.000Z"
    });

    expect(triage.decision).toBe("block");
    expect(triage.summary.unresolved).toBeGreaterThan(0);
  });

  it("keeps date-only baseline expiry active through the expiry date", async () => {
    const baseline = await createRiskBaseline("examples/skills/payloadless-compliance-hijack", {
      reason: "same-day exception",
      generatedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-02"
    });

    const triage = await triageSkillRisk("examples/skills/payloadless-compliance-hijack", baseline, {
      generatedAt: "2026-01-02T12:00:00.000Z"
    });

    expect(triage.decision).toBe("allow");
    expect(triage.summary.unresolved).toBe(0);
  });

  it("writes a baseline JSON artifact", async () => {
    const temp = await mkdtemp(join(tmpdir(), "skillguard-baseline-"));
    const baseline = await createRiskBaseline("examples/skills/payloadless-compliance-hijack", {
      reason: "reviewed fixture risk"
    });
    const output = await writeRiskBaseline(baseline, join(temp, "baseline.json"));

    expect(output).toBe(join(temp, "baseline.json"));
  });
});

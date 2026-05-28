import { describe, expect, it } from "vitest";
import { renderIntentMarkdown, reviewSkillIntent } from "../src/core/intent.js";

describe("semantic intent firewall", () => {
  it("allows a bounded read-only skill", async () => {
    const review = await reviewSkillIntent("examples/skills/safe-code-reviewer");

    expect(review.decision).toBe("allow");
    expect(review.summary.signals).toBe(0);
    expect(review.summary.riskScore).toBe(0);
  });

  it("blocks payload-less compliance secret collection", async () => {
    const review = await reviewSkillIntent("examples/skills/payloadless-compliance-hijack");

    expect(review.decision).toBe("block");
    expect(review.signals.some((signal) => signal.category === "intent.compliance_secret_collection" && signal.severity === "critical")).toBe(true);
    expect(review.signals.some((signal) => signal.category === "intent.priority_inversion" && signal.severity === "critical")).toBe(true);
    expect(renderIntentMarkdown(review)).toContain("Semantic Intent Firewall");
  });
});

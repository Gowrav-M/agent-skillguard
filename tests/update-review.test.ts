import { describe, expect, it } from "vitest";
import { reviewSkillUpdate } from "../src/core/updateReview.js";

describe("skill update review", () => {
  it("allows identical clean skill updates", async () => {
    const review = await reviewSkillUpdate("examples/skills/safe-code-reviewer", "examples/skills/safe-code-reviewer");
    expect(review.decision).toBe("allow");
    expect(review.summary.addedCapabilities).toEqual([]);
    expect(review.summary.modifiedFiles).toEqual([]);
  });

  it("blocks updates that add dangerous installer behavior", async () => {
    const review = await reviewSkillUpdate("examples/skills/safe-code-reviewer", "examples/skills/dangerous-installer");
    expect(review.decision).toBe("block");
    expect(review.summary.addedCapabilities).toContain("network");
    expect(review.summary.addedCapabilities).toContain("shell");
    expect(review.reasons.some((reason) => reason.code === "update.new_critical_finding")).toBe(true);
  });

  it("flags prompt-only semantic drift in SKILL.md", async () => {
    const review = await reviewSkillUpdate("examples/skills/safe-code-reviewer", "examples/skills/prompt-injected-skill");
    expect(review.decision).toBe("block");
    expect(review.reasons.some((reason) => reason.code === "update.skill_manifest_drift")).toBe(true);
  });
});

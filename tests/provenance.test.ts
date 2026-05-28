import { describe, expect, it } from "vitest";
import { createSkillProvenance, defaultSkillTrustPolicy, evaluateSkillTrust } from "../src/core/provenance.js";

describe("skill provenance firewall", () => {
  it("allows a GitHub skill pinned to an immutable commit", async () => {
    const provenance = await createSkillProvenance("examples/skills/safe-code-reviewer", {
      sourceUri: "https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/safe-code-reviewer",
      sourceCommit: "0123456789abcdef0123456789abcdef01234567",
      publisher: "Gowrav-M"
    });
    const decision = evaluateSkillTrust(provenance, defaultSkillTrustPolicy());
    expect(decision.decision).toBe("allow");
    expect(decision.reasons).toHaveLength(0);
  });

  it("blocks mutable branch sources without a commit pin", async () => {
    const provenance = await createSkillProvenance("examples/skills/safe-code-reviewer", {
      sourceUri: "https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/safe-code-reviewer",
      sourceRef: "main",
      publisher: "Gowrav-M"
    });
    const decision = evaluateSkillTrust(provenance, defaultSkillTrustPolicy());
    expect(decision.decision).toBe("block");
    expect(decision.reasons.some((reason) => reason.code === "provenance.missing_commit_pin")).toBe(true);
  });

  it("blocks unapproved source hosts", async () => {
    const provenance = await createSkillProvenance("examples/skills/safe-code-reviewer", {
      sourceUri: "https://example.net/skills/safe-code-reviewer",
      sourceCommit: "0123456789abcdef0123456789abcdef01234567",
      publisher: "unknown"
    });
    const decision = evaluateSkillTrust(provenance, defaultSkillTrustPolicy());
    expect(decision.decision).toBe("block");
    expect(decision.reasons.some((reason) => reason.code === "provenance.unapproved_host")).toBe(true);
  });

  it("enforces publisher allowlists when configured", async () => {
    const provenance = await createSkillProvenance("examples/skills/safe-code-reviewer", {
      sourceUri: "https://github.com/Gowrav-M/agent-skillguard",
      sourceCommit: "0123456789abcdef0123456789abcdef01234567",
      publisher: "Gowrav-M"
    });
    const decision = evaluateSkillTrust(provenance, {
      ...defaultSkillTrustPolicy(),
      allowedPublishers: ["trusted-org"]
    });
    expect(decision.decision).toBe("block");
    expect(decision.reasons.some((reason) => reason.code === "provenance.unapproved_publisher")).toBe(true);
  });
});

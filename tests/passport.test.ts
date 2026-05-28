import { cp, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { createSkillPassport, renderPassportHtml, renderPassportMarkdown, verifySkillPassport, writePassportArtifacts } from "../src/core/passport.js";
import { skillPassportSchema } from "../src/core/schemas.js";

const source = "https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/safe-code-reviewer";
const commit = "0123456789abcdef0123456789abcdef01234567";

describe("skill passport", () => {
  it("creates an allow passport for a safe pinned skill", async () => {
    const passport = await createSkillPassport("examples/skills/safe-code-reviewer", {
      sourceUri: source,
      sourceCommit: commit,
      publisher: "Gowrav-M"
    });

    expect(skillPassportSchema.parse(passport).decision).toBe("allow");
    expect(passport.embedded.scan.summary.riskScore).toBe(0);
    expect(passport.embedded.trust.decision).toBe("allow");
    expect(passport.embedded.contract.decision).toBe("allow");
    expect(passport.embedded.admission.decision).toBe("allow");
    expect(passport.digests.skillDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(passport.digests.lockDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("blocks a passport for an unpinned mutable source", async () => {
    const passport = await createSkillPassport("examples/skills/safe-code-reviewer", {
      sourceUri: source,
      publisher: "Gowrav-M"
    });

    expect(passport.decision).toBe("block");
    expect(passport.embedded.trust.reasons.some((reason) => reason.code === "provenance.missing_commit_pin")).toBe(true);
  });

  it("blocks a passport for undeclared secret access", async () => {
    const passport = await createSkillPassport("examples/skills/prompt-injected-skill", {
      sourceUri: "https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/prompt-injected-skill",
      sourceCommit: commit,
      publisher: "Gowrav-M"
    });

    expect(passport.decision).toBe("block");
    expect(passport.embedded.contract.decision).toBe("block");
    expect(passport.summary.capabilityViolations).toBeGreaterThan(0);
  });

  it("renders and writes passport artifacts including optional bundle", async () => {
    const temp = await mkdtemp(join(tmpdir(), "skillguard-passport-"));
    const passport = await createSkillPassport("examples/skills/safe-code-reviewer", {
      sourceUri: source,
      sourceCommit: commit,
      publisher: "Gowrav-M",
      pack: true,
      outputDir: temp
    });
    const artifacts = await writePassportArtifacts(passport, temp);

    expect(renderPassportMarkdown(passport)).toContain("Skill Passport");
    expect(renderPassportHtml(passport)).toContain("Skill Passport");
    expect(artifacts.some((artifact) => artifact.endsWith("passport.json"))).toBe(true);
    expect(artifacts.some((artifact) => artifact.endsWith("passport.md"))).toBe(true);
    expect(artifacts.some((artifact) => artifact.endsWith("passport.html"))).toBe(true);
    expect(artifacts.some((artifact) => artifact.endsWith(".skill.tgz"))).toBe(true);
    await expect(readFile(join(temp, "passport.json"), "utf8")).resolves.toContain("safe-code-reviewer");
  });

  it("verifies a passport against the current skill and bundle", async () => {
    const temp = await mkdtemp(join(tmpdir(), "skillguard-passport-verify-"));
    const passport = await createSkillPassport("examples/skills/safe-code-reviewer", {
      sourceUri: source,
      sourceCommit: commit,
      publisher: "Gowrav-M",
      pack: true,
      outputDir: temp
    });
    const artifacts = await writePassportArtifacts(passport, temp);
    const bundlePath = artifacts.find((artifact) => artifact.endsWith(".skill.tgz"));
    expect(bundlePath).toBeDefined();

    const verification = await verifySkillPassport(passport, {
      skillDir: "examples/skills/safe-code-reviewer",
      bundlePath
    });

    expect(verification.valid).toBe(true);
    expect(verification.checked.skillDigest).toBe(true);
    expect(verification.checked.bundleDigest).toBe(true);
  });

  it("fails passport verification when the skill changed after approval", async () => {
    const temp = await mkdtemp(join(tmpdir(), "skillguard-passport-drift-"));
    const skillCopy = join(temp, "safe-code-reviewer");
    await cp("examples/skills/safe-code-reviewer", skillCopy, { recursive: true });
    const passport = await createSkillPassport(skillCopy, {
      sourceUri: source,
      sourceCommit: commit,
      publisher: "Gowrav-M"
    });
    await writeFile(join(skillCopy, "SKILL.md"), "# changed after approval\n", "utf8");

    const verification = await verifySkillPassport(passport, { skillDir: skillCopy });

    expect(verification.valid).toBe(false);
    expect(verification.reasons.some((reason) => reason.code === "passport.skill_digest_mismatch")).toBe(true);
  });
});

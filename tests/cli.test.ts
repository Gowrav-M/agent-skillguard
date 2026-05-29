import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execaNode } from "./helpers.js";
import { describe, expect, it } from "vitest";

describe("CLI", () => {
  it("demo generates local reports", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "skillguard-demo-"));
    const result = await execaNode(["src/cli.ts", "demo"], cwd);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Demo complete");
  });

  it("scan fails when threshold is met", async () => {
    const result = await execaNode(["src/cli.ts", "scan", "examples/skills/prompt-injected-skill", "--fail-on", "critical"], process.cwd());
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("Policy threshold failed");
  });

  it("admit blocks unsafe skills", async () => {
    const result = await execaNode(["src/cli.ts", "admit", "examples/skills/prompt-injected-skill"], process.cwd());
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("Admission blocked");
  });

  it("review-update blocks risky skill upgrades", async () => {
    const result = await execaNode(["src/cli.ts", "review-update", "examples/skills/safe-code-reviewer", "examples/skills/dangerous-installer"], process.cwd());
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("Update blocked");
  });

  it("trust blocks unpinned mutable skill sources", async () => {
    const result = await execaNode(["src/cli.ts", "trust", "examples/skills/safe-code-reviewer", "--source", "https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/safe-code-reviewer"], process.cwd());
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("Trust blocked");
  });

  it("contract blocks undeclared capabilities", async () => {
    const result = await execaNode(["src/cli.ts", "contract", "examples/skills/prompt-injected-skill"], process.cwd());
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("Contract blocked");
  });

  it("intent blocks payload-less semantic hijacking", async () => {
    const result = await execaNode(["src/cli.ts", "intent", "examples/skills/payloadless-compliance-hijack", "--fail-on", "high"], process.cwd());
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain("Intent decision: BLOCK");
    expect(result.stderr).toContain("Intent blocked");
  });

  it("baseline lets triage accept reviewed existing risk", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "skillguard-baseline-cli-"));
    const baseline = await execaNode([
      "src/cli.ts",
      "baseline",
      join(process.cwd(), "examples/skills/payloadless-compliance-hijack"),
      "--reason",
      "reviewed fixture risk"
    ], cwd);
    expect(baseline.exitCode).toBe(0);
    expect(baseline.stdout).toContain("Baseline accepted");

    const triage = await execaNode([
      "src/cli.ts",
      "triage",
      join(process.cwd(), "examples/skills/payloadless-compliance-hijack"),
      "--baseline",
      join(cwd, ".skillguard/baseline.json"),
      "--fail-on",
      "high"
    ], cwd);
    expect(triage.exitCode).toBe(0);
    expect(triage.stdout).toContain("Triage decision: ALLOW");
  });

  it("passport allows safe pinned skills", async () => {
    const result = await execaNode([
      "src/cli.ts",
      "passport",
      "examples/skills/safe-code-reviewer",
      "--source",
      "https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/safe-code-reviewer",
      "--commit",
      "0123456789abcdef0123456789abcdef01234567",
      "--publisher",
      "Gowrav-M"
    ], process.cwd());
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Passport decision: ALLOW");
  });

  it("passport blocks unsafe skills", async () => {
    const result = await execaNode([
      "src/cli.ts",
      "passport",
      "examples/skills/prompt-injected-skill",
      "--source",
      "https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/prompt-injected-skill",
      "--commit",
      "0123456789abcdef0123456789abcdef01234567",
      "--publisher",
      "Gowrav-M"
    ], process.cwd());
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("Passport blocked");
  });

  it("verify-passport validates a generated passport", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "skillguard-verify-passport-"));
    const passport = await execaNode([
      "src/cli.ts",
      "passport",
      join(process.cwd(), "examples/skills/safe-code-reviewer"),
      "--source",
      "https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/safe-code-reviewer",
      "--commit",
      "0123456789abcdef0123456789abcdef01234567",
      "--publisher",
      "Gowrav-M",
      "--pack"
    ], cwd);
    expect(passport.exitCode).toBe(0);

    const verify = await execaNode([
      "src/cli.ts",
      "verify-passport",
      join(cwd, ".skillguard/passports/safe-code-reviewer/passport.json"),
      "--skill-dir",
      join(process.cwd(), "examples/skills/safe-code-reviewer"),
      "--bundle",
      join(cwd, ".skillguard/passports/safe-code-reviewer/safe-code-reviewer.skill.tgz")
    ], cwd);
    expect(verify.exitCode).toBe(0);
    expect(verify.stdout).toContain("Passport verification passed");
  });
});

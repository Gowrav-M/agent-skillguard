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
});

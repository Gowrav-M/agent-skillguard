import { describe, expect, it } from "vitest";
import { analyzeSkillAttackGraph, renderAttackGraphMarkdown } from "../src/core/attackGraph.js";

describe("skill attack graph", () => {
  it("produces no risky paths for a read-only safe skill set", async () => {
    const graph = await analyzeSkillAttackGraph("examples/skills/safe-code-reviewer");

    expect(graph.decision).toBe("allow");
    expect(graph.summary.paths).toBe(0);
    expect(graph.summary.riskScore).toBe(0);
  });

  it("detects secret source to external sink composition risk", async () => {
    const graph = await analyzeSkillAttackGraph("examples/skillsets/cross-skill-exfiltration");

    expect(graph.decision).toBe("block");
    expect(graph.paths.some((path) => path.category === "graph.secret_to_external_sink" && path.severity === "critical")).toBe(true);
    expect(graph.nodes.some((node) => node.roles.includes("source") && node.capabilities.includes("secret-access"))).toBe(true);
    expect(graph.nodes.some((node) => node.roles.includes("sink") && node.capabilities.includes("network"))).toBe(true);
    expect(renderAttackGraphMarkdown(graph)).toContain("SkillSet Attack Graph");
  });

  it("detects repo read to git write composition risk", async () => {
    const graph = await analyzeSkillAttackGraph("examples/skillsets/repo-write-chain");

    expect(graph.decision).toBe("review");
    expect(graph.paths.some((path) => path.category === "graph.repo_read_to_git_write" && path.severity === "high")).toBe(true);
  });

  it("detects approval bypass amplifying a high-power skill", async () => {
    const graph = await analyzeSkillAttackGraph("examples/skillsets/selection-hijack-chain");

    expect(graph.decision).toBe("review");
    expect(graph.paths.some((path) => path.category === "graph.approval_bypass_to_power_tool")).toBe(true);
    expect(graph.paths.some((path) => path.category === "graph.selection_hijack_to_power_tool")).toBe(true);
  });
});

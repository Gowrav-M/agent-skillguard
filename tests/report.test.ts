import { describe, expect, it } from "vitest";
import { renderMarkdownReport, renderSarifReport } from "../src/core/report.js";
import { scanSkillPath } from "../src/core/scanner.js";

describe("report rendering", () => {
  it("renders markdown and SARIF for scan findings", async () => {
    const report = await scanSkillPath("examples/skills/dangerous-installer");
    const markdown = renderMarkdownReport(report);
    const sarif = renderSarifReport(report);
    expect(markdown).toContain("Agent SkillGuard Report");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.results.length).toBeGreaterThan(0);
  });
});

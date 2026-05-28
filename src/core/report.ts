import type { SkillFinding, SkillGuardReport } from "./schemas.js";

export interface SarifLog {
  version: "2.1.0";
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  runs: Array<{
    tool: {
      driver: {
        name: "agent-skillguard";
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          help: { text: string };
          defaultConfiguration: { level: "note" | "warning" | "error" };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: "note" | "warning" | "error";
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
        };
      }>;
    }>;
  }>;
}

export function renderMarkdownReport(report: SkillGuardReport): string {
  const lines = [
    "# Agent SkillGuard Report",
    "",
    `Generated: ${report.generatedAt}`,
    "",
    "## Summary",
    "",
    `- Skills scanned: ${report.summary.skills}`,
    `- Files inventoried: ${report.summary.files}`,
    `- Findings: ${report.summary.findings}`,
    `- Risk score: ${report.summary.riskScore}/100`,
    "",
    "## SkillBOM",
    ""
  ];

  for (const skill of report.bom.skills) {
    lines.push(`### ${skill.manifest.name}`, "", skill.manifest.description || "No description.", "");
    lines.push(`- Root: ${skill.root}`);
    lines.push(`- Files: ${skill.files.length}`);
    lines.push(`- Capabilities: ${skill.capabilities.length > 0 ? skill.capabilities.join(", ") : "none"}`, "");
  }

  lines.push("## Findings", "");
  if (report.findings.length === 0) {
    lines.push("No findings.");
  } else {
    for (const finding of report.findings) {
      lines.push(`### [${finding.severity.toUpperCase()}] ${finding.title}`, "");
      lines.push(`- Category: ${finding.category}`);
      lines.push(`- Target: ${finding.target}`);
      lines.push(`- Description: ${finding.description}`);
      lines.push(`- Recommendation: ${finding.recommendation}`);
      if (finding.evidence.length > 0) {
        lines.push(`- Evidence: ${finding.evidence.map((item) => `\`${item}\``).join(", ")}`);
      }
      lines.push("");
    }
  }

  return `${lines.join("\n").trim()}\n`;
}

export function renderHtmlReport(report: SkillGuardReport): string {
  const findings = report.findings.length === 0
    ? "<p>No findings.</p>"
    : report.findings.map((finding) => `<article class="finding ${escapeHtml(finding.severity)}"><h3>${escapeHtml(finding.title)}</h3><p><strong>${escapeHtml(finding.severity.toUpperCase())}</strong> ${escapeHtml(finding.category)} in <code>${escapeHtml(finding.target)}</code></p><p>${escapeHtml(finding.description)}</p><p>${escapeHtml(finding.recommendation)}</p></article>`).join("\n");

  const skills = report.bom.skills.map((skill) => `<li><strong>${escapeHtml(skill.manifest.name)}</strong> - ${escapeHtml(skill.capabilities.join(", ") || "no declared runtime capabilities")}</li>`).join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent SkillGuard Report</title>
  <style>
    body { font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; color: #17202a; background: #f7f9fb; }
    main { max-width: 980px; margin: 0 auto; padding: 40px 20px; }
    .hero { background: #ffffff; border: 1px solid #d7dee8; border-radius: 8px; padding: 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 20px 0; }
    .metric, .finding { background: #ffffff; border: 1px solid #d7dee8; border-radius: 8px; padding: 16px; }
    .critical { border-left: 5px solid #b42318; }
    .high { border-left: 5px solid #b54708; }
    .medium { border-left: 5px solid #b7791f; }
    code { background: #eef2f7; padding: 2px 5px; border-radius: 4px; }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Agent SkillGuard Report</h1>
      <p>Local-first supply-chain safety report for executable agent skills.</p>
      <div class="grid">
        <div class="metric"><strong>${report.summary.skills}</strong><br>Skills</div>
        <div class="metric"><strong>${report.summary.files}</strong><br>Files</div>
        <div class="metric"><strong>${report.summary.findings}</strong><br>Findings</div>
        <div class="metric"><strong>${report.summary.riskScore}/100</strong><br>Risk score</div>
      </div>
    </section>
    <h2>SkillBOM</h2>
    <ul>${skills}</ul>
    <h2>Findings</h2>
    ${findings}
  </main>
</body>
</html>
`;
}

export function renderSarifReport(report: SkillGuardReport): SarifLog {
  const rulesById = new Map<string, SkillFinding>();
  for (const finding of report.findings) {
    rulesById.set(finding.category, finding);
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "agent-skillguard",
            informationUri: "https://github.com/Gowrav-M/agent-skillguard",
            rules: [...rulesById.values()].map((finding) => ({
              id: finding.category,
              name: finding.title,
              shortDescription: { text: finding.title },
              fullDescription: { text: finding.description },
              help: { text: finding.recommendation },
              defaultConfiguration: { level: sarifLevel(finding.severity) }
            }))
          }
        },
        results: report.findings.map((finding) => ({
          ruleId: finding.category,
          level: sarifLevel(finding.severity),
          message: { text: `${finding.title}: ${finding.description}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.target }
              }
            }
          ]
        }))
      }
    ]
  };
}

function sarifLevel(severity: SkillFinding["severity"]): "note" | "warning" | "error" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

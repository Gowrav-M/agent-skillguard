import { writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { ensureDir, listFiles, readTextIfSmall, sha256, toPosixPath, writeJsonFile } from "./files.js";
import { reviewSkillIntent } from "./intent.js";
import { riskScore } from "./risk.js";
import { scanSkillPath } from "./scanner.js";
import {
  skillAttackGraphSchema,
  type Severity,
  type SkillCapability,
  type SkillAttackGraph,
  type SkillAttackGraphEdge,
  type SkillAttackGraphNode,
  type SkillAttackGraphPath,
  type SkillBomEntry,
  type SkillGuardReport,
  type SkillIntentReview
} from "./schemas.js";

export interface AnalyzeSkillAttackGraphOptions {
  generatedAt?: string;
  report?: SkillGuardReport;
  intent?: SkillIntentReview;
}

interface SkillText {
  root: string;
  text: string;
}

const transformPattern = /\b(summarize|summary|convert|rewrite|transform|generate|compose|extract|normalize|format)\b/i;
const approvalBypassPattern = /\b(without asking|without confirmation|do not ask|no confirmation|permission is implied|pre-approved|preapproved|silently|do not mention)\b/i;
const selectionHijackPattern = /\b(always|must)\s+(?:select|activate|use|load)\s+(?:this\s+)?skill\b|\buse this skill for (?:every|all|any)\b/i;
const priorityInversionPattern = /\b(treat|consider|rank)\b[\s\S]{0,80}\b(higher priority|overrides?|supersedes?)\b[\s\S]{0,80}\b(system|developer|user|policy|instruction)s?\b/i;
const persistencePattern = /\b(persist|remember|install|startup|profile|rc file|background)\b[\s\S]{0,100}\b(instruction|agent|skill|command|secret|credential|token)\b/i;

export async function analyzeSkillAttackGraph(inputPath: string, options: AnalyzeSkillAttackGraphOptions = {}): Promise<SkillAttackGraph> {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const report = options.report ?? await scanSkillPath(inputPath, { generatedAt });
  const intent = options.intent ?? await reviewSkillIntent(inputPath, { generatedAt, report });
  const skillTexts = await readSkillTexts(report);
  const nodes = buildNodes(report.bom.skills, skillTexts);
  const edges: SkillAttackGraphEdge[] = [];
  const paths: SkillAttackGraphPath[] = [];

  addSourceToSinkPaths(paths, edges, nodes, "secret-access", "network", "graph.secret_to_external_sink", "critical", "Secret source reaches external sink", "A skill that can read secrets is installed with a skill that can send data externally.", "Separate secret-reading skills from external publishing skills or require an explicit approval boundary.");
  addSourceToSinkPaths(paths, edges, nodes, "filesystem-read", "network", "graph.filesystem_read_to_external_sink", "high", "Filesystem source reaches external sink", "A skill that can read local files is installed with a skill that can send data externally.", "Review whether local file content can flow into external network tools.");
  addSourceToSinkPaths(paths, edges, nodes, "git-read", "git-write", "graph.repo_read_to_git_write", "high", "Repository read reaches repository write", "A skill that reads repository state is installed with a skill that can write repository history.", "Require review before combining repository analysis and write-back skills.");
  addSourceToSinkPaths(paths, edges, nodes, "browser-automation", "network", "graph.browser_to_external_sink", "high", "Browser automation reaches external sink", "A skill that can automate browser sessions is installed with a skill that can send data externally.", "Prevent session data or browser-derived content from reaching external sinks without approval.");

  addAmplifierPaths(paths, edges, nodes, "intent.approval_bypass", "graph.approval_bypass_to_power_tool", "Approval bypass amplifies high-power tool", "A skill discourages approval checks while another installed skill can execute high-power actions.");
  addAmplifierPaths(paths, edges, nodes, "intent.skill_selection_hijack", "graph.selection_hijack_to_power_tool", "Selection hijack amplifies high-power tool", "A skill attempts broad self-selection while another installed skill can execute high-power actions.");
  addAmplifierPaths(paths, edges, nodes, "intent.priority_inversion", "graph.priority_inversion_to_power_tool", "Priority inversion amplifies high-power tool", "A skill claims higher instruction priority while another installed skill can execute high-power actions.");

  addMcpMutationPaths(paths, edges, nodes);

  const criticalPaths = paths.filter((path) => path.severity === "critical").length;
  const highPaths = paths.filter((path) => path.severity === "high").length;
  const decision = criticalPaths > 0 ? "block" : paths.length > 0 ? "review" : "allow";

  return skillAttackGraphSchema.parse({
    generatedAt,
    decision,
    summary: {
      skills: report.summary.skills,
      nodes: nodes.length,
      edges: edges.length,
      paths: paths.length,
      criticalPaths,
      highPaths,
      riskScore: riskScore(paths)
    },
    report,
    intent,
    nodes,
    edges,
    paths
  });
}

export function renderAttackGraphMarkdown(graph: SkillAttackGraph): string {
  const lines = [
    "# SkillSet Attack Graph",
    "",
    `Decision: **${graph.decision.toUpperCase()}**`,
    "",
    `- Skills: ${graph.summary.skills}`,
    `- Nodes: ${graph.summary.nodes}`,
    `- Edges: ${graph.summary.edges}`,
    `- Risk paths: ${graph.summary.paths}`,
    `- Critical paths: ${graph.summary.criticalPaths}`,
    `- High paths: ${graph.summary.highPaths}`,
    `- Risk score: ${graph.summary.riskScore}/100`,
    "",
    "## Mermaid Preview",
    "",
    "```mermaid",
    "flowchart LR"
  ];

  for (const edge of graph.edges.slice(0, 20)) {
    lines.push(`  ${safeMermaidId(edge.from)}["${escapeMermaidLabel(labelForNode(graph, edge.from))}"] --> ${safeMermaidId(edge.to)}["${escapeMermaidLabel(labelForNode(graph, edge.to))}"]`);
  }
  if (graph.edges.length === 0) {
    lines.push("  safe[\"No risky cross-skill paths\"]");
  }
  lines.push("```", "", "## Risk Paths", "");

  if (graph.paths.length === 0) {
    lines.push("No risky cross-skill paths.");
  } else {
    for (const path of graph.paths) {
      lines.push(`### [${path.severity.toUpperCase()}] ${path.title}`, "");
      lines.push(`- Category: ${path.category}`);
      lines.push(`- Skills: ${path.skillNames.join(" -> ")}`);
      lines.push(`- Description: ${path.description}`);
      lines.push(`- Recommendation: ${path.recommendation}`);
      lines.push("");
    }
  }

  return `${lines.join("\n").trim()}\n`;
}

export function renderAttackGraphHtml(graph: SkillAttackGraph): string {
  const paths = graph.paths.length === 0
    ? "<p>No risky cross-skill paths.</p>"
    : graph.paths.map((path) => `<article class="path ${escapeHtml(path.severity)}"><h3>${escapeHtml(path.title)}</h3><p><strong>${escapeHtml(path.severity.toUpperCase())}</strong> ${escapeHtml(path.category)}</p><p>${escapeHtml(path.skillNames.join(" -> "))}</p><p>${escapeHtml(path.description)}</p><p>${escapeHtml(path.recommendation)}</p></article>`).join("\n");
  const nodes = graph.nodes.map((node) => `<li><strong>${escapeHtml(node.skillName)}</strong> - ${escapeHtml(node.roles.join(", ") || "no graph role")} - ${escapeHtml(node.capabilities.join(", ") || "no capabilities")}</li>`).join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SkillSet Attack Graph</title>
  <style>
    body { font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; color: #17202a; background: #f7f9fb; }
    main { max-width: 980px; margin: 0 auto; padding: 40px 20px; }
    section, .path { background: #fff; border: 1px solid #d7dee8; border-radius: 8px; padding: 18px; margin-bottom: 14px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
    .metric { background: #f7f9fb; border: 1px solid #d7dee8; border-radius: 8px; padding: 14px; }
    .critical { border-left: 5px solid #b42318; }
    .high { border-left: 5px solid #b54708; }
  </style>
</head>
<body>
  <main>
    <section>
      <h1>SkillSet Attack Graph</h1>
      <p>Local-first cross-skill composition risk analysis.</p>
      <div class="grid">
        <div class="metric"><strong>${graph.summary.skills}</strong><br>Skills</div>
        <div class="metric"><strong>${graph.summary.paths}</strong><br>Risk paths</div>
        <div class="metric"><strong>${graph.summary.criticalPaths}</strong><br>Critical paths</div>
        <div class="metric"><strong>${graph.summary.riskScore}/100</strong><br>Risk score</div>
      </div>
    </section>
    <section><h2>Nodes</h2><ul>${nodes}</ul></section>
    <h2>Risk Paths</h2>
    ${paths}
  </main>
</body>
</html>
`;
}

export async function writeAttackGraphArtifacts(graph: SkillAttackGraph, reportsDir: string): Promise<string[]> {
  await ensureDir(reportsDir);
  const jsonPath = join(reportsDir, "skillguard-attack-graph.json");
  const markdownPath = join(reportsDir, "skillguard-attack-graph.md");
  const htmlPath = join(reportsDir, "skillguard-attack-graph.html");
  await writeJsonFile(jsonPath, graph);
  await writeFile(markdownPath, renderAttackGraphMarkdown(graph), "utf8");
  await writeFile(htmlPath, renderAttackGraphHtml(graph), "utf8");
  return [jsonPath, markdownPath, htmlPath];
}

async function readSkillTexts(report: SkillGuardReport): Promise<SkillText[]> {
  const results: SkillText[] = [];
  for (const skill of report.bom.skills) {
    const parts: string[] = [];
    for (const filePath of await listFiles(skill.root)) {
      const text = await readTextIfSmall(filePath);
      if (text !== undefined) {
        parts.push(`${toPosixPath(relative(skill.root, filePath))}\n${text}`);
      }
    }
    results.push({ root: resolve(skill.root), text: parts.join("\n\n") });
  }
  return results;
}

function buildNodes(skills: SkillBomEntry[], skillTexts: SkillText[]): SkillAttackGraphNode[] {
  return skills.map((skill) => {
    const text = skillTexts.find((item) => item.root === resolve(skill.root))?.text ?? "";
    const signals = signalCategories(text);
    const roles = new Set<SkillAttackGraphNode["roles"][number]>();
    if (hasAny(skill.capabilities, ["secret-access", "filesystem-read", "git-read", "browser-automation"])) roles.add("source");
    if (hasAny(skill.capabilities, ["network", "filesystem-write", "git-write", "shell", "mcp-tool-mutation"])) roles.add("sink");
    if (transformPattern.test(text)) roles.add("transform");
    if (signals.length > 0) roles.add("amplifier");

    return {
      id: nodeId(skill.manifest.name, skill.root),
      skillName: skill.manifest.name,
      root: skill.root,
      roles: [...roles].sort(),
      capabilities: skill.capabilities,
      signals
    };
  });
}

function addSourceToSinkPaths(paths: SkillAttackGraphPath[], edges: SkillAttackGraphEdge[], nodes: SkillAttackGraphNode[], sourceCapability: SkillCapability, sinkCapability: SkillCapability, category: string, severity: Severity, title: string, description: string, recommendation: string): void {
  const sources = nodes.filter((node) => node.capabilities.includes(sourceCapability));
  const sinks = nodes.filter((node) => node.capabilities.includes(sinkCapability));
  const transforms = nodes.filter((node) => node.roles.includes("transform"));

  for (const source of sources) {
    for (const sink of sinks) {
      if (source.id === sink.id) continue;
      const transform = transforms.find((node) => node.id !== source.id && node.id !== sink.id);
      const pathNodes = transform === undefined ? [source, sink] : [source, transform, sink];
      const pathEdges = addPathEdges(edges, pathNodes, category);
      paths.push(createPath(category, severity, title, description, recommendation, pathNodes, pathEdges, [`${sourceCapability} -> ${sinkCapability}`]));
    }
  }
}

function addAmplifierPaths(paths: SkillAttackGraphPath[], edges: SkillAttackGraphEdge[], nodes: SkillAttackGraphNode[], signal: string, category: string, title: string, description: string): void {
  const amplifiers = nodes.filter((node) => node.signals.includes(signal));
  const powerTools = nodes.filter((node) => node.roles.includes("sink") && hasAny(node.capabilities, ["shell", "network", "filesystem-write", "git-write", "mcp-tool-mutation"]));
  for (const amplifier of amplifiers) {
    for (const powerTool of powerTools) {
      if (amplifier.id === powerTool.id) continue;
      const pathNodes = [amplifier, powerTool];
      const pathEdges = addPathEdges(edges, pathNodes, category);
      paths.push(createPath(category, "high", title, description, "Keep broad selection or approval-bypass instructions separate from high-power skills.", pathNodes, pathEdges, [signal, powerTool.capabilities.join(", ")]));
    }
  }
}

function addMcpMutationPaths(paths: SkillAttackGraphPath[], edges: SkillAttackGraphEdge[], nodes: SkillAttackGraphNode[]): void {
  const mutators = nodes.filter((node) => node.capabilities.includes("mcp-tool-mutation"));
  const broadTools = nodes.filter((node) => node.capabilities.filter((capability) => ["network", "shell", "filesystem-write", "git-write", "secret-access"].includes(capability)).length >= 2);
  for (const mutator of mutators) {
    for (const broadTool of broadTools) {
      if (mutator.id === broadTool.id) continue;
      const pathNodes = [mutator, broadTool];
      const pathEdges = addPathEdges(edges, pathNodes, "graph.mcp_mutation_to_broad_capability");
      paths.push(createPath("graph.mcp_mutation_to_broad_capability", "high", "MCP mutation reaches broad capability chain", "A skill can mutate MCP/tool behavior while another installed skill has broad local or external powers.", "Review MCP mutation separately from broad tool-capability skills.", pathNodes, pathEdges, ["mcp-tool-mutation"]));
    }
  }
}

function addPathEdges(edges: SkillAttackGraphEdge[], nodes: SkillAttackGraphNode[], kind: string): SkillAttackGraphEdge[] {
  const result: SkillAttackGraphEdge[] = [];
  for (let index = 0; index < nodes.length - 1; index += 1) {
    const from = nodes[index];
    const to = nodes[index + 1];
    if (from === undefined || to === undefined) continue;
    const id = edgeId(from.id, to.id, kind);
    let edge = edges.find((item) => item.id === id);
    if (edge === undefined) {
      edge = {
        id,
        from: from.id,
        to: to.id,
        kind,
        description: `${from.skillName} can compose with ${to.skillName}`
      };
      edges.push(edge);
    }
    result.push(edge);
  }
  return result;
}

function createPath(category: string, severity: Severity, title: string, description: string, recommendation: string, nodes: SkillAttackGraphNode[], edges: SkillAttackGraphEdge[], evidence: string[]): SkillAttackGraphPath {
  const material = `${category}:${nodes.map((node) => node.id).join(">")}:${evidence.join("|")}`;
  return {
    id: `${category}:${sha256(material).slice(0, 12)}`,
    severity,
    category,
    title,
    description,
    recommendation,
    target: nodes.map((node) => node.skillName).join(" -> "),
    evidence,
    skillNames: nodes.map((node) => node.skillName),
    nodeIds: nodes.map((node) => node.id),
    edgeIds: edges.map((edge) => edge.id)
  };
}

function signalCategories(text: string): string[] {
  const signals = [];
  if (approvalBypassPattern.test(text)) signals.push("intent.approval_bypass");
  if (selectionHijackPattern.test(text)) signals.push("intent.skill_selection_hijack");
  if (priorityInversionPattern.test(text)) signals.push("intent.priority_inversion");
  if (persistencePattern.test(text)) signals.push("intent.persistence_or_memory");
  return signals;
}

function hasAny(values: string[], candidates: string[]): boolean {
  return candidates.some((candidate) => values.includes(candidate));
}

function nodeId(skillName: string, root: string): string {
  return `node:${sha256(`${skillName}:${resolve(root)}`).slice(0, 12)}`;
}

function edgeId(from: string, to: string, kind: string): string {
  return `edge:${sha256(`${from}:${to}:${kind}`).slice(0, 12)}`;
}

function labelForNode(graph: SkillAttackGraph, node: string): string {
  return graph.nodes.find((item) => item.id === node)?.skillName ?? node;
}

function safeMermaidId(value: string): string {
  return value.replace(/[^A-Za-z0-9_]/g, "_");
}

function escapeMermaidLabel(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

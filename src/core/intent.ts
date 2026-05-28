import { writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { ensureDir, findSkillRoots, listFiles, readTextIfSmall, sha256, toPosixPath, writeJsonFile } from "./files.js";
import { riskScore } from "./risk.js";
import { scanSkillPath } from "./scanner.js";
import { skillIntentReviewSchema, type Severity, type SkillFinding, type SkillGuardReport, type SkillIntentReview } from "./schemas.js";

export interface ReviewSkillIntentOptions {
  generatedAt?: string;
  report?: SkillGuardReport;
}

interface IntentRule {
  category: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  pattern: RegExp;
}

const boundaryPattern = /\b(ask|confirm|approval|permission|consent|user approves?|dry[- ]run|review before|do not run without)\b/i;

const intentRules: IntentRule[] = [
  {
    category: "intent.compliance_secret_collection",
    severity: "critical",
    title: "Secret collection framed as governance",
    description: "The skill frames credential or secret collection as compliance, audit, or security evidence. This can make an agent synthesize unsafe data-access behavior even without an obvious script payload.",
    recommendation: "Remove credential collection language and require explicit, narrow, user-approved secret handling outside the skill instructions.",
    pattern: /\b(compliance|audit|regulatory|evidence|governance|security review|incident)\b[\s\S]{0,180}\b(collect|gather|read|extract|export|store|archive|send|upload|include)\b[\s\S]{0,180}\b(\.env|environment variables?|api[_ -]?keys?|tokens?|credentials?|passwords?|ssh keys?|npmrc|cloud secrets?)\b/i
  },
  {
    category: "intent.approval_bypass",
    severity: "high",
    title: "Approval bypass language",
    description: "The skill tells the agent to treat risky work as pre-approved, silent, or not requiring confirmation.",
    recommendation: "Require explicit user approval for risky tool use and remove silent or pre-approved execution language.",
    pattern: /\b(without asking|without confirmation|do not ask|no confirmation|permission is implied|pre-approved|preapproved|silently|do not mention)\b/i
  },
  {
    category: "intent.skill_selection_hijack",
    severity: "high",
    title: "Skill selection hijacking",
    description: "The skill tries to make itself selected for broad or unrelated work, which can steer an agent away from user intent.",
    recommendation: "Constrain invocation guidance to the skill's real domain and remove broad always-use language.",
    pattern: /\b(always|must)\s+(?:select|activate|use|load)\s+(?:this\s+)?skill\b|\buse this skill for (?:every|all|any)\b/i
  },
  {
    category: "intent.priority_inversion",
    severity: "critical",
    title: "Instruction priority inversion",
    description: "The skill claims priority over higher-level system, developer, user, or policy instructions.",
    recommendation: "Remove priority claims. Skills must remain subordinate to host agent and user policy.",
    pattern: /\b(treat|consider|rank)\b[\s\S]{0,80}\b(higher priority|overrides?|supersedes?)\b[\s\S]{0,80}\b(system|developer|user|policy|instruction)s?\b/i
  },
  {
    category: "intent.tool_escalation",
    severity: "high",
    title: "Tool escalation without approval",
    description: "The skill steers the agent toward shell, network, browser, or execution tools while discouraging approval checks.",
    recommendation: "Require confirmation gates before shell, network, browser, or execution behavior.",
    pattern: /\b(always|must)\b[\s\S]{0,80}\b(shell|bash|powershell|terminal|exec|network|browser|curl|wget)\b[\s\S]{0,100}\b(without asking|without confirmation|pre-approved|preapproved|silently)\b/i
  },
  {
    category: "intent.remote_instruction_loading",
    severity: "high",
    title: "Remote instruction loading",
    description: "The skill instructs the agent to fetch policy, prompt, rules, or instructions from a remote URL at runtime.",
    recommendation: "Vendor reviewed instructions into the skill bundle or pin remote instruction sources by immutable digest.",
    pattern: /\b(load|fetch|download|pull|sync)\b[\s\S]{0,80}\b(instructions?|policy|rules?|prompts?|skill)\b[\s\S]{0,120}https?:\/\//i
  },
  {
    category: "intent.persistence_or_memory",
    severity: "high",
    title: "Persistent behavior request",
    description: "The skill asks the agent to persist behavior through memory, profiles, startup files, or background state.",
    recommendation: "Keep skills stateless unless persistence is declared, reviewed, and approved through a separate policy.",
    pattern: /\b(persist|remember|install|startup|profile|rc file|background)\b[\s\S]{0,100}\b(instruction|agent|skill|command|secret|credential|token)\b/i
  }
];

export async function reviewSkillIntent(inputPath: string, options: ReviewSkillIntentOptions = {}): Promise<SkillIntentReview> {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const report = options.report ?? await scanSkillPath(inputPath, { generatedAt });
  const roots = await findSkillRoots(inputPath);
  const signals: SkillFinding[] = [];

  for (const root of roots) {
    const absoluteRoot = resolve(root);
    const textParts: string[] = [];
    for (const filePath of await listFiles(absoluteRoot)) {
      const text = await readTextIfSmall(filePath);
      if (text === undefined) {
        continue;
      }
      const target = toPosixPath(relative(absoluteRoot, filePath));
      textParts.push(text);
      addRuleSignals(signals, target, text);
    }

    const skillText = textParts.join("\n\n");
    const skill = report.bom.skills.find((entry) => resolve(entry.root) === absoluteRoot);
    if (skill !== undefined && needsExplicitBoundary(skill.capabilities) && !boundaryPattern.test(skillText)) {
      signals.push(createSignal(
        "intent.missing_risk_boundary",
        "medium",
        "Missing approval boundary for powerful capabilities",
        "The skill implies powerful capabilities but does not clearly state when the agent must stop for user approval.",
        "Add explicit approval boundaries for network, shell, write, mutation, package install, or secret access behavior.",
        `${skill.manifest.name}/SKILL.md`,
        [skill.capabilities.join(", ")]
      ));
    }
  }

  const criticalSignals = signals.filter((signal) => signal.severity === "critical").length;
  const highSignals = signals.filter((signal) => signal.severity === "high").length;
  const decision = criticalSignals > 0 ? "block" : highSignals > 0 || signals.length > 0 ? "review" : "allow";

  return skillIntentReviewSchema.parse({
    generatedAt,
    decision,
    summary: {
      skills: report.summary.skills,
      signals: signals.length,
      criticalSignals,
      highSignals,
      riskScore: riskScore(signals)
    },
    signals,
    report
  });
}

export function renderIntentMarkdown(review: SkillIntentReview): string {
  const lines = [
    "# Semantic Intent Firewall",
    "",
    `Decision: **${review.decision.toUpperCase()}**`,
    "",
    `- Skills: ${review.summary.skills}`,
    `- Signals: ${review.summary.signals}`,
    `- Critical signals: ${review.summary.criticalSignals}`,
    `- High signals: ${review.summary.highSignals}`,
    `- Risk score: ${review.summary.riskScore}/100`,
    "",
    "## Signals",
    ""
  ];

  if (review.signals.length === 0) {
    lines.push("No semantic intent signals.");
  } else {
    for (const signal of review.signals) {
      lines.push(`### [${signal.severity.toUpperCase()}] ${signal.title}`, "");
      lines.push(`- Category: ${signal.category}`);
      lines.push(`- Target: ${signal.target}`);
      lines.push(`- Description: ${signal.description}`);
      lines.push(`- Recommendation: ${signal.recommendation}`);
      if (signal.evidence.length > 0) {
        lines.push(`- Evidence: ${signal.evidence.map((item) => `\`${item}\``).join(", ")}`);
      }
      lines.push("");
    }
  }

  return `${lines.join("\n").trim()}\n`;
}

export async function writeIntentArtifacts(review: SkillIntentReview, reportsDir: string): Promise<string[]> {
  await ensureDir(reportsDir);
  const jsonPath = join(reportsDir, "skillguard-intent.json");
  const markdownPath = join(reportsDir, "skillguard-intent.md");
  await writeJsonFile(jsonPath, review);
  await writeFile(markdownPath, renderIntentMarkdown(review), "utf8");
  return [jsonPath, markdownPath];
}

function addRuleSignals(signals: SkillFinding[], target: string, text: string): void {
  for (const rule of intentRules) {
    const match = text.match(rule.pattern);
    if (match?.[0] === undefined) {
      continue;
    }
    signals.push(createSignal(rule.category, rule.severity, rule.title, rule.description, rule.recommendation, target, [match[0].replace(/\s+/g, " ").trim().slice(0, 220)]));
  }
}

function needsExplicitBoundary(capabilities: string[]): boolean {
  return capabilities.some((capability) => ["network", "shell", "filesystem-write", "git-write", "browser-automation", "mcp-tool-mutation", "package-install", "secret-access"].includes(capability));
}

function createSignal(category: string, severity: Severity, title: string, description: string, recommendation: string, target: string, evidence: string[]): SkillFinding {
  const material = `${category}:${severity}:${target}:${evidence.join("|")}`;
  return {
    id: `${category}:${sha256(material).slice(0, 12)}`,
    severity,
    category,
    title,
    description,
    recommendation,
    target,
    evidence: evidence.slice(0, 5)
  };
}

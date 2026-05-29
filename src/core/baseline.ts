import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { ensureDir, readJsonFile, writeJsonFile } from "./files.js";
import { reviewSkillIntent } from "./intent.js";
import { riskScore } from "./risk.js";
import { scanSkillPath } from "./scanner.js";
import {
  skillRiskBaselineSchema,
  skillRiskTriageSchema,
  type SkillFinding,
  type SkillRiskBaseline,
  type SkillRiskBaselineEntry,
  type SkillRiskTriage
} from "./schemas.js";

export interface CreateRiskBaselineOptions {
  generatedAt?: string;
  reason: string;
  expiresAt?: string;
}

export interface TriageSkillRiskOptions {
  generatedAt?: string;
}

export async function createRiskBaseline(inputPath: string, options: CreateRiskBaselineOptions): Promise<SkillRiskBaseline> {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const report = await scanSkillPath(inputPath, { generatedAt });
  const intent = await reviewSkillIntent(inputPath, { generatedAt, report });
  const acceptedAt = generatedAt;
  const entries = [
    ...report.findings.map((finding) => baselineEntry("scan", finding, acceptedAt, options)),
    ...intent.signals.map((signal) => baselineEntry("intent", signal, acceptedAt, options))
  ];

  return skillRiskBaselineSchema.parse({
    schemaVersion: 1,
    generatedAt,
    scope: resolve(inputPath),
    reason: options.reason,
    accepted: entries
  });
}

export async function triageSkillRisk(inputPath: string, baseline: SkillRiskBaseline, options: TriageSkillRiskOptions = {}): Promise<SkillRiskTriage> {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const report = await scanSkillPath(inputPath, { generatedAt });
  const intent = await reviewSkillIntent(inputPath, { generatedAt, report });
  const acceptedIds = new Set(
    baseline.accepted
      .filter((entry) => isEntryActive(entry, generatedAt))
      .map((entry) => `${entry.source}:${entry.id}`)
  );
  const unresolvedFindings = report.findings.filter((finding) => !acceptedIds.has(`scan:${finding.id}`));
  const unresolvedIntentSignals = intent.signals.filter((signal) => !acceptedIds.has(`intent:${signal.id}`));
  const unresolved = [...unresolvedFindings, ...unresolvedIntentSignals];
  const decision = unresolved.some((finding) => finding.severity === "critical")
    ? "block"
    : unresolved.length > 0
      ? "review"
      : "allow";

  return skillRiskTriageSchema.parse({
    generatedAt,
    decision,
    summary: {
      accepted: baseline.accepted.length,
      unresolved: unresolved.length,
      unresolvedFindings: unresolvedFindings.length,
      unresolvedIntentSignals: unresolvedIntentSignals.length,
      riskScore: riskScore(unresolved)
    },
    baseline,
    report,
    intent,
    unresolvedFindings,
    unresolvedIntentSignals
  });
}

export async function readRiskBaseline(path: string): Promise<SkillRiskBaseline> {
  return skillRiskBaselineSchema.parse(await readJsonFile<unknown>(path));
}

export async function writeRiskBaseline(baseline: SkillRiskBaseline, outputPath: string): Promise<string> {
  await writeJsonFile(outputPath, baseline);
  return outputPath;
}

export async function writeRiskTriageArtifacts(triage: SkillRiskTriage, reportsDir: string): Promise<string[]> {
  await ensureDir(reportsDir);
  const jsonPath = join(reportsDir, "skillguard-triage.json");
  const markdownPath = join(reportsDir, "skillguard-triage.md");
  await writeJsonFile(jsonPath, triage);
  await writeFile(markdownPath, renderRiskTriageMarkdown(triage), "utf8");
  return [jsonPath, markdownPath];
}

export function renderRiskBaselineMarkdown(baseline: SkillRiskBaseline): string {
  const lines = [
    "# SkillGuard Risk Baseline",
    "",
    `Generated: ${baseline.generatedAt}`,
    `Scope: ${baseline.scope}`,
    `Reason: ${baseline.reason}`,
    "",
    `Accepted risks: ${baseline.accepted.length}`,
    "",
    "## Accepted Entries",
    ""
  ];

  for (const entry of baseline.accepted) {
    lines.push(`- [${entry.severity.toUpperCase()}] ${entry.source}:${entry.category} at \`${entry.target}\` - ${entry.title}`);
  }

  return `${lines.join("\n").trim()}\n`;
}

export function renderRiskTriageMarkdown(triage: SkillRiskTriage): string {
  const lines = [
    "# SkillGuard Risk Triage",
    "",
    `Decision: **${triage.decision.toUpperCase()}**`,
    "",
    `- Accepted baseline entries: ${triage.summary.accepted}`,
    `- Unresolved risks: ${triage.summary.unresolved}`,
    `- Unresolved scan findings: ${triage.summary.unresolvedFindings}`,
    `- Unresolved intent signals: ${triage.summary.unresolvedIntentSignals}`,
    `- Risk score: ${triage.summary.riskScore}/100`,
    "",
    "## Unresolved Scan Findings",
    ""
  ];

  appendFindings(lines, triage.unresolvedFindings);
  lines.push("", "## Unresolved Intent Signals", "");
  appendFindings(lines, triage.unresolvedIntentSignals);
  return `${lines.join("\n").trim()}\n`;
}

function baselineEntry(source: "scan" | "intent", finding: SkillFinding, acceptedAt: string, options: CreateRiskBaselineOptions): SkillRiskBaselineEntry {
  const entry: SkillRiskBaselineEntry = {
    id: finding.id,
    source,
    severity: finding.severity,
    category: finding.category,
    target: finding.target,
    title: finding.title,
    acceptedAt,
    reason: options.reason
  };
  if (options.expiresAt !== undefined) {
    entry.expiresAt = options.expiresAt;
  }
  return entry;
}

function isEntryActive(entry: SkillRiskBaselineEntry, generatedAt: string): boolean {
  if (entry.expiresAt === undefined) {
    return true;
  }
  return parseExpiry(entry.expiresAt) >= Date.parse(generatedAt);
}

function parseExpiry(expiresAt: string): number {
  if (/^\d{4}-\d{2}-\d{2}$/.test(expiresAt)) {
    return Date.parse(`${expiresAt}T23:59:59.999Z`);
  }
  return Date.parse(expiresAt);
}

function appendFindings(lines: string[], findings: SkillFinding[]): void {
  if (findings.length === 0) {
    lines.push("No unresolved entries.");
    return;
  }

  for (const finding of findings) {
    lines.push(`- [${finding.severity.toUpperCase()}] ${finding.category} at \`${finding.target}\`: ${finding.title}`);
  }
}

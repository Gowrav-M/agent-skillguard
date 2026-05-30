import { access } from "node:fs/promises";
import { join } from "node:path";
import { readJsonFile } from "./files.js";
import {
  skillAdmissionDecisionSchema,
  skillGuardReportSchema,
  type SkillAdmissionDecision,
  type SkillFinding,
  type SkillGuardReport
} from "./schemas.js";

export type TrustDecision = "allow" | "review" | "block";
export type TrustSeverity = "info" | "low" | "medium" | "warning" | "high" | "critical";

export interface SkillGuardTrustPaths {
  reportsDir: string;
  reportJson: string;
  reportMarkdown: string;
  reportHtml: string;
  reportSarif: string;
  admissionJson: string;
}

export interface TrustEvidenceFinding {
  id: string;
  severity: TrustSeverity;
  title: string;
  message: string;
  recommendation?: string;
  source?: string;
}

export interface TrustEvidence {
  schemaVersion: "agent.trust.evidence.v1";
  tool: {
    name: "agent-skillguard";
    version: string;
  };
  subject: {
    type: "skill";
    name: string;
  };
  decision: TrustDecision;
  score: number;
  generatedAt: string;
  findings: TrustEvidenceFinding[];
  artifacts: Array<{ type: string; path: string }>;
  recommendations: string[];
}

export function trustEvidencePath(paths: SkillGuardTrustPaths): string {
  return join(paths.reportsDir, "trust-evidence.json");
}

export async function readSkillGuardReport(path: string): Promise<SkillGuardReport> {
  return skillGuardReportSchema.parse(await readJsonFile<unknown>(path));
}

export async function readSkillAdmission(path: string): Promise<SkillAdmissionDecision | undefined> {
  if (!(await fileExists(path))) {
    return undefined;
  }
  return skillAdmissionDecisionSchema.parse(await readJsonFile<unknown>(path));
}

export async function createSkillGuardTrustEvidence(input: {
  paths: SkillGuardTrustPaths;
  version: string;
  report?: SkillGuardReport;
  admission?: SkillAdmissionDecision;
}): Promise<TrustEvidence> {
  const report = input.report ?? await readSkillGuardReport(input.paths.reportJson);
  const admission = input.admission ?? await readSkillAdmission(input.paths.admissionJson);
  const decision = admission?.decision ?? decisionFor(report.findings, report.summary.riskScore);
  const artifacts = await existingArtifacts(input.paths);
  return {
    schemaVersion: "agent.trust.evidence.v1",
    tool: {
      name: "agent-skillguard",
      version: input.version
    },
    subject: {
      type: "skill",
      name: "agent-skillguard skill supply-chain evidence"
    },
    decision,
    score: clampScore(report.summary.riskScore),
    generatedAt: report.generatedAt,
    findings: report.findings.map(toTrustFinding),
    artifacts,
    recommendations: recommendationsFor(report.findings, decision)
  };
}

function decisionFor(findings: SkillFinding[], riskScore: number): TrustDecision {
  if (findings.some((finding) => finding.severity === "critical") || riskScore >= 80) {
    return "block";
  }
  if (findings.some((finding) => finding.severity === "high" || finding.severity === "medium") || riskScore > 0) {
    return "review";
  }
  return "allow";
}

function toTrustFinding(finding: SkillFinding): TrustEvidenceFinding {
  return {
    id: finding.id,
    severity: finding.severity,
    title: finding.title,
    message: finding.description,
    recommendation: finding.recommendation,
    source: finding.target
  };
}

function recommendationsFor(findings: SkillFinding[], decision: TrustDecision): string[] {
  const recommendations = new Set(findings.map((finding) => finding.recommendation));
  if (decision === "allow") {
    recommendations.add("Keep the SkillGuard lockfile and passport attached to future skill reviews.");
  }
  if (decision === "review") {
    recommendations.add("Review SkillGuard findings before allowing this skill set into an agent workspace.");
  }
  if (decision === "block") {
    recommendations.add("Block installation or publishing until critical SkillGuard findings are resolved.");
  }
  return [...recommendations].filter((recommendation) => recommendation.length > 0);
}

async function existingArtifacts(paths: SkillGuardTrustPaths): Promise<Array<{ type: string; path: string }>> {
  const candidates: Array<{ type: string; path: string }> = [
    { type: "skillguard-report-json", path: paths.reportJson },
    { type: "skillguard-report-markdown", path: paths.reportMarkdown },
    { type: "skillguard-report-html", path: paths.reportHtml },
    { type: "skillguard-report-sarif", path: paths.reportSarif },
    { type: "skillguard-admission-json", path: paths.admissionJson }
  ];
  const existing: Array<{ type: string; path: string }> = [];
  for (const candidate of candidates) {
    if (await fileExists(candidate.path)) {
      existing.push(candidate);
    }
  }
  return existing;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

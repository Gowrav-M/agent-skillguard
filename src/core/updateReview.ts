import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { sha256, writeJsonFile } from "./files.js";
import { evaluateAdmission } from "./policy.js";
import { severityRank } from "./risk.js";
import { scanSkillPath } from "./scanner.js";
import {
  skillUpdateReviewSchema,
  type AdmissionReason,
  type SkillCapability,
  type SkillFinding,
  type SkillGuardReport,
  type SkillUpdateReview
} from "./schemas.js";

export interface ReviewSkillUpdateOptions {
  generatedAt?: string;
}

export async function reviewSkillUpdate(previousPath: string, candidatePath: string, options: ReviewSkillUpdateOptions = {}): Promise<SkillUpdateReview> {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const previous = await scanSkillPath(previousPath, { generatedAt });
  const candidate = await scanSkillPath(candidatePath, { generatedAt });

  const previousCapabilities = capabilitiesFor(previous);
  const candidateCapabilities = capabilitiesFor(candidate);
  const previousFiles = filesFor(previous);
  const candidateFiles = filesFor(candidate);
  const previousFindings = findingFingerprints(previous.findings);

  const addedCapabilities = difference(candidateCapabilities, previousCapabilities);
  const removedCapabilities = difference(previousCapabilities, candidateCapabilities);
  const addedFiles = difference([...candidateFiles.keys()], [...previousFiles.keys()]);
  const removedFiles = difference([...previousFiles.keys()], [...candidateFiles.keys()]);
  const modifiedFiles = [...candidateFiles.entries()]
    .filter(([path, hash]) => previousFiles.has(path) && previousFiles.get(path) !== hash)
    .map(([path]) => path)
    .sort();

  const newFindings = candidate.findings.filter((finding) => !previousFindings.has(findingFingerprint(finding)));
  const reasons: AdmissionReason[] = [];

  for (const finding of newFindings) {
    if (finding.severity === "critical") {
      reasons.push(reason("critical", "update.new_critical_finding", finding.title, finding.target));
    } else if (severityRank(finding.severity) >= severityRank("high")) {
      reasons.push(reason(finding.severity, "update.new_high_finding", finding.title, finding.target));
    }
  }

  const newlyDangerousCapabilities = addedCapabilities.filter((capability) =>
    capability === "secret-access" ||
    capability === "mcp-tool-mutation" ||
    capability === "package-install" ||
    capability === "shell" ||
    capability === "filesystem-write" ||
    capability === "git-write"
  );
  for (const capability of newlyDangerousCapabilities) {
    reasons.push(reason("high", `update.added_capability.${capability}`, `Candidate adds capability ${capability}.`, "capabilities"));
  }

  if (modifiedFiles.includes("SKILL.md") || addedFiles.includes("SKILL.md")) {
    reasons.push(reason("high", "update.skill_manifest_drift", "Candidate changes the main SKILL.md instruction surface.", "SKILL.md"));
  }

  if (candidate.summary.riskScore > previous.summary.riskScore + 25) {
    reasons.push(reason("high", "update.risk_score_increase", `Risk score increased from ${previous.summary.riskScore} to ${candidate.summary.riskScore}.`, "risk-score"));
  }

  const candidateAdmission = evaluateAdmission(candidate);
  for (const admissionReason of candidateAdmission.reasons) {
    reasons.push({
      ...admissionReason,
      code: `candidate.${admissionReason.code}`
    });
  }

  const dedupedReasons = dedupeReasons(reasons);
  const decision = dedupedReasons.some((item) => severityRank(item.severity) >= severityRank("high"))
    ? "block"
    : dedupedReasons.length > 0 || modifiedFiles.length > 0 || addedFiles.length > 0 || removedFiles.length > 0
      ? "review"
      : "allow";

  return skillUpdateReviewSchema.parse({
    generatedAt,
    decision,
    summary: {
      previousRiskScore: previous.summary.riskScore,
      candidateRiskScore: candidate.summary.riskScore,
      addedCapabilities,
      removedCapabilities,
      addedFiles,
      removedFiles,
      modifiedFiles,
      newFindings: newFindings.length
    },
    reasons: dedupedReasons,
    previous,
    candidate
  });
}

export function renderUpdateReviewMarkdown(review: SkillUpdateReview): string {
  const lines = [
    "# SkillGuard Update Review",
    "",
    `Decision: **${review.decision.toUpperCase()}**`,
    "",
    `- Previous risk score: ${review.summary.previousRiskScore}/100`,
    `- Candidate risk score: ${review.summary.candidateRiskScore}/100`,
    `- New findings: ${review.summary.newFindings}`,
    `- Added capabilities: ${review.summary.addedCapabilities.join(", ") || "none"}`,
    `- Removed capabilities: ${review.summary.removedCapabilities.join(", ") || "none"}`,
    `- Added files: ${review.summary.addedFiles.join(", ") || "none"}`,
    `- Removed files: ${review.summary.removedFiles.join(", ") || "none"}`,
    `- Modified files: ${review.summary.modifiedFiles.join(", ") || "none"}`,
    "",
    "## Reasons",
    ""
  ];

  if (review.reasons.length === 0) {
    lines.push("No blocking or review reasons.");
  } else {
    for (const item of review.reasons) {
      lines.push(`- [${item.severity.toUpperCase()}] ${item.code} at \`${item.target}\`: ${item.message}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export async function writeUpdateReviewArtifacts(review: SkillUpdateReview, reportsDir: string): Promise<string[]> {
  const jsonPath = join(reportsDir, "skillguard-update-review.json");
  const markdownPath = join(reportsDir, "skillguard-update-review.md");
  await writeJsonFile(jsonPath, review);
  await writeFile(markdownPath, renderUpdateReviewMarkdown(review), "utf8");
  return [jsonPath, markdownPath];
}

function capabilitiesFor(report: SkillGuardReport): SkillCapability[] {
  return [...new Set(report.bom.skills.flatMap((skill) => skill.capabilities))].sort();
}

function filesFor(report: SkillGuardReport): Map<string, string> {
  const files = new Map<string, string>();
  for (const skill of report.bom.skills) {
    for (const file of skill.files) {
      files.set(file.path, file.sha256);
    }
  }
  return files;
}

function findingFingerprints(findings: SkillFinding[]): Set<string> {
  return new Set(findings.map(findingFingerprint));
}

function findingFingerprint(finding: SkillFinding): string {
  return sha256(`${finding.category}:${finding.severity}:${finding.target}:${finding.title}`);
}

function difference<T extends string>(left: readonly T[], right: readonly T[]): T[] {
  const rightSet = new Set(right);
  return left.filter((item) => !rightSet.has(item)).sort();
}

function reason(severity: AdmissionReason["severity"], code: string, message: string, target: string): AdmissionReason {
  return { severity, code, message, target };
}

function dedupeReasons(reasons: AdmissionReason[]): AdmissionReason[] {
  const seen = new Set<string>();
  return reasons.filter((item) => {
    const key = `${item.severity}:${item.code}:${item.target}:${item.message}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

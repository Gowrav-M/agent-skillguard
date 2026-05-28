import type { Severity, SkillFinding } from "./schemas.js";

const severityWeights: Record<Severity, number> = {
  info: 0,
  low: 10,
  medium: 25,
  high: 55,
  critical: 90
};

export function severityRank(severity: Severity): number {
  return severityWeights[severity];
}

export function maxSeverity(findings: SkillFinding[]): Severity | undefined {
  return findings.reduce<Severity | undefined>((current, finding) => {
    if (current === undefined || severityRank(finding.severity) > severityRank(current)) {
      return finding.severity;
    }
    return current;
  }, undefined);
}

export function riskScore(findings: SkillFinding[]): number {
  const base = findings.reduce((score, finding) => score + severityWeights[finding.severity], 0);
  return Math.min(100, base);
}

export function meetsThreshold(findings: SkillFinding[], threshold: Severity | undefined): boolean {
  if (threshold === undefined) {
    return false;
  }
  return findings.some((finding) => severityRank(finding.severity) >= severityRank(threshold));
}

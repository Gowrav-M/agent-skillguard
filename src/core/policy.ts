import { dirname, resolve } from "node:path";
import { stat } from "node:fs/promises";
import { defaultLockPathForSkill, readSkillLock, verifySkillLock } from "./lockfile.js";
import { severityRank } from "./risk.js";
import {
  skillAdmissionDecisionSchema,
  skillGuardPolicySchema,
  type AdmissionReason,
  type SkillAdmissionDecision,
  type SkillGuardPolicy,
  type SkillGuardReport
} from "./schemas.js";

export function defaultSkillGuardPolicy(): SkillGuardPolicy {
  return skillGuardPolicySchema.parse({
    schemaVersion: 1,
    blockOnSeverity: "critical",
    deniedCapabilities: ["secret-access", "mcp-tool-mutation"],
    requireLockfile: false,
    requireCleanScan: false,
    allowInstallScripts: false
  });
}

export function evaluateAdmission(report: SkillGuardReport, policyInput: SkillGuardPolicy = defaultSkillGuardPolicy()): SkillAdmissionDecision {
  const policy = skillGuardPolicySchema.parse(policyInput);
  const reasons: AdmissionReason[] = [];
  const blockThreshold = severityRank(policy.blockOnSeverity);

  for (const finding of report.findings) {
    if (severityRank(finding.severity) >= blockThreshold) {
      reasons.push({
        severity: finding.severity,
        code: `finding.${finding.category}`,
        message: finding.title,
        target: finding.target
      });
    }

    if (!policy.allowInstallScripts && finding.category === "package.lifecycle_script") {
      reasons.push({
        severity: "high",
        code: "policy.install_script",
        message: "Install lifecycle scripts are blocked by policy.",
        target: finding.target
      });
    }
  }

  for (const skill of report.bom.skills) {
    for (const capability of skill.capabilities) {
      if (policy.deniedCapabilities.includes(capability)) {
        reasons.push({
          severity: "critical",
          code: `capability.${capability}`,
          message: `Capability ${capability} is denied by policy.`,
          target: skill.manifest.name
        });
      }
    }
  }

  if (policy.requireCleanScan && report.findings.length > 0) {
    reasons.push({
      severity: "high",
      code: "policy.require_clean_scan",
      message: "Policy requires zero scanner findings.",
      target: "scan"
    });
  }

  const decision = reasons.some((reason) => severityRank(reason.severity) >= severityRank("high")) ? "block" : report.findings.length > 0 ? "review" : "allow";

  return skillAdmissionDecisionSchema.parse({
    generatedAt: report.generatedAt,
    decision,
    summary: {
      skills: report.summary.skills,
      findings: report.summary.findings,
      riskScore: report.summary.riskScore
    },
    policy,
    reasons: dedupeReasons(reasons),
    report
  });
}

export async function evaluateAdmissionWithOptionalLock(inputPath: string, report: SkillGuardReport, policy: SkillGuardPolicy): Promise<SkillAdmissionDecision> {
  const decision = evaluateAdmission(report, policy);

  if (!policy.requireLockfile) {
    return decision;
  }

  const lockReasons: AdmissionReason[] = [];
  for (const skill of report.bom.skills) {
    const root = resolve(skill.root);
    const lockPath = defaultLockPathForSkill(root);
    try {
      await stat(lockPath);
      const lock = await readSkillLock(lockPath);
      const result = await verifySkillLock(root, lock);
      for (const finding of result.findings) {
        lockReasons.push({
          severity: finding.severity,
          code: `lock.${finding.category}`,
          message: finding.title,
          target: finding.target
        });
      }
    } catch {
      lockReasons.push({
        severity: "critical",
        code: "policy.require_lockfile",
        message: "Policy requires a valid skillguard.lock.json for each admitted skill.",
        target: `${dirname(inputPath)}/${skill.manifest.name}`
      });
    }
  }

  const reasons = dedupeReasons([...decision.reasons, ...lockReasons]);
  const finalDecision = reasons.some((reason) => severityRank(reason.severity) >= severityRank("high")) ? "block" : decision.decision;

  return skillAdmissionDecisionSchema.parse({
    ...decision,
    decision: finalDecision,
    reasons
  });
}

function dedupeReasons(reasons: AdmissionReason[]): AdmissionReason[] {
  const seen = new Set<string>();
  return reasons.filter((reason) => {
    const key = `${reason.code}:${reason.target}:${reason.message}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

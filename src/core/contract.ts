import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { writeJsonFile } from "./files.js";
import { severityRank } from "./risk.js";
import {
  skillContractDecisionSchema,
  type AdmissionReason,
  type SkillCapability,
  type SkillContractDecision,
  type SkillGuardReport
} from "./schemas.js";

const highRiskCapabilities = new Set<SkillCapability>([
  "network",
  "shell",
  "filesystem-write",
  "git-write",
  "mcp-tool-mutation",
  "package-install",
  "secret-access"
]);

export function evaluateCapabilityContracts(report: SkillGuardReport): SkillContractDecision {
  const reasons: AdmissionReason[] = [];
  const contracts = report.bom.skills.map((skill) => {
    const declared = [...skill.manifest.declaredCapabilities].sort();
    const observed = [...skill.observedCapabilities].sort();
    const undeclaredCapabilities = difference(observed, declared);
    const unusedDeclarations = difference(declared, observed);

    for (const capability of undeclaredCapabilities) {
      const severity = highRiskCapabilities.has(capability) ? "critical" : "high";
      reasons.push({
        severity,
        code: `contract.undeclared.${capability}`,
        message: `Observed capability ${capability} is not declared by the skill.`,
        target: skill.manifest.name
      });
    }

    return {
      skillName: skill.manifest.name,
      declaredCapabilities: declared,
      observedCapabilities: observed,
      undeclaredCapabilities,
      unusedDeclarations
    };
  });

  const dedupedReasons = dedupeReasons(reasons);
  const decision = dedupedReasons.some((reason) => severityRank(reason.severity) >= severityRank("high"))
    ? "block"
    : "allow";

  return skillContractDecisionSchema.parse({
    generatedAt: report.generatedAt,
    decision,
    summary: {
      skills: contracts.length,
      violations: dedupedReasons.length,
      undeclaredCapabilities: contracts.reduce((count, contract) => count + contract.undeclaredCapabilities.length, 0)
    },
    contracts,
    reasons: dedupedReasons,
    report
  });
}

export function renderContractMarkdown(decision: SkillContractDecision): string {
  const lines = [
    "# SkillGuard Capability Contract",
    "",
    `Decision: **${decision.decision.toUpperCase()}**`,
    "",
    `- Skills: ${decision.summary.skills}`,
    `- Violations: ${decision.summary.violations}`,
    `- Undeclared capabilities: ${decision.summary.undeclaredCapabilities}`,
    "",
    "## Contracts",
    ""
  ];

  for (const contract of decision.contracts) {
    lines.push(`### ${contract.skillName}`);
    lines.push("");
    lines.push(`- Declared: ${contract.declaredCapabilities.join(", ") || "none"}`);
    lines.push(`- Observed: ${contract.observedCapabilities.join(", ") || "none"}`);
    lines.push(`- Undeclared: ${contract.undeclaredCapabilities.join(", ") || "none"}`);
    lines.push(`- Unused declarations: ${contract.unusedDeclarations.join(", ") || "none"}`);
    lines.push("");
  }

  lines.push("## Reasons", "");
  if (decision.reasons.length === 0) {
    lines.push("No contract violations.");
  } else {
    for (const reason of decision.reasons) {
      lines.push(`- [${reason.severity.toUpperCase()}] ${reason.code} at \`${reason.target}\`: ${reason.message}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export async function writeContractArtifacts(decision: SkillContractDecision, reportsDir: string): Promise<string[]> {
  const jsonPath = join(reportsDir, "skillguard-contract.json");
  const markdownPath = join(reportsDir, "skillguard-contract.md");
  await writeJsonFile(jsonPath, decision);
  await writeFile(markdownPath, renderContractMarkdown(decision), "utf8");
  return [jsonPath, markdownPath];
}

function difference<T extends string>(left: readonly T[], right: readonly T[]): T[] {
  const rightSet = new Set(right);
  return left.filter((item) => !rightSet.has(item)).sort();
}

function dedupeReasons(reasons: AdmissionReason[]): AdmissionReason[] {
  const seen = new Set<string>();
  return reasons.filter((reason) => {
    const key = `${reason.severity}:${reason.code}:${reason.target}:${reason.message}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

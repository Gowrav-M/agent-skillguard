import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fingerprintFile, listFiles, sha256, writeJsonFile } from "./files.js";
import { scanSkillPath } from "./scanner.js";
import {
  skillProvenanceSchema,
  skillTrustDecisionSchema,
  skillTrustPolicySchema,
  type AdmissionReason,
  type SkillProvenance,
  type SkillTrustDecision,
  type SkillTrustPolicy
} from "./schemas.js";

export interface CreateSkillProvenanceOptions {
  sourceUri: string;
  sourceRef?: string;
  sourceCommit?: string;
  publisher?: string;
  generatedAt?: string;
}

export function defaultSkillTrustPolicy(): SkillTrustPolicy {
  return skillTrustPolicySchema.parse({
    schemaVersion: 1,
    allowedHosts: ["github.com"],
    allowedPublishers: [],
    requirePinnedCommit: true,
    denyMutableRefs: true
  });
}

export async function createSkillProvenance(skillDir: string, options: CreateSkillProvenanceOptions): Promise<SkillProvenance> {
  const report = await scanSkillPath(skillDir, options.generatedAt === undefined ? {} : { generatedAt: options.generatedAt });
  const skill = report.bom.skills[0];
  if (skill === undefined) {
    throw new Error(`No skill found at ${skillDir}.`);
  }

  const source = parseSourceUri(options.sourceUri);
  const digestMaterial = [];
  for (const path of await listFiles(skill.root)) {
    const file = await fingerprintFile(skill.root, path);
    if (file.path === "skillguard.provenance.json") {
      continue;
    }
    digestMaterial.push(`${file.path}:${file.sha256}`);
  }

  return skillProvenanceSchema.parse({
    schemaVersion: 1,
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    skillName: skill.manifest.name,
    sourceUri: options.sourceUri,
    sourceHost: source.host,
    sourceOwner: source.owner,
    sourceRepo: source.repo,
    sourceRef: options.sourceRef ?? source.ref,
    sourceCommit: options.sourceCommit,
    publisher: options.publisher,
    skillDigest: `sha256:${sha256(digestMaterial.sort().join("\n"))}`
  });
}

export function evaluateSkillTrust(provenance: SkillProvenance, policyInput: SkillTrustPolicy = defaultSkillTrustPolicy()): SkillTrustDecision {
  const policy = skillTrustPolicySchema.parse(policyInput);
  const reasons: AdmissionReason[] = [];

  if (!policy.allowedHosts.includes(provenance.sourceHost)) {
    reasons.push(reason("critical", "provenance.unapproved_host", `Source host ${provenance.sourceHost} is not allowed by policy.`, provenance.sourceUri));
  }

  if (policy.requirePinnedCommit && provenance.sourceCommit === undefined) {
    reasons.push(reason("critical", "provenance.missing_commit_pin", "Skill source is not pinned to an immutable commit.", provenance.sourceUri));
  }

  if (provenance.sourceCommit !== undefined && !/^[a-f0-9]{40}$/i.test(provenance.sourceCommit)) {
    reasons.push(reason("high", "provenance.invalid_commit_pin", "Source commit is not a full 40-character Git commit hash.", provenance.sourceCommit));
  }

  if (policy.denyMutableRefs && provenance.sourceCommit === undefined && provenance.sourceRef !== undefined && isMutableRef(provenance.sourceRef)) {
    reasons.push(reason("high", "provenance.mutable_ref", `Source ref ${provenance.sourceRef} is mutable.`, provenance.sourceUri));
  }

  if (policy.allowedPublishers.length > 0 && (provenance.publisher === undefined || !policy.allowedPublishers.includes(provenance.publisher))) {
    reasons.push(reason("critical", "provenance.unapproved_publisher", `Publisher ${provenance.publisher ?? "unknown"} is not in the allowlist.`, provenance.publisher ?? "unknown"));
  }

  if (provenance.publisher === undefined) {
    reasons.push(reason("medium", "provenance.missing_publisher", "No publisher identity was recorded for this skill.", provenance.sourceUri));
  }

  const decision = reasons.some((item) => item.severity === "critical" || item.severity === "high")
    ? "block"
    : reasons.length > 0
      ? "review"
      : "allow";

  return skillTrustDecisionSchema.parse({
    generatedAt: provenance.generatedAt,
    decision,
    provenance,
    policy,
    reasons
  });
}

export function renderTrustMarkdown(decision: SkillTrustDecision): string {
  const lines = [
    "# SkillGuard Trust Decision",
    "",
    `Decision: **${decision.decision.toUpperCase()}**`,
    "",
    `- Skill: ${decision.provenance.skillName}`,
    `- Source: ${decision.provenance.sourceUri}`,
    `- Host: ${decision.provenance.sourceHost}`,
    `- Publisher: ${decision.provenance.publisher ?? "unknown"}`,
    `- Commit: ${decision.provenance.sourceCommit ?? "not pinned"}`,
    `- Digest: ${decision.provenance.skillDigest}`,
    "",
    "## Reasons",
    ""
  ];

  if (decision.reasons.length === 0) {
    lines.push("No trust policy violations.");
  } else {
    for (const item of decision.reasons) {
      lines.push(`- [${item.severity.toUpperCase()}] ${item.code} at \`${item.target}\`: ${item.message}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export async function writeTrustArtifacts(decision: SkillTrustDecision, reportsDir: string): Promise<string[]> {
  const jsonPath = join(reportsDir, "skillguard-trust.json");
  const markdownPath = join(reportsDir, "skillguard-trust.md");
  await writeJsonFile(jsonPath, decision);
  await writeFile(markdownPath, renderTrustMarkdown(decision), "utf8");
  return [jsonPath, markdownPath];
}

function parseSourceUri(sourceUri: string): { host: string; owner?: string; repo?: string; ref?: string } {
  try {
    const url = new URL(sourceUri);
    const parts = url.pathname.split("/").filter(Boolean);
    const refIndex = parts.findIndex((part) => part === "tree" || part === "blob");
    const result: { host: string; owner?: string; repo?: string; ref?: string } = {
      host: url.host.toLowerCase()
    };
    if (parts[0] !== undefined) result.owner = parts[0];
    if (parts[1] !== undefined) result.repo = parts[1].replace(/\.git$/i, "");
    const parsedRef = refIndex >= 0 ? parts[refIndex + 1] : undefined;
    if (parsedRef !== undefined) result.ref = parsedRef;
    return result;
  } catch {
    return { host: "local" };
  }
}

function isMutableRef(ref: string): boolean {
  if (/^[a-f0-9]{40}$/i.test(ref)) {
    return false;
  }
  if (/^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/i.test(ref)) {
    return false;
  }
  return true;
}

function reason(severity: AdmissionReason["severity"], code: string, message: string, target: string): AdmissionReason {
  return { severity, code, message, target };
}

import { copyFile, readFile, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { ensureDir, sha256, writeJsonFile } from "./files.js";
import { createSkillLock } from "./lockfile.js";
import { packSkillBundle } from "./pack.js";
import { evaluateCapabilityContracts } from "./contract.js";
import { defaultSkillGuardPolicy, evaluateAdmission } from "./policy.js";
import { createSkillProvenance, defaultSkillTrustPolicy, evaluateSkillTrust } from "./provenance.js";
import { scanSkillPath } from "./scanner.js";
import {
  skillPassportSchema,
  skillPassportVerificationSchema,
  type AdmissionReason,
  type SkillPassport,
  type SkillPassportVerification
} from "./schemas.js";

export interface CreateSkillPassportOptions {
  sourceUri: string;
  sourceCommit?: string;
  sourceRef?: string;
  publisher?: string;
  generatedAt?: string;
  outputDir?: string;
  pack?: boolean;
}

export async function createSkillPassport(skillDir: string, options: CreateSkillPassportOptions): Promise<SkillPassport> {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const absoluteSkillDir = resolve(skillDir);
  const scan = await scanSkillPath(absoluteSkillDir, { generatedAt });
  const skill = scan.bom.skills[0];
  if (skill === undefined) {
    throw new Error(`No skill found at ${skillDir}.`);
  }

  const provenanceOptions: Parameters<typeof createSkillProvenance>[1] = {
    sourceUri: options.sourceUri,
    generatedAt
  };
  if (options.sourceCommit !== undefined) provenanceOptions.sourceCommit = options.sourceCommit;
  if (options.sourceRef !== undefined) provenanceOptions.sourceRef = options.sourceRef;
  if (options.publisher !== undefined) provenanceOptions.publisher = options.publisher;

  const source = await createSkillProvenance(absoluteSkillDir, provenanceOptions);
  const trust = evaluateSkillTrust(source, defaultSkillTrustPolicy());
  const contract = evaluateCapabilityContracts(scan);
  const admission = evaluateAdmission(scan, defaultSkillGuardPolicy());
  const lock = await createSkillLock(absoluteSkillDir, { generatedAt });
  const lockDigest = `sha256:${sha256(JSON.stringify(lock))}`;

  const outputDir = options.outputDir ?? defaultPassportOutputDir(process.cwd(), skill.manifest.name);
  const artifacts = [
    join(outputDir, "passport.json"),
    join(outputDir, "passport.md"),
    join(outputDir, "passport.html"),
    join(outputDir, "skillguard.lock.json")
  ];

  let bundleDigest: string | undefined;
  if (options.pack === true) {
    const bundlePath = join(outputDir, `${safeFileName(skill.manifest.name)}.skill.tgz`);
    const bundle = await packSkillBundle(absoluteSkillDir, bundlePath);
    bundleDigest = `sha256:${bundle.sha256}`;
    artifacts.push(bundle.path);
  }

  const decision = [trust.decision, contract.decision, admission.decision].includes("block")
    ? "block"
    : [trust.decision, contract.decision, admission.decision].includes("review")
      ? "review"
      : "allow";

  const passport = {
    schemaVersion: 1,
    generatedAt,
    skillName: skill.manifest.name,
    decision,
    source,
    digests: bundleDigest === undefined
      ? {
          skillDigest: source.skillDigest,
          lockDigest
        }
      : {
          skillDigest: source.skillDigest,
          lockDigest,
          bundleDigest
        },
    summary: {
      riskScore: scan.summary.riskScore,
      findings: scan.summary.findings,
      capabilityViolations: contract.summary.violations,
      admissionReasons: admission.reasons.length,
      trustReasons: trust.reasons.length,
      decisionReasons: trust.reasons.length + contract.reasons.length + admission.reasons.length
    },
    artifacts,
    embedded: {
      scan,
      trust,
      contract,
      admission,
      lock
    }
  };

  return skillPassportSchema.parse(passport);
}

export async function writePassportArtifacts(passport: SkillPassport, outputDir: string): Promise<string[]> {
  await ensureDir(outputDir);
  const jsonPath = join(outputDir, "passport.json");
  const markdownPath = join(outputDir, "passport.md");
  const htmlPath = join(outputDir, "passport.html");
  const lockPath = join(outputDir, "skillguard.lock.json");

  await writeJsonFile(jsonPath, passport);
  await writeFile(markdownPath, renderPassportMarkdown(passport), "utf8");
  await writeFile(htmlPath, renderPassportHtml(passport), "utf8");
  await writeJsonFile(lockPath, passport.embedded.lock);

  const artifacts = [jsonPath, markdownPath, htmlPath, lockPath];
  const bundleArtifact = passport.artifacts.find((artifact) => artifact.endsWith(".skill.tgz"));
  if (bundleArtifact !== undefined) {
    const destination = join(outputDir, basename(bundleArtifact));
    if (resolve(bundleArtifact) !== resolve(destination)) {
      await copyFile(bundleArtifact, destination);
    }
    artifacts.push(destination);
  }

  return artifacts;
}

export interface VerifySkillPassportOptions {
  skillDir?: string;
  bundlePath?: string;
  generatedAt?: string;
}

export async function readSkillPassport(passportPath: string): Promise<SkillPassport> {
  return skillPassportSchema.parse(JSON.parse(await readFile(passportPath, "utf8")));
}

export async function verifySkillPassport(passport: SkillPassport, options: VerifySkillPassportOptions = {}): Promise<SkillPassportVerification> {
  const reasons: AdmissionReason[] = [];
  const checked: SkillPassportVerification["checked"] = {
    schema: true,
    lockDigest: true,
    decisionConsistency: true
  };

  const expectedLockDigest = `sha256:${sha256(JSON.stringify(passport.embedded.lock))}`;
  if (expectedLockDigest !== passport.digests.lockDigest) {
    checked.lockDigest = false;
    reasons.push(verificationReason("critical", "passport.lock_digest_mismatch", "Embedded lock digest does not match passport digest.", passport.skillName));
  }

  if (options.skillDir !== undefined) {
    const provenanceOptions: Parameters<typeof createSkillProvenance>[1] = {
      sourceUri: passport.source.sourceUri,
      generatedAt: passport.generatedAt
    };
    if (passport.source.sourceCommit !== undefined) provenanceOptions.sourceCommit = passport.source.sourceCommit;
    if (passport.source.sourceRef !== undefined) provenanceOptions.sourceRef = passport.source.sourceRef;
    if (passport.source.publisher !== undefined) provenanceOptions.publisher = passport.source.publisher;
    const recreated = await createSkillProvenance(options.skillDir, provenanceOptions);
    checked.skillDigest = recreated.skillDigest === passport.digests.skillDigest;
    if (!checked.skillDigest) {
      reasons.push(verificationReason("critical", "passport.skill_digest_mismatch", "Current skill digest does not match the passport-approved digest.", options.skillDir));
    }
  }

  if (options.bundlePath !== undefined) {
    const bundleDigest = `sha256:${sha256(await readFile(options.bundlePath))}`;
    checked.bundleDigest = bundleDigest === passport.digests.bundleDigest;
    if (!checked.bundleDigest) {
      reasons.push(verificationReason("critical", "passport.bundle_digest_mismatch", "Bundle digest does not match the passport-approved digest.", options.bundlePath));
    }
  }

  const expectedDecision = [passport.embedded.trust.decision, passport.embedded.contract.decision, passport.embedded.admission.decision].includes("block")
    ? "block"
    : [passport.embedded.trust.decision, passport.embedded.contract.decision, passport.embedded.admission.decision].includes("review")
      ? "review"
      : "allow";
  checked.decisionConsistency = expectedDecision === passport.decision;
  if (!checked.decisionConsistency) {
    reasons.push(verificationReason("high", "passport.decision_mismatch", "Passport decision does not match embedded control decisions.", passport.skillName));
  }

  return skillPassportVerificationSchema.parse({
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    valid: reasons.length === 0,
    passportDecision: passport.decision,
    checked,
    reasons,
    passport
  });
}

export function renderPassportVerificationMarkdown(verification: SkillPassportVerification): string {
  const lines = [
    "# Skill Passport Verification",
    "",
    `Valid: **${verification.valid ? "YES" : "NO"}**`,
    "",
    `- Passport decision: ${verification.passportDecision.toUpperCase()}`,
    `- Schema: ${verification.checked.schema ? "ok" : "failed"}`,
    `- Lock digest: ${verification.checked.lockDigest ? "ok" : "failed"}`,
    `- Skill digest: ${verification.checked.skillDigest === undefined ? "not checked" : verification.checked.skillDigest ? "ok" : "failed"}`,
    `- Bundle digest: ${verification.checked.bundleDigest === undefined ? "not checked" : verification.checked.bundleDigest ? "ok" : "failed"}`,
    `- Decision consistency: ${verification.checked.decisionConsistency ? "ok" : "failed"}`,
    "",
    "## Reasons",
    ""
  ];

  if (verification.reasons.length === 0) {
    lines.push("No verification failures.");
  } else {
    for (const reason of verification.reasons) {
      lines.push(`- [${reason.severity.toUpperCase()}] ${reason.code} at \`${reason.target}\`: ${reason.message}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export async function writePassportVerificationArtifacts(verification: SkillPassportVerification, reportsDir: string): Promise<string[]> {
  await ensureDir(reportsDir);
  const jsonPath = join(reportsDir, "passport-verification.json");
  const markdownPath = join(reportsDir, "passport-verification.md");
  await writeJsonFile(jsonPath, verification);
  await writeFile(markdownPath, renderPassportVerificationMarkdown(verification), "utf8");
  return [jsonPath, markdownPath];
}

export function renderPassportMarkdown(passport: SkillPassport): string {
  const lines = [
    "# Skill Passport",
    "",
    `Decision: **${passport.decision.toUpperCase()}**`,
    "",
    `- Skill: ${passport.skillName}`,
    `- Generated: ${passport.generatedAt}`,
    `- Source: ${passport.source.sourceUri}`,
    `- Publisher: ${passport.source.publisher ?? "unknown"}`,
    `- Commit: ${passport.source.sourceCommit ?? "not pinned"}`,
    `- Skill digest: ${passport.digests.skillDigest}`,
    `- Lock digest: ${passport.digests.lockDigest}`,
    `- Bundle digest: ${passport.digests.bundleDigest ?? "not packed"}`,
    "",
    "## Summary",
    "",
    `- Risk score: ${passport.summary.riskScore}/100`,
    `- Findings: ${passport.summary.findings}`,
    `- Capability violations: ${passport.summary.capabilityViolations}`,
    `- Trust reasons: ${passport.summary.trustReasons}`,
    `- Admission reasons: ${passport.summary.admissionReasons}`,
    `- Decision reasons: ${passport.summary.decisionReasons}`,
    "",
    "## Embedded Decisions",
    "",
    `- Trust: ${passport.embedded.trust.decision.toUpperCase()}`,
    `- Contract: ${passport.embedded.contract.decision.toUpperCase()}`,
    `- Admission: ${passport.embedded.admission.decision.toUpperCase()}`,
    "",
    "## Artifacts",
    ""
  ];

  for (const artifact of passport.artifacts) {
    lines.push(`- ${artifact}`);
  }

  return `${lines.join("\n")}\n`;
}

export function renderPassportHtml(passport: SkillPassport): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Skill Passport - ${escapeHtml(passport.skillName)}</title>
  <style>
    body { font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f7f9fb; color: #17202a; }
    main { max-width: 980px; margin: 0 auto; padding: 40px 20px; }
    section { background: #fff; border: 1px solid #d7dee8; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
    .decision { font-size: 28px; font-weight: 700; }
    .allow { color: #047857; }
    .review { color: #b45309; }
    .block { color: #b42318; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
    .metric { background: #f7f9fb; border: 1px solid #d7dee8; border-radius: 8px; padding: 14px; }
    code { background: #eef2f7; padding: 2px 5px; border-radius: 4px; }
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Skill Passport</h1>
      <p class="decision ${passport.decision}">${passport.decision.toUpperCase()}</p>
      <p><strong>${escapeHtml(passport.skillName)}</strong></p>
      <p><code>${escapeHtml(passport.source.sourceUri)}</code></p>
    </section>
    <section class="grid">
      <div class="metric"><strong>${passport.summary.riskScore}/100</strong><br>Risk score</div>
      <div class="metric"><strong>${passport.summary.findings}</strong><br>Findings</div>
      <div class="metric"><strong>${passport.summary.capabilityViolations}</strong><br>Capability violations</div>
      <div class="metric"><strong>${passport.summary.decisionReasons}</strong><br>Decision reasons</div>
    </section>
    <section>
      <h2>Evidence</h2>
      <p>Skill digest: <code>${passport.digests.skillDigest}</code></p>
      <p>Lock digest: <code>${passport.digests.lockDigest}</code></p>
      <p>Bundle digest: <code>${passport.digests.bundleDigest ?? "not packed"}</code></p>
    </section>
    <section>
      <h2>Embedded Decisions</h2>
      <ul>
        <li>Trust: ${passport.embedded.trust.decision.toUpperCase()}</li>
        <li>Contract: ${passport.embedded.contract.decision.toUpperCase()}</li>
        <li>Admission: ${passport.embedded.admission.decision.toUpperCase()}</li>
      </ul>
    </section>
  </main>
</body>
</html>
`;
}

export function defaultPassportOutputDir(cwd: string, skillName: string): string {
  return join(cwd, ".skillguard", "passports", safeFileName(skillName));
}

function safeFileName(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "skill";
}

function verificationReason(severity: AdmissionReason["severity"], code: string, message: string, target: string): AdmissionReason {
  return { severity, code, message, target };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

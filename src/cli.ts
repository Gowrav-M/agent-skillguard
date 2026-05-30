#!/usr/bin/env node
import { access, readFile, stat, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command, InvalidArgumentError } from "commander";
import { analyzeSkillAttackGraph, writeAttackGraphArtifacts } from "./core/attackGraph.js";
import { createRiskBaseline, readRiskBaseline, renderRiskBaselineMarkdown, triageSkillRisk, writeRiskBaseline, writeRiskTriageArtifacts } from "./core/baseline.js";
import { evaluateCapabilityContracts, writeContractArtifacts } from "./core/contract.js";
import { ensureDir, readJsonFile, writeJsonFile } from "./core/files.js";
import { reviewSkillIntent, writeIntentArtifacts } from "./core/intent.js";
import { createSkillLock, defaultLockPathForSkill, readSkillLock, verifySkillLock, writeSkillLock } from "./core/lockfile.js";
import { packSkillBundle, verifySkillBundle } from "./core/pack.js";
import { createSkillPassport, defaultPassportOutputDir, readSkillPassport, verifySkillPassport, writePassportArtifacts, writePassportVerificationArtifacts } from "./core/passport.js";
import { defaultSkillGuardPolicy, evaluateAdmissionWithOptionalLock } from "./core/policy.js";
import { createSkillProvenance, defaultSkillTrustPolicy, evaluateSkillTrust, writeTrustArtifacts } from "./core/provenance.js";
import { renderHtmlReport, renderMarkdownReport, renderSarifReport } from "./core/report.js";
import { meetsThreshold } from "./core/risk.js";
import { scanSkillPath } from "./core/scanner.js";
import { severitySchema, skillGuardPolicySchema, skillGuardReportSchema, type Severity, type SkillAdmissionDecision, type SkillFinding, type SkillGuardPolicy, type SkillGuardReport } from "./core/schemas.js";
import { createSkillGuardTrustEvidence, trustEvidencePath } from "./core/trustEvidence.js";
import { reviewSkillUpdate, writeUpdateReviewArtifacts } from "./core/updateReview.js";

const version = "1.1.0";

interface ReportWriteOptions {
  sarif?: boolean;
}

interface ThresholdOptions {
  failOn?: Severity;
}

const program = new Command();

program
  .name("agent-skillguard")
  .description("Local-first supply-chain scanner, packer, lockfile, and verifier for AI agent skills.")
  .version(version);

program
  .command("init")
  .description("Create local .skillguard configuration.")
  .action(async () => {
    const paths = localPaths(process.cwd());
    await ensureDir(paths.reportsDir);
    await writeJsonFile(paths.configPath, {
      schemaVersion: 1,
      policy: {
        failOn: "critical",
        allowNetworkByDefault: false
      }
    });
    console.log(`Initialized ${paths.configPath}`);
  });

program
  .command("demo")
  .description("Scan bundled safe and malicious skill fixtures and write local reports.")
  .option("--no-sarif", "Skip SARIF output.")
  .action(async (options: ReportWriteOptions) => {
    const root = await packageRoot();
    const examplesDir = join(root, "examples", "skills");
    const report = await scanSkillPath(examplesDir);
    const intent = await reviewSkillIntent(examplesDir, { generatedAt: report.generatedAt, report });
    const graph = await analyzeSkillAttackGraph(examplesDir, { generatedAt: report.generatedAt, report, intent });
    const artifacts = [
      ...(await writeReportArtifacts(report, process.cwd(), { sarif: options.sarif !== false })),
      ...(await writeIntentArtifacts(intent, localPaths(process.cwd()).reportsDir)),
      ...(await writeAttackGraphArtifacts(graph, localPaths(process.cwd()).reportsDir))
    ];
    console.log("Demo complete");
    console.log(`Skills scanned: ${report.summary.skills}`);
    console.log(`Findings: ${report.summary.findings}`);
    console.log(`Risk score: ${report.summary.riskScore}/100`);
    console.log(`Intent signals: ${intent.summary.signals}`);
    console.log(`Attack graph paths: ${graph.summary.paths}`);
    console.log("Artifacts:");
    for (const artifact of artifacts) {
      console.log(`- ${artifact}`);
    }
  });

program
  .command("scan")
  .argument("<path>", "Skill directory or directory containing multiple SKILL.md files.")
  .description("Inspect skill folders, manifests, scripts, and bundled tool descriptors.")
  .option("--sarif", "Write SARIF output.", false)
  .option("--fail-on <severity>", "Exit non-zero when this severity or higher is found.", parseSeverity)
  .action(async (path: string, options: ReportWriteOptions & ThresholdOptions) => {
    const report = await scanSkillPath(resolve(process.cwd(), path));
    const artifacts = await writeReportArtifacts(report, process.cwd(), { sarif: options.sarif ?? false });
    console.log(`Scanned ${report.summary.skills} skill(s), ${report.summary.files} file(s).`);
    console.log(`Findings: ${report.summary.findings}, risk score: ${report.summary.riskScore}/100`);
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }
    applyThreshold(report.findings, options.failOn);
  });

program
  .command("admit")
  .argument("<path>", "Skill directory or directory containing multiple SKILL.md files.")
  .description("Run enterprise admission control using policy-as-code.")
  .option("--policy <path>", "Policy JSON path. Defaults to .skillguard/policy.json when present.")
  .option("--require-lock", "Require skillguard.lock.json for each skill.", false)
  .option("--sarif", "Write SARIF output.", false)
  .action(async (path: string, options: { policy?: string; requireLock?: boolean; sarif?: boolean }) => {
    const target = resolve(process.cwd(), path);
    const report = await scanSkillPath(target);
    const basePolicy = await loadPolicy(process.cwd(), options.policy);
    const policy = {
      ...basePolicy,
      requireLockfile: options.requireLock === true || basePolicy.requireLockfile
    };
    const decision = await evaluateAdmissionWithOptionalLock(target, report, policy);
    const artifacts = await writeReportArtifacts(report, process.cwd(), { sarif: options.sarif ?? true });
    const paths = localPaths(process.cwd());
    await writeJsonFile(paths.admissionJson, decision);
    await writeFile(paths.admissionMarkdown, renderAdmissionMarkdown(decision), "utf8");

    console.log(`Admission decision: ${decision.decision.toUpperCase()}`);
    console.log(`Risk score: ${decision.summary.riskScore}/100`);
    console.log(`Reasons: ${decision.reasons.length}`);
    for (const artifact of [...artifacts, paths.admissionJson, paths.admissionMarkdown]) {
      console.log(`Wrote ${artifact}`);
    }

    if (decision.decision === "block") {
      console.error("Admission blocked");
      for (const reason of decision.reasons) {
        console.error(`- [${reason.severity}] ${reason.code}: ${reason.target}`);
      }
      process.exitCode = 1;
    }
  });

program
  .command("review-update")
  .argument("<approved-skill>", "Previously approved skill directory.")
  .argument("<candidate-skill>", "Candidate replacement skill directory.")
  .description("Compare an approved skill with a candidate update and block risky drift.")
  .action(async (approvedSkill: string, candidateSkill: string) => {
    const paths = localPaths(process.cwd());
    const review = await reviewSkillUpdate(resolve(process.cwd(), approvedSkill), resolve(process.cwd(), candidateSkill));
    await ensureDir(paths.reportsDir);
    const artifacts = await writeUpdateReviewArtifacts(review, paths.reportsDir);

    console.log(`Update decision: ${review.decision.toUpperCase()}`);
    console.log(`Risk score: ${review.summary.previousRiskScore}/100 -> ${review.summary.candidateRiskScore}/100`);
    console.log(`Added capabilities: ${review.summary.addedCapabilities.join(", ") || "none"}`);
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }

    if (review.decision === "block") {
      console.error("Update blocked");
      for (const item of review.reasons) {
        console.error(`- [${item.severity}] ${item.code}: ${item.target}`);
      }
      process.exitCode = 1;
    }
  });

program
  .command("trust")
  .argument("<skill-dir>", "Skill directory to evaluate.")
  .requiredOption("--source <uri>", "Source URI for the skill.")
  .option("--commit <sha>", "Immutable source commit hash.")
  .option("--ref <ref>", "Source ref, branch, or tag.")
  .option("--publisher <name>", "Publisher or owner identity.")
  .option("--allow-host <host...>", "Allowed source hosts.")
  .option("--allow-publisher <publisher...>", "Allowed publisher identities.")
  .option("--write", "Write skillguard.provenance.json into the skill directory.", false)
  .description("Evaluate skill provenance and block untrusted mutable sources.")
  .action(async (skillDir: string, options: { source: string; commit?: string; ref?: string; publisher?: string; allowHost?: string[]; allowPublisher?: string[]; write?: boolean }) => {
    const absoluteSkillDir = resolve(process.cwd(), skillDir);
    const paths = localPaths(process.cwd());
    const provenanceOptions: Parameters<typeof createSkillProvenance>[1] = {
      sourceUri: options.source
    };
    if (options.commit !== undefined) provenanceOptions.sourceCommit = options.commit;
    if (options.ref !== undefined) provenanceOptions.sourceRef = options.ref;
    if (options.publisher !== undefined) provenanceOptions.publisher = options.publisher;
    const provenance = await createSkillProvenance(absoluteSkillDir, provenanceOptions);
    const policy = {
      ...defaultSkillTrustPolicy(),
      allowedHosts: options.allowHost ?? defaultSkillTrustPolicy().allowedHosts,
      allowedPublishers: options.allowPublisher ?? defaultSkillTrustPolicy().allowedPublishers
    };
    const decision = evaluateSkillTrust(provenance, policy);
    await ensureDir(paths.reportsDir);
    const artifacts = await writeTrustArtifacts(decision, paths.reportsDir);
    if (options.write === true) {
      const provenancePath = join(absoluteSkillDir, "skillguard.provenance.json");
      await writeJsonFile(provenancePath, provenance);
      artifacts.push(provenancePath);
    }

    console.log(`Trust decision: ${decision.decision.toUpperCase()}`);
    console.log(`Source: ${decision.provenance.sourceUri}`);
    console.log(`Digest: ${decision.provenance.skillDigest}`);
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }

    if (decision.decision === "block") {
      console.error("Trust blocked");
      for (const reason of decision.reasons) {
        console.error(`- [${reason.severity}] ${reason.code}: ${reason.target}`);
      }
      process.exitCode = 1;
    }
  });

program
  .command("contract")
  .argument("<path>", "Skill directory or directory containing multiple SKILL.md files.")
  .description("Enforce least-privilege capability contracts from SKILL.md declarations.")
  .action(async (path: string) => {
    const paths = localPaths(process.cwd());
    const report = await scanSkillPath(resolve(process.cwd(), path));
    const decision = evaluateCapabilityContracts(report);
    await ensureDir(paths.reportsDir);
    const artifacts = await writeContractArtifacts(decision, paths.reportsDir);

    console.log(`Contract decision: ${decision.decision.toUpperCase()}`);
    console.log(`Violations: ${decision.summary.violations}`);
    console.log(`Undeclared capabilities: ${decision.summary.undeclaredCapabilities}`);
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }

    if (decision.decision === "block") {
      console.error("Contract blocked");
      for (const reason of decision.reasons) {
        console.error(`- [${reason.severity}] ${reason.code}: ${reason.target}`);
      }
      process.exitCode = 1;
    }
  });

program
  .command("intent")
  .argument("<path>", "Skill directory or directory containing multiple SKILL.md files.")
  .description("Run the Semantic Intent Firewall against natural-language skill instructions.")
  .option("--fail-on <severity>", "Exit non-zero when this severity or higher is found.", parseSeverity)
  .action(async (path: string, options: ThresholdOptions) => {
    const review = await reviewSkillIntent(resolve(process.cwd(), path));
    const artifacts = await writeIntentArtifacts(review, localPaths(process.cwd()).reportsDir);

    console.log(`Intent decision: ${review.decision.toUpperCase()}`);
    console.log(`Signals: ${review.summary.signals}`);
    console.log(`Risk score: ${review.summary.riskScore}/100`);
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }

    if (review.decision === "block") {
      console.error("Intent blocked");
      for (const signal of review.signals) {
        console.error(`- [${signal.severity}] ${signal.category}: ${signal.target}`);
      }
      process.exitCode = 1;
    }
    applyThreshold(review.signals, options.failOn);
  });

program
  .command("graph")
  .argument("<path>", "Skill directory or directory containing multiple SKILL.md files.")
  .description("Build a SkillSet Attack Graph for cross-skill composition risk.")
  .option("--baseline <path>", "Optional risk baseline. When present, fail-on applies only to unresolved graph paths.")
  .option("--fail-on <severity>", "Exit non-zero when this severity or higher is found.", parseSeverity)
  .action(async (path: string, options: { baseline?: string; failOn?: Severity }) => {
    const paths = localPaths(process.cwd());
    const target = resolve(process.cwd(), path);
    const graph = await analyzeSkillAttackGraph(target);
    const artifacts = await writeAttackGraphArtifacts(graph, paths.reportsDir);
    const thresholdPaths = options.baseline === undefined
      ? graph.paths
      : (await triageSkillRisk(target, await readRiskBaseline(resolve(process.cwd(), options.baseline)), { generatedAt: graph.generatedAt })).unresolvedGraphPaths;

    console.log(`Attack graph decision: ${graph.decision.toUpperCase()}`);
    console.log(`Skills: ${graph.summary.skills}`);
    console.log(`Risk paths: ${graph.summary.paths}`);
    console.log(`Unresolved graph paths: ${thresholdPaths.length}`);
    console.log(`Risk score: ${graph.summary.riskScore}/100`);
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }

    if (meetsThreshold(thresholdPaths, options.failOn)) {
      console.error("Attack graph blocked");
      for (const pathFinding of thresholdPaths) {
        console.error(`- [${pathFinding.severity}] ${pathFinding.category}: ${pathFinding.target}`);
      }
    }
    applyThreshold(thresholdPaths, options.failOn);
  });

program
  .command("baseline")
  .argument("<path>", "Skill directory or directory containing multiple SKILL.md files.")
  .requiredOption("--reason <text>", "Reason this current risk set is accepted.")
  .option("--expires <date>", "Optional expiration date for accepted entries.")
  .option("-o, --output <path>", "Baseline output path. Defaults to .skillguard/baseline.json.")
  .description("Create an auditable risk baseline from current scan and intent results.")
  .action(async (path: string, options: { reason: string; expires?: string; output?: string }) => {
    const paths = localPaths(process.cwd());
    const baselineOptions: Parameters<typeof createRiskBaseline>[1] = {
      reason: options.reason
    };
    if (options.expires !== undefined) baselineOptions.expiresAt = options.expires;
    const baseline = await createRiskBaseline(resolve(process.cwd(), path), baselineOptions);
    const outputPath = resolve(process.cwd(), options.output ?? paths.baselineJson);
    await writeRiskBaseline(baseline, outputPath);
    await ensureDir(paths.reportsDir);
    await writeFile(paths.baselineMarkdown, renderRiskBaselineMarkdown(baseline), "utf8");

    console.log(`Baseline accepted ${baseline.accepted.length} risk entries`);
    console.log(`Wrote ${outputPath}`);
    console.log(`Wrote ${paths.baselineMarkdown}`);
  });

program
  .command("triage")
  .argument("<path>", "Skill directory or directory containing multiple SKILL.md files.")
  .requiredOption("--baseline <path>", "Risk baseline JSON file.")
  .option("--fail-on <severity>", "Exit non-zero when this severity or higher is unresolved.", parseSeverity)
  .description("Compare current scan and intent results against an accepted risk baseline.")
  .action(async (path: string, options: { baseline: string; failOn?: Severity }) => {
    const paths = localPaths(process.cwd());
    const baseline = await readRiskBaseline(resolve(process.cwd(), options.baseline));
    const triage = await triageSkillRisk(resolve(process.cwd(), path), baseline);
    const artifacts = await writeRiskTriageArtifacts(triage, paths.reportsDir);
    const unresolved = [...triage.unresolvedFindings, ...triage.unresolvedIntentSignals];

    console.log(`Triage decision: ${triage.decision.toUpperCase()}`);
    console.log(`Accepted risks: ${triage.summary.accepted}`);
    console.log(`Unresolved risks: ${triage.summary.unresolved}`);
    console.log(`Risk score: ${triage.summary.riskScore}/100`);
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }
    if (triage.decision === "block") {
      console.error("Triage blocked");
      for (const finding of unresolved) {
        console.error(`- [${finding.severity}] ${finding.category}: ${finding.target}`);
      }
      process.exitCode = 1;
    }
    applyThreshold(unresolved, options.failOn);
  });

program
  .command("passport")
  .argument("<skill-dir>", "Skill directory to approve.")
  .requiredOption("--source <uri>", "Source URI for the skill.")
  .option("--commit <sha>", "Immutable source commit hash.")
  .option("--ref <ref>", "Source ref, branch, or tag.")
  .option("--publisher <name>", "Publisher or owner identity.")
  .option("--output <path>", "Passport output directory.")
  .option("--pack", "Create a deterministic .skill.tgz in the passport directory.", false)
  .description("Create a portable enterprise approval artifact for a skill.")
  .action(async (skillDir: string, options: { source: string; commit?: string; ref?: string; publisher?: string; output?: string; pack?: boolean }) => {
    const absoluteSkillDir = resolve(process.cwd(), skillDir);
    const passportOptions: Parameters<typeof createSkillPassport>[1] = {
      sourceUri: options.source,
      pack: options.pack === true
    };
    if (options.commit !== undefined) passportOptions.sourceCommit = options.commit;
    if (options.ref !== undefined) passportOptions.sourceRef = options.ref;
    if (options.publisher !== undefined) passportOptions.publisher = options.publisher;
    if (options.output !== undefined) passportOptions.outputDir = resolve(process.cwd(), options.output);

    const passport = await createSkillPassport(absoluteSkillDir, passportOptions);
    const outputDir = passportOptions.outputDir ?? defaultPassportOutputDir(process.cwd(), passport.skillName);
    const artifacts = await writePassportArtifacts(passport, outputDir);

    console.log(`Passport decision: ${passport.decision.toUpperCase()}`);
    console.log(`Skill: ${passport.skillName}`);
    console.log(`Risk score: ${passport.summary.riskScore}/100`);
    console.log(`Decision reasons: ${passport.summary.decisionReasons}`);
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }

    if (passport.decision === "block") {
      console.error("Passport blocked");
      process.exitCode = 1;
    }
  });

program
  .command("verify-passport")
  .argument("<passport-json>", "Passport JSON file to verify.")
  .option("--skill-dir <path>", "Current skill directory to compare with the passport digest.")
  .option("--bundle <path>", "Skill bundle to compare with the passport bundle digest.")
  .description("Verify that a Skill Passport still matches its approved evidence.")
  .action(async (passportJson: string, options: { skillDir?: string; bundle?: string }) => {
    const passport = await readSkillPassport(resolve(process.cwd(), passportJson));
    const verificationOptions: Parameters<typeof verifySkillPassport>[1] = {};
    if (options.skillDir !== undefined) verificationOptions.skillDir = resolve(process.cwd(), options.skillDir);
    if (options.bundle !== undefined) verificationOptions.bundlePath = resolve(process.cwd(), options.bundle);
    const verification = await verifySkillPassport(passport, verificationOptions);
    const artifacts = await writePassportVerificationArtifacts(verification, localPaths(process.cwd()).reportsDir);

    if (verification.valid) {
      console.log("Passport verification passed");
    } else {
      console.error("Passport verification failed");
      process.exitCode = 1;
    }
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }
    for (const reason of verification.reasons) {
      console.error(`- [${reason.severity}] ${reason.code}: ${reason.target}`);
    }
  });

program
  .command("policy")
  .description("Create a default enterprise SkillGuard policy.")
  .option("-o, --output <path>", "Policy output path.")
  .action(async (options: { output?: string }) => {
    const paths = localPaths(process.cwd());
    const output = resolve(process.cwd(), options.output ?? paths.policyJson);
    await writeJsonFile(output, defaultSkillGuardPolicy());
    console.log(`Wrote ${output}`);
  });

program
  .command("lock")
  .argument("<path>", "Skill directory.")
  .description("Write skillguard.lock.json with file hashes and declared capabilities.")
  .option("-o, --output <path>", "Lockfile output path.")
  .action(async (path: string, options: { output?: string }) => {
    const skillDir = resolve(process.cwd(), path);
    const outputPath = resolve(process.cwd(), options.output ?? defaultLockPathForSkill(skillDir));
    await writeSkillLock(skillDir, outputPath);
    console.log(`Wrote ${outputPath}`);
  });

program
  .command("pack")
  .argument("<skill-dir>", "Skill directory to package.")
  .description("Create a deterministic .skill.tgz bundle with an embedded lockfile.")
  .option("-o, --output <path>", "Bundle output path.")
  .action(async (skillDir: string, options: { output?: string }) => {
    const absoluteSkillDir = resolve(process.cwd(), skillDir);
    const lock = await createSkillLock(absoluteSkillDir);
    const outputPath = resolve(process.cwd(), options.output ?? `${lock.root}.skill.tgz`);
    const result = await packSkillBundle(absoluteSkillDir, outputPath);
    console.log(`Packed ${result.path}`);
    console.log(`SHA-256 ${result.sha256}`);
  });

program
  .command("verify")
  .argument("<bundle-or-dir>", "Skill bundle or skill directory.")
  .description("Verify hashes, lockfile, manifest, and policy.")
  .option("--lock <path>", "Explicit lockfile path for a skill directory.")
  .option("--fail-on <severity>", "Exit non-zero when this severity or higher is found.", parseSeverity)
  .action(async (input: string, options: { lock?: string; failOn?: Severity }) => {
    const target = resolve(process.cwd(), input);
    const result = target.endsWith(".skill.tgz")
      ? await verifySkillBundle(target)
      : await verifySkillLock(target, await readSkillLock(resolve(process.cwd(), options.lock ?? defaultLockPathForSkill(target))));

    if (result.valid) {
      console.log("Verification passed");
    } else {
      console.error(`Verification failed with ${result.findings.length} finding(s).`);
      for (const finding of result.findings) {
        console.error(`- [${finding.severity}] ${finding.category}: ${finding.target}`);
      }
      process.exitCode = 1;
    }

    applyThreshold(result.findings, options.failOn);
  });

program
  .command("report")
  .description("Render Markdown, HTML, JSON, and optional SARIF from the last scan report.")
  .option("--sarif", "Write SARIF output.", false)
  .action(async (options: ReportWriteOptions) => {
    const paths = localPaths(process.cwd());
    const report = skillGuardReportSchema.parse(await readJsonFile<unknown>(paths.reportJson));
    const artifacts = await writeReportArtifacts(report, process.cwd(), { sarif: options.sarif ?? false });
    for (const artifact of artifacts) {
      console.log(`Wrote ${artifact}`);
    }
  });

program
  .command("doctor")
  .description("Check Node version, writable output folder, config validity, and package setup.")
  .action(async () => {
    const checks = await runDoctor(process.cwd());
    for (const check of checks) {
      console.log(`${check.ok ? "ok" : "fail"} ${check.name}: ${check.message}`);
    }
    if (checks.some((check) => !check.ok)) {
      process.exitCode = 1;
    }
  });

program
  .command("evidence")
  .description("Write normalized Agent Trust Center evidence from the latest SkillGuard report.")
  .action(async () => {
    const paths = localPaths(process.cwd());
    try {
      await access(paths.reportJson, constants.R_OK);
    } catch {
      throw new Error("No SkillGuard report found. Run agent-skillguard demo, scan, or report first.");
    }
    const evidence = await createSkillGuardTrustEvidence({ paths, version });
    const outputPath = trustEvidencePath(paths);
    await writeJsonFile(outputPath, evidence);
    console.log(`Decision: ${evidence.decision.toUpperCase()}`);
    console.log(`Trust evidence: ${outputPath}`);
  });

await program.parseAsync(process.argv);

function parseSeverity(value: string): Severity {
  const parsed = severitySchema.safeParse(value);
  if (!parsed.success) {
    throw new InvalidArgumentError(`Expected one of: ${severitySchema.options.join(", ")}`);
  }
  return parsed.data;
}

function localPaths(cwd: string): { root: string; configPath: string; policyJson: string; baselineJson: string; reportsDir: string; reportJson: string; reportMarkdown: string; reportHtml: string; reportSarif: string; admissionJson: string; admissionMarkdown: string; baselineMarkdown: string } {
  const root = join(cwd, ".skillguard");
  const reportsDir = join(root, "reports");
  return {
    root,
    configPath: join(root, "config.json"),
    policyJson: join(root, "policy.json"),
    baselineJson: join(root, "baseline.json"),
    reportsDir,
    reportJson: join(reportsDir, "skillguard-report.json"),
    reportMarkdown: join(reportsDir, "skillguard-report.md"),
    reportHtml: join(reportsDir, "skillguard-report.html"),
    reportSarif: join(reportsDir, "skillguard-report.sarif"),
    admissionJson: join(reportsDir, "skillguard-admission.json"),
    admissionMarkdown: join(reportsDir, "skillguard-admission.md"),
    baselineMarkdown: join(reportsDir, "skillguard-baseline.md")
  };
}

async function writeReportArtifacts(report: SkillGuardReport, cwd: string, options: ReportWriteOptions): Promise<string[]> {
  const paths = localPaths(cwd);
  await ensureDir(paths.reportsDir);
  await writeJsonFile(paths.reportJson, report);
  await writeFile(paths.reportMarkdown, renderMarkdownReport(report), "utf8");
  await writeFile(paths.reportHtml, renderHtmlReport(report), "utf8");
  const artifacts = [paths.reportJson, paths.reportMarkdown, paths.reportHtml];
  if (options.sarif === true) {
    await writeJsonFile(paths.reportSarif, renderSarifReport(report));
    artifacts.push(paths.reportSarif);
  }
  return artifacts;
}

function applyThreshold(findings: SkillFinding[], failOn: Severity | undefined): void {
  if (meetsThreshold(findings, failOn)) {
    console.error(`Policy threshold failed: found ${failOn} or higher severity finding.`);
    process.exitCode = 1;
  }
}

async function packageRoot(): Promise<string> {
  let current = dirname(fileURLToPath(import.meta.url));
  while (true) {
    const candidate = join(current, "package.json");
    try {
      await access(candidate, constants.R_OK);
      return current;
    } catch {
      const parent = dirname(current);
      if (parent === current) {
        return process.cwd();
      }
      current = parent;
    }
  }
}

async function runDoctor(cwd: string): Promise<Array<{ name: string; ok: boolean; message: string }>> {
  const checks: Array<{ name: string; ok: boolean; message: string }> = [];
  const major = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
  checks.push({
    name: "node",
    ok: major >= 22,
    message: `v${process.versions.node}`
  });

  const paths = localPaths(cwd);
  try {
    await ensureDir(paths.reportsDir);
    await access(paths.reportsDir, constants.W_OK);
    checks.push({ name: "output", ok: true, message: paths.reportsDir });
  } catch (error) {
    checks.push({ name: "output", ok: false, message: error instanceof Error ? error.message : "not writable" });
  }

  try {
    await stat(paths.configPath);
    await readJsonFile<unknown>(paths.configPath);
    checks.push({ name: "config", ok: true, message: paths.configPath });
  } catch {
    checks.push({ name: "config", ok: true, message: "not initialized yet; run agent-skillguard init" });
  }

  try {
    const root = await packageRoot();
    const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as { name?: string; version?: string };
    checks.push({
      name: "package",
      ok: packageJson.name === "agent-skillguard",
      message: `${packageJson.name ?? "unknown"}@${packageJson.version ?? "unknown"}`
    });
  } catch (error) {
    checks.push({ name: "package", ok: false, message: error instanceof Error ? error.message : "missing package metadata" });
  }

  return checks;
}

async function loadPolicy(cwd: string, explicitPath: string | undefined): Promise<SkillGuardPolicy> {
  const paths = localPaths(cwd);
  const policyPath = explicitPath === undefined ? paths.policyJson : resolve(cwd, explicitPath);
  try {
    return skillGuardPolicySchema.parse({
      ...defaultSkillGuardPolicy(),
      ...(await readJsonFile<Partial<SkillGuardPolicy>>(policyPath))
    });
  } catch {
    return defaultSkillGuardPolicy();
  }
}

function renderAdmissionMarkdown(decision: SkillAdmissionDecision): string {
  const lines = [
    "# SkillGuard Admission Decision",
    "",
    `Decision: **${decision.decision.toUpperCase()}**`,
    "",
    `- Skills: ${decision.summary.skills}`,
    `- Findings: ${decision.summary.findings}`,
    `- Risk score: ${decision.summary.riskScore}/100`,
    "",
    "## Reasons",
    ""
  ];

  if (decision.reasons.length === 0) {
    lines.push("No blocking or review reasons.");
  } else {
    for (const reason of decision.reasons) {
      lines.push(`- [${reason.severity.toUpperCase()}] ${reason.code} at \`${reason.target}\`: ${reason.message}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

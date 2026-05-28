#!/usr/bin/env node
import { access, readFile, stat, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command, InvalidArgumentError } from "commander";
import { ensureDir, readJsonFile, writeJsonFile } from "./core/files.js";
import { createSkillLock, defaultLockPathForSkill, readSkillLock, verifySkillLock, writeSkillLock } from "./core/lockfile.js";
import { packSkillBundle, verifySkillBundle } from "./core/pack.js";
import { defaultSkillGuardPolicy, evaluateAdmissionWithOptionalLock } from "./core/policy.js";
import { renderHtmlReport, renderMarkdownReport, renderSarifReport } from "./core/report.js";
import { meetsThreshold } from "./core/risk.js";
import { scanSkillPath } from "./core/scanner.js";
import { severitySchema, skillGuardPolicySchema, skillGuardReportSchema, type Severity, type SkillAdmissionDecision, type SkillFinding, type SkillGuardPolicy, type SkillGuardReport } from "./core/schemas.js";

const version = "0.2.0";

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
    const artifacts = await writeReportArtifacts(report, process.cwd(), { sarif: options.sarif !== false });
    console.log("Demo complete");
    console.log(`Skills scanned: ${report.summary.skills}`);
    console.log(`Findings: ${report.summary.findings}`);
    console.log(`Risk score: ${report.summary.riskScore}/100`);
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

await program.parseAsync(process.argv);

function parseSeverity(value: string): Severity {
  const parsed = severitySchema.safeParse(value);
  if (!parsed.success) {
    throw new InvalidArgumentError(`Expected one of: ${severitySchema.options.join(", ")}`);
  }
  return parsed.data;
}

function localPaths(cwd: string): { root: string; configPath: string; policyJson: string; reportsDir: string; reportJson: string; reportMarkdown: string; reportHtml: string; reportSarif: string; admissionJson: string; admissionMarkdown: string } {
  const root = join(cwd, ".skillguard");
  const reportsDir = join(root, "reports");
  return {
    root,
    configPath: join(root, "config.json"),
    policyJson: join(root, "policy.json"),
    reportsDir,
    reportJson: join(reportsDir, "skillguard-report.json"),
    reportMarkdown: join(reportsDir, "skillguard-report.md"),
    reportHtml: join(reportsDir, "skillguard-report.html"),
    reportSarif: join(reportsDir, "skillguard-report.sarif"),
    admissionJson: join(reportsDir, "skillguard-admission.json"),
    admissionMarkdown: join(reportsDir, "skillguard-admission.md")
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

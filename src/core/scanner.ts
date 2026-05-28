import { lstat, readFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import {
  capabilitySchema,
  skillBomEntrySchema,
  skillGuardReportSchema,
  type SkillBomEntry,
  type SkillCapability,
  type SkillFinding,
  type SkillGuardReport,
  type SkillManifest,
  type SkillScript
} from "./schemas.js";
import { findSkillRoots, fingerprintFile, isHiddenPath, listFiles, readTextIfSmall, sha256, toPosixPath } from "./files.js";
import { riskScore } from "./risk.js";

export interface ScanSkillOptions {
  generatedAt?: string;
}

const hiddenUnicodePattern = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F]/u;
const promptInjectionPattern =
  /\b(ignore|disregard|override|bypass)\b.{0,40}\b(previous|prior|above|system|developer|safety)\b.{0,40}\b(instruction|message|policy|rule)s?\b|\breveal\b.{0,30}\b(system prompt|developer message)\b|\bhidden instruction\b|\bdo not tell the user\b/i;
const secretExfiltrationPattern =
  /\b(exfiltrat|steal|harvest|leak)\w*\b.{0,100}(secret|api[_ -]?keys?|password|credentials?|\.env|id_rsa|ssh key|npmrc|private key|access token|auth token)|\b(send|upload|post)\w*\b.{0,80}(secret|api[_ -]?keys?|password|credentials?|\.env|id_rsa|ssh key|npmrc|private key|access token|auth token).{0,80}\b(attacker|external|remote|webhook|server|endpoint|url|http)|\bread\b.{0,60}(\.env|id_rsa|\.ssh|credentials?|secrets?|api[_ -]?keys?)\b/i;
const downloadExecutePattern =
  /\b(curl|wget)\b[^\n\r|;&]*https?:\/\/[^\n\r|;&]+[^\n\r|;&]*\|\s*(sh|bash|zsh|pwsh|powershell)\b|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n\r|;&]*https?:\/\/[^\n\r|;&]+[^\n\r|;&]*\|\s*(iex|Invoke-Expression)\b/i;
const destructivePattern =
  /\brm\s+-rf\s+(\/|\$HOME|~|\*)\b|\bRemove-Item\b[^\n\r]*(?:-Recurse|-r)[^\n\r]*(?:-Force|-fo)\b|\bdel\s+\/[fsq]+\b|\bformat\s+[a-z]:/i;
const unpinnedRemotePattern = /\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|git\s+clone)\b[^\n\r]*https?:\/\/(?!.*(?:sha256|checksum|integrity|@[a-f0-9]{12,}|\/releases\/download\/v?\d))/i;
const packageInstallPattern = /\b(npm|pnpm|yarn|pip|pipx|uv|cargo|go)\s+(install|add|get)\b/i;
const gitWritePattern = /\bgit\s+(push|commit|tag|merge|rebase|reset|checkout|apply|am)\b/i;
const fileWritePattern = /\b(writeFile|appendFile|fs\.write|Set-Content|Out-File|tee|>\s*[^\s]|Remove-Item|rm\s+-|mv\s+|cp\s+)\b/i;
const browserPattern = /\b(playwright|puppeteer|selenium|browser automation|chromium)\b/i;
const mcpMutationPattern = /\b(mcp|tool descriptor|tools\/call)\b.{0,80}\b(delete|update|mutate|write|install|register|unregister)\b/i;
const urlPattern = /https?:\/\/[^\s)"'<>]+/gi;

const lifecycleScriptNames = new Set(["preinstall", "install", "postinstall", "prepare", "prepack", "postpack"]);

export async function scanSkillPath(inputPath: string, options: ScanSkillOptions = {}): Promise<SkillGuardReport> {
  const roots = await findSkillRoots(inputPath);
  if (roots.length === 0) {
    throw new Error(`No skill roots found under ${inputPath}. Expected one or more SKILL.md files.`);
  }

  const findings: SkillFinding[] = [];
  const skills: SkillBomEntry[] = [];
  const generatedAt = options.generatedAt ?? new Date().toISOString();

  for (const root of roots) {
    const result = await scanSingleSkillRoot(root);
    skills.push(result.entry);
    findings.push(...result.findings);
  }

  const report: SkillGuardReport = {
    generatedAt,
    summary: {
      skills: skills.length,
      files: skills.reduce((count, skill) => count + skill.files.length, 0),
      findings: findings.length,
      riskScore: riskScore(findings)
    },
    bom: {
      generatedAt,
      skills
    },
    findings
  };

  return skillGuardReportSchema.parse(report);
}

async function scanSingleSkillRoot(root: string): Promise<{ entry: SkillBomEntry; findings: SkillFinding[] }> {
  const absoluteRoot = resolve(root);
  const filePaths = await listFiles(absoluteRoot);
  const files = [];
  const findings: SkillFinding[] = [];
  const scripts: SkillScript[] = [];
  const capabilities = new Set<SkillCapability>();

  for (const absolutePath of filePaths) {
    const fingerprint = await fingerprintFile(absoluteRoot, absolutePath);
    files.push(fingerprint);

    const relativePath = toPosixPath(relative(absoluteRoot, absolutePath));
    const entryStat = await lstat(absolutePath);

    if (entryStat.isSymbolicLink()) {
      findings.push(createFinding("bundle.symlink", "high", "Symbolic link in skill bundle", "The skill contains a symlink. Symlinks can escape an expected bundle boundary during install or review.", "Replace the symlink with a regular file or remove it from the skill package.", relativePath, ["symbolic link"]));
    }

    if (isHiddenPath(relativePath)) {
      findings.push(createFinding("bundle.hidden_file", "medium", "Hidden file in skill bundle", "Hidden files make skill behavior harder to review and can hide payloads from simple directory listings.", "Move required content into explicit files and remove hidden payloads.", relativePath, [relativePath]));
    }

    if (relativePath.includes("../")) {
      findings.push(createFinding("bundle.path_traversal", "critical", "Path traversal in skill bundle", "A path attempts to leave the skill root.", "Reject the bundle and rebuild it from a clean skill directory.", relativePath, [relativePath]));
    }

    if (fingerprint.kind === "binary") {
      findings.push(createFinding("bundle.binary_payload", "high", "Binary payload in skill", "Binary files are hard to audit and can hide executable behavior.", "Ship source files or document and hash-review the binary payload.", relativePath, [relativePath]));
    }

    if (fingerprint.size > 5_000_000) {
      findings.push(createFinding("bundle.oversized_payload", "high", "Oversized skill payload", "Large bundled files increase supply-chain risk and make review harder.", "Remove generated assets and package only source needed by the skill.", relativePath, [`${fingerprint.size} bytes`]));
    }

    const text = await readTextIfSmall(absolutePath);
    if (text !== undefined) {
      addTextFindings(findings, relativePath, text);
      inferCapabilities(capabilities, text);
      await inspectManifestLikeFile(findings, capabilities, absolutePath, relativePath, text);
    }

    if (fingerprint.kind === "script") {
      const scriptCapabilities = scriptCapabilitiesForPathAndText(absolutePath, text ?? "");
      for (const capability of scriptCapabilities) {
        capabilities.add(capability);
      }
      scripts.push({
        path: relativePath,
        interpreter: interpreterForPath(absolutePath),
        capabilities: [...scriptCapabilities].sort()
      });
    }
  }

  const manifest = await readSkillManifest(absoluteRoot, findings);
  const observedCapabilities = [...capabilities].sort();
  for (const capability of manifest.declaredCapabilities) {
    capabilities.add(capability);
  }

  if (capabilities.has("network") && capabilities.has("shell") && capabilities.has("filesystem-write")) {
    findings.push(createFinding("skill.broad_capability_chain", "high", "Skill combines network, shell, and write access", "This capability combination can download and execute code, then persist changes locally.", "Split the skill into narrower skills or require an explicit install-time approval policy.", `${manifest.name}/capabilities`, [...capabilities]));
  }

  const entry = skillBomEntrySchema.parse({
    root: absoluteRoot,
    manifest,
    files: files.sort((left, right) => left.path.localeCompare(right.path)),
    scripts: scripts.sort((left, right) => left.path.localeCompare(right.path)),
    observedCapabilities,
    capabilities: [...capabilities].sort()
  });

  return { entry, findings };
}

function createFinding(category: string, severity: SkillFinding["severity"], title: string, description: string, recommendation: string, target: string, evidence: string[]): SkillFinding {
  const material = `${category}:${severity}:${target}:${evidence.join("|")}`;
  return {
    id: `${category}:${sha256(material).slice(0, 12)}`,
    severity,
    category,
    title,
    description,
    recommendation,
    target,
    evidence: evidence.slice(0, 5)
  };
}

function addTextFindings(findings: SkillFinding[], target: string, text: string): void {
  if (hiddenUnicodePattern.test(text)) {
    const severity = promptInjectionPattern.test(text) || secretExfiltrationPattern.test(text) ? "critical" : "high";
    findings.push(createFinding("skill.hidden_unicode", severity, "Hidden Unicode control characters", "The skill contains hidden Unicode control characters that can conceal instructions or alter reviewer-visible text.", "Remove hidden Unicode characters and keep instructions reviewable as plain text.", target, ["zero-width or bidi control character"]));
  }

  if (promptInjectionPattern.test(text)) {
    findings.push(createFinding("skill.prompt_injection", "critical", "Prompt-injection instruction detected", "The skill contains language that attempts to override higher-priority system or developer instructions.", "Remove the instruction and require skill behavior to follow host agent policy.", target, evidenceFor(text, promptInjectionPattern)));
  }

  if (secretExfiltrationPattern.test(text)) {
    findings.push(createFinding("skill.secret_exfiltration", "critical", "Secret exfiltration behavior detected", "The skill instructs the agent or script to access and transmit secrets, credentials, or token files.", "Remove credential access and keep secret handling behind explicit user approval.", target, evidenceFor(text, secretExfiltrationPattern)));
  }

  if (downloadExecutePattern.test(text)) {
    findings.push(createFinding("script.download_execute", "critical", "Download-and-execute chain detected", "The skill downloads remote code and immediately executes it, which is a common installer compromise pattern.", "Pin and verify artifacts before execution, or vendor reviewed source instead.", target, evidenceFor(text, downloadExecutePattern)));
  }

  if (destructivePattern.test(text)) {
    findings.push(createFinding("script.destructive_operation", "critical", "Destructive automation detected", "The skill contains broad delete or format operations that can destroy local data.", "Replace broad destructive commands with narrow, user-approved file operations.", target, evidenceFor(text, destructivePattern)));
  }

  if (unpinnedRemotePattern.test(text)) {
    findings.push(createFinding("dependency.unpinned_remote", "medium", "Unpinned remote dependency", "The skill fetches remote content without an obvious immutable version or checksum.", "Pin remote artifacts to immutable versions and verify checksums.", target, evidenceFor(text, unpinnedRemotePattern)));
  }
}

async function inspectManifestLikeFile(findings: SkillFinding[], capabilities: Set<SkillCapability>, absolutePath: string, relativePath: string, text: string): Promise<void> {
  if (!relativePath.toLowerCase().endsWith("package.json")) {
    return;
  }

  try {
    const parsed = JSON.parse(text) as { scripts?: Record<string, unknown>; dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> };
    for (const [name, value] of Object.entries(parsed.scripts ?? {})) {
      if (lifecycleScriptNames.has(name) && typeof value === "string" && value.trim().length > 0) {
        capabilities.add("package-install");
        capabilities.add("shell");
        findings.push(createFinding("package.lifecycle_script", "high", "Package lifecycle script detected", "Lifecycle scripts run automatically during install and can execute arbitrary local commands.", "Remove lifecycle hooks or move install behavior behind explicit user approval.", relativePath, [`${name}: ${value}`]));
      }
    }

    for (const dependencyName of [...Object.keys(parsed.dependencies ?? {}), ...Object.keys(parsed.devDependencies ?? {})]) {
      if (/^(?:https?:|git\+https?:|github:)/i.test(String((parsed.dependencies ?? parsed.devDependencies ?? {})[dependencyName]))) {
        findings.push(createFinding("dependency.remote_specifier", "medium", "Remote package specifier detected", "Remote package specifiers are harder to reproduce and review than registry versions pinned by a lockfile.", "Use registry versions with a committed lockfile or include a verified checksum.", relativePath, [dependencyName]));
      }
    }
  } catch {
    findings.push(createFinding("manifest.invalid_json", "high", "Invalid package manifest", "A package.json file could not be parsed as JSON.", "Fix or remove the malformed manifest before publishing the skill.", relativePath, ["JSON parse failed"]));
  }

  await Promise.resolve();
}

async function readSkillManifest(root: string, findings: SkillFinding[]): Promise<SkillManifest> {
  const skillPath = join(root, "SKILL.md");
  let content: string;
  try {
    content = await readFile(skillPath, "utf8");
  } catch {
    findings.push(createFinding("skill.missing_manifest", "critical", "Missing SKILL.md", "A skill must include a SKILL.md file at its root.", "Add a SKILL.md with name, description, and declared capabilities.", toPosixPath(relative(dirname(root), skillPath)), ["SKILL.md missing"]));
    return { name: basename(root), description: "", declaredCapabilities: [] };
  }

  const frontmatter = parseFrontmatter(content);
  const heading = content.match(/^#\s+(.+)$/m)?.[1]?.trim();
  const description = frontmatter.description ?? firstParagraph(content) ?? "";
  const declaredCapabilities = parseDeclaredCapabilities(frontmatter.capabilities ?? frontmatter.declaredCapabilities);

  if (!heading && frontmatter.name === undefined) {
    findings.push(createFinding("skill.malformed_manifest", "high", "Skill manifest lacks a clear name", "SKILL.md should include a top-level heading or frontmatter name for review and lockfile clarity.", "Add a # Skill Name heading or name field in frontmatter.", "SKILL.md", ["missing name"]));
  }

  return {
    name: frontmatter.name ?? heading ?? basename(root),
    description,
    version: frontmatter.version,
    source: frontmatter.source,
    declaredCapabilities
  };
}

function parseFrontmatter(content: string): Record<string, string> {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match?.[1]) {
    return {};
  }

  const result: Record<string, string> = {};
  for (const line of match[1].split(/\r?\n/)) {
    const keyValue = line.match(/^([A-Za-z][\w-]*)\s*:\s*(.+?)\s*$/);
    if (keyValue?.[1] !== undefined && keyValue[2] !== undefined) {
      result[keyValue[1]] = keyValue[2].replace(/^['"]|['"]$/g, "");
    }
  }
  return result;
}

function firstParagraph(content: string): string | undefined {
  const withoutFrontmatter = content.replace(/^---\r?\n[\s\S]*?\r?\n---/, "");
  return withoutFrontmatter
    .split(/\r?\n\r?\n/)
    .map((part) => part.replace(/^#.*$/gm, "").trim())
    .find((part) => part.length > 0);
}

function parseDeclaredCapabilities(raw: string | undefined): SkillCapability[] {
  if (raw === undefined) {
    return [];
  }
  const normalized = raw.replace(/^\[|\]$/g, "");
  const values = normalized.split(/[,\s]+/).map((value) => value.trim().replace(/^['"]|['"]$/g, "")).filter(Boolean);
  return values.filter((value): value is SkillCapability => capabilitySchema.safeParse(value).success);
}

function inferCapabilities(capabilities: Set<SkillCapability>, text: string): void {
  if (urlPattern.test(text) || unpinnedRemotePattern.test(text)) capabilities.add("network");
  if (downloadExecutePattern.test(text) || /\b(shell|bash|powershell|cmd\.exe|exec|spawn)\b/i.test(text)) capabilities.add("shell");
  if (packageInstallPattern.test(text)) capabilities.add("package-install");
  if (gitWritePattern.test(text)) capabilities.add("git-write");
  if (/\bgit\s+(show|diff|status|log|grep)\b/i.test(text)) capabilities.add("git-read");
  if (fileWritePattern.test(text)) capabilities.add("filesystem-write");
  if (/\b(readFile|Get-Content|cat\s+|less\s+|grep\s+|ripgrep|rg\s+)\b/i.test(text)) capabilities.add("filesystem-read");
  if (browserPattern.test(text)) capabilities.add("browser-automation");
  if (mcpMutationPattern.test(text)) capabilities.add("mcp-tool-mutation");
  if (secretExfiltrationPattern.test(text)) capabilities.add("secret-access");
}

function scriptCapabilitiesForPathAndText(path: string, text: string): Set<SkillCapability> {
  const capabilities = new Set<SkillCapability>(["shell"]);
  inferCapabilities(capabilities, text);
  const lowerPath = path.toLowerCase();
  if (lowerPath.includes("install") || packageInstallPattern.test(text)) {
    capabilities.add("package-install");
  }
  return capabilities;
}

function interpreterForPath(path: string): string {
  const lower = path.toLowerCase();
  if (lower.endsWith(".ps1")) return "powershell";
  if (lower.endsWith(".cmd") || lower.endsWith(".bat")) return "cmd";
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".js") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return "node";
  if (lower.endsWith(".ts")) return "typescript";
  if (lower.endsWith(".sh") || lower.endsWith(".bash") || lower.endsWith(".zsh")) return "shell";
  return "unknown";
}

function evidenceFor(text: string, pattern: RegExp): string[] {
  const match = text.match(pattern);
  if (match?.[0] === undefined) {
    return [];
  }
  return [match[0].replace(/\s+/g, " ").trim().slice(0, 180)];
}

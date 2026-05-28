import { readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { findSkillRoots, fingerprintFile, listFiles, sha256, writeJsonFile } from "./files.js";
import { scanSkillPath } from "./scanner.js";
import { skillLockSchema, type SkillCapability, type SkillFinding, type SkillLock } from "./schemas.js";

export interface CreateSkillLockOptions {
  generatedAt?: string;
}

export interface VerifySkillLockResult {
  valid: boolean;
  findings: SkillFinding[];
}

export async function createSkillLock(inputPath: string, options: CreateSkillLockOptions = {}): Promise<SkillLock> {
  const roots = await findSkillRoots(inputPath);
  if (roots.length !== 1) {
    throw new Error(`Lock expects exactly one skill root, found ${roots.length}.`);
  }

  const rootCandidate = roots[0];
  if (rootCandidate === undefined) {
    throw new Error("Lock expects one skill root, found none.");
  }

  const root = resolve(rootCandidate);
  const skillFiles = (await listFiles(root)).filter((path) => basename(path) !== "skillguard.lock.json");
  const files = await Promise.all(skillFiles.map((path) => fingerprintFile(root, path)));
  const report = await scanSkillPath(root, options.generatedAt === undefined ? {} : { generatedAt: options.generatedAt });
  const capabilities = new Set<SkillCapability>();
  for (const skill of report.bom.skills) {
    for (const capability of skill.capabilities) {
      capabilities.add(capability);
    }
  }

  return skillLockSchema.parse({
    schemaVersion: 1,
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    root: basename(root),
    files: files.sort((left, right) => left.path.localeCompare(right.path)),
    capabilities: [...capabilities].sort()
  });
}

export async function writeSkillLock(inputPath: string, outputPath = "skillguard.lock.json"): Promise<SkillLock> {
  const lock = await createSkillLock(inputPath);
  await writeJsonFile(outputPath, lock);
  return lock;
}

export async function readSkillLock(lockPath: string): Promise<SkillLock> {
  return skillLockSchema.parse(JSON.parse(await readFile(lockPath, "utf8")));
}

export async function verifySkillLock(inputPath: string, lock: SkillLock): Promise<VerifySkillLockResult> {
  const current = await createSkillLock(inputPath, { generatedAt: lock.generatedAt });
  const findings: SkillFinding[] = [];
  const expectedByPath = new Map(lock.files.map((file) => [file.path, file]));
  const actualByPath = new Map(current.files.map((file) => [file.path, file]));

  for (const expected of lock.files) {
    const actual = actualByPath.get(expected.path);
    if (actual === undefined) {
      findings.push(lockFinding("lock.missing_file", "critical", "Locked skill file is missing", "A file present in the lockfile is missing from the skill directory.", "Restore the file or regenerate the lockfile after review.", expected.path, [expected.path]));
      continue;
    }
    if (actual.sha256 !== expected.sha256) {
      findings.push(lockFinding("lock.hash_mismatch", "critical", "Locked skill file hash changed", "A skill file changed after the lockfile was generated.", "Review the diff and regenerate the lockfile only if the change is intentional.", expected.path, [`expected ${expected.sha256}`, `actual ${actual.sha256}`]));
    }
    if (actual.size !== expected.size) {
      findings.push(lockFinding("lock.size_mismatch", "high", "Locked skill file size changed", "A skill file size differs from the lockfile.", "Review the changed file and regenerate the lockfile only after approval.", expected.path, [`expected ${expected.size}`, `actual ${actual.size}`]));
    }
  }

  for (const actual of current.files) {
    if (!expectedByPath.has(actual.path)) {
      findings.push(lockFinding("lock.untracked_file", "high", "Untracked skill file detected", "A file exists in the skill directory but is absent from the lockfile.", "Review the file and regenerate the lockfile if it belongs in the skill.", actual.path, [actual.path]));
    }
  }

  return {
    valid: findings.length === 0,
    findings
  };
}

function lockFinding(category: string, severity: SkillFinding["severity"], title: string, description: string, recommendation: string, target: string, evidence: string[]): SkillFinding {
  return {
    id: `${category}:${sha256(`${category}:${target}:${evidence.join("|")}`).slice(0, 12)}`,
    severity,
    category,
    title,
    description,
    recommendation,
    target,
    evidence
  };
}

export function defaultLockPathForSkill(skillDir: string): string {
  return join(resolve(skillDir), "skillguard.lock.json");
}

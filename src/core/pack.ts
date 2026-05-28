import { gzipSync, gunzipSync } from "node:zlib";
import { readFile, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { ensureDir, listFiles, sha256, toPosixPath } from "./files.js";
import { createSkillLock, type VerifySkillLockResult } from "./lockfile.js";
import { skillLockSchema, type SkillLock } from "./schemas.js";

export interface PackResult {
  path: string;
  sha256: string;
}

export interface SkillBundle {
  schemaVersion: 1;
  kind: "agent-skillguard.bundle";
  createdAt: string;
  lock: SkillLock;
  files: Array<{
    path: string;
    mode: number;
    contentBase64: string;
  }>;
}

const deterministicTimestamp = "1970-01-01T00:00:00.000Z";

export async function packSkillBundle(skillDir: string, outputPath: string): Promise<PackResult> {
  const root = resolve(skillDir);
  const lock = await createSkillLock(root, { generatedAt: deterministicTimestamp });
  const files = [];

  for (const file of (await listFiles(root)).filter((path) => basename(path) !== "skillguard.lock.json")) {
    const content = await readFile(file);
    files.push({
      path: toPosixPath(file.slice(root.length + 1)),
      mode: 0o644,
      contentBase64: content.toString("base64")
    });
  }

  const bundle: SkillBundle = {
    schemaVersion: 1,
    kind: "agent-skillguard.bundle",
    createdAt: deterministicTimestamp,
    lock,
    files: files.sort((left, right) => left.path.localeCompare(right.path))
  };

  const canonical = JSON.stringify(bundle);
  const bytes = gzipSync(Buffer.from(canonical, "utf8"), { level: 9 });
  await ensureDir(dirname(outputPath));
  await writeFile(outputPath, bytes);

  return {
    path: resolve(outputPath),
    sha256: sha256(bytes)
  };
}

export async function readSkillBundle(bundlePath: string): Promise<SkillBundle> {
  const bytes = await readFile(bundlePath);
  const parsed = JSON.parse(gunzipSync(bytes).toString("utf8")) as SkillBundle;
  return {
    ...parsed,
    lock: skillLockSchema.parse(parsed.lock)
  };
}

export async function verifySkillBundle(bundlePath: string): Promise<VerifySkillLockResult> {
  const bundle = await readSkillBundle(bundlePath);
  const findings = [];
  const lockFiles = new Map(bundle.lock.files.map((file) => [file.path, file]));
  const bundleFiles = new Map(bundle.files.map((file) => [file.path, file]));

  for (const expected of bundle.lock.files) {
    const file = bundleFiles.get(expected.path);
    if (file === undefined) {
      findings.push({
        id: `bundle.missing_file:${sha256(expected.path).slice(0, 12)}`,
        severity: "critical" as const,
        category: "bundle.missing_file",
        title: "Bundle file is missing",
        description: "A file present in the embedded lockfile is missing from the bundle.",
        recommendation: "Repack the skill from a clean source directory.",
        target: expected.path,
        evidence: [expected.path]
      });
      continue;
    }

    const actualHash = sha256(Buffer.from(file.contentBase64, "base64"));
    if (actualHash !== expected.sha256) {
      findings.push({
        id: `bundle.hash_mismatch:${sha256(expected.path).slice(0, 12)}`,
        severity: "critical" as const,
        category: "bundle.hash_mismatch",
        title: "Bundle file hash mismatch",
        description: "The bundle content does not match the embedded lockfile.",
        recommendation: "Reject this bundle and rebuild it from the source skill directory.",
        target: expected.path,
        evidence: [`expected ${expected.sha256}`, `actual ${actualHash}`]
      });
    }
  }

  for (const path of bundleFiles.keys()) {
    if (!lockFiles.has(path)) {
      findings.push({
        id: `bundle.unlocked_file:${sha256(path).slice(0, 12)}`,
        severity: "high" as const,
        category: "bundle.unlocked_file",
        title: "Bundle contains unlocked file",
        description: "A file appears in the bundle but not in the embedded lockfile.",
        recommendation: "Repack the skill with a fresh lockfile after reviewing the file.",
        target: path,
        evidence: [path]
      });
    }
  }

  return {
    valid: findings.length === 0,
    findings
  };
}

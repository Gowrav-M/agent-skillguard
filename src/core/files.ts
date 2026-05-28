import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, readdir, readlink, stat, writeFile } from "node:fs/promises";
import { basename, dirname, extname, join, relative, resolve, sep } from "node:path";
import type { SkillFile } from "./schemas.js";

const binaryExtensions = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".exe", ".dll", ".so", ".dylib", ".bin", ".zip", ".gz", ".tgz", ".tar"]);
const scriptExtensions = new Set([".sh", ".bash", ".zsh", ".ps1", ".cmd", ".bat", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".php", ".go", ".rs"]);

export async function ensureDir(path: string): Promise<void> {
  await mkdir(path, { recursive: true });
}

export async function writeJsonFile(path: string, value: unknown): Promise<void> {
  await ensureDir(dirname(path));
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export async function readJsonFile<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

export function sha256(buffer: Buffer | string): string {
  return createHash("sha256").update(buffer).digest("hex");
}

export function toPosixPath(path: string): string {
  return path.split(sep).join("/");
}

export function classifyFile(path: string): SkillFile["kind"] {
  const lower = path.toLowerCase();
  const extension = extname(lower);
  if (lower.endsWith("skill.md") || extension === ".md" || extension === ".mdx") return "markdown";
  if (scriptExtensions.has(extension)) return "script";
  if (lower.endsWith("package.json") || lower.endsWith("skill.json") || lower.endsWith("manifest.json")) return "manifest";
  if (extension === ".json") return "json";
  if (binaryExtensions.has(extension)) return "binary";
  return "other";
}

export async function listFiles(root: string): Promise<string[]> {
  const absoluteRoot = resolve(root);
  const results: string[] = [];

  async function walk(current: string): Promise<void> {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "dist") {
        continue;
      }
      const absolute = join(current, entry.name);
      const entryStat = await lstat(absolute);
      if (entryStat.isSymbolicLink()) {
        results.push(absolute);
        continue;
      }
      if (entry.isDirectory()) {
        await walk(absolute);
      } else if (entry.isFile()) {
        results.push(absolute);
      }
    }
  }

  await walk(absoluteRoot);
  return results;
}

export async function fingerprintFile(root: string, absolutePath: string): Promise<SkillFile> {
  const fileStat = await lstat(absolutePath);
  const content = fileStat.isSymbolicLink()
    ? Buffer.from(`symlink:${await readlink(absolutePath)}`, "utf8")
    : await readFile(absolutePath);
  return {
    path: toPosixPath(relative(resolve(root), absolutePath)),
    size: fileStat.size,
    sha256: sha256(content),
    kind: classifyFile(absolutePath)
  };
}

export async function findSkillRoots(inputPath: string): Promise<string[]> {
  const absolute = resolve(inputPath);
  const inputStat = await stat(absolute);
  if (inputStat.isFile()) {
    return [dirname(absolute)];
  }

  const directSkill = join(absolute, "SKILL.md");
  try {
    await stat(directSkill);
    return [absolute];
  } catch {
    const files = await listFiles(absolute);
    const roots = files.filter((file) => file.endsWith(`${sep}SKILL.md`)).map((file) => dirname(file));
    return [...new Set(roots)].sort((left, right) => left.localeCompare(right));
  }
}

export async function readTextIfSmall(path: string, maxBytes = 1_000_000): Promise<string | undefined> {
  const fileStat = await stat(path);
  if (fileStat.size > maxBytes) {
    return undefined;
  }
  const content = await readFile(path);
  if (content.includes(0)) {
    return undefined;
  }
  return content.toString("utf8");
}

export function isHiddenPath(path: string): boolean {
  return toPosixPath(path)
    .split("/")
    .some((part) => basename(part).startsWith(".") && part !== "." && part !== "..");
}

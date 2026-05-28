import { spawn } from "node:child_process";
import { resolve as resolvePath } from "node:path";
import { pathToFileURL } from "node:url";

export async function execaNode(args: string[], cwd: string): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return await new Promise((resolve) => {
    const normalizedArgs = args.map((arg, index) => index === 0 && arg.startsWith("src/") ? resolvePath(process.cwd(), arg) : arg);
    const tsxLoader = pathToFileURL(resolvePath(process.cwd(), "node_modules", "tsx", "dist", "loader.mjs")).href;
    const child = spawn(process.execPath, ["--import", tsxLoader, ...normalizedArgs], { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("close", (code) => {
      resolve({ exitCode: code ?? 1, stdout, stderr });
    });
  });
}

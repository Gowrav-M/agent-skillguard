import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { createSkillLock, verifySkillLock } from "../src/core/lockfile.js";

describe("skill lockfile", () => {
  it("passes for unchanged skill files and fails after modification", async () => {
    const lock = await createSkillLock("examples/skills/safe-code-reviewer");
    const ok = await verifySkillLock("examples/skills/safe-code-reviewer", lock);
    expect(ok.valid).toBe(true);

    const temp = await mkdtemp(join(tmpdir(), "skillguard-lock-"));
    await writeFile(join(temp, "SKILL.md"), await readFile("examples/skills/safe-code-reviewer/SKILL.md", "utf8"));
    const tempLock = await createSkillLock(temp);
    await writeFile(join(temp, "SKILL.md"), "# modified\n");
    const changed = await verifySkillLock(temp, tempLock);
    expect(changed.valid).toBe(false);
    expect(changed.findings[0]?.category).toBe("lock.hash_mismatch");
  });
});

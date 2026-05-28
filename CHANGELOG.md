# Changelog

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

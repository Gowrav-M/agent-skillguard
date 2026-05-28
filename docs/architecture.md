# Architecture

Agent SkillGuard is a local TypeScript CLI with five layers.

## Scanner

Walks one skill directory or a collection of `SKILL.md` roots. It fingerprints files, classifies scripts and manifests, infers capabilities, and emits findings.

## SkillBOM

Creates an SBOM-like inventory containing:

- skill manifest
- file hashes and sizes
- script interpreters
- inferred and declared capabilities

## Lockfile

Writes `skillguard.lock.json` with the current file inventory and hashes. Verification fails when files are missing, added, resized, or modified.

## Admission Controller

Evaluates a scan against policy-as-code. It turns findings and SkillBOM capabilities into `ALLOW`, `REVIEW`, or `BLOCK` decisions for local installs and CI gates.

## Provenance Firewall

Records source host, publisher, commit pin, and skill digest. It blocks mutable or unapproved sources before the skill enters admission or update review.

## Capability Contracts

Compares declared capabilities in `SKILL.md` with observed behavior inferred from the skill content. It blocks least-privilege violations before admission.

## Update Firewall

Compares an approved skill with a candidate update. It detects file drift, new findings, added capabilities, changed `SKILL.md` instruction surfaces, and risk-score jumps before an update is accepted.

## Packer

Creates deterministic `.skill.tgz` bundles with an embedded lockfile and canonical file payloads.

## Reporter

Renders JSON, Markdown, HTML, and SARIF so developers can review locally and security teams can ingest findings in GitHub code scanning.

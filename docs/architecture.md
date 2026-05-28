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

## Packer

Creates deterministic `.skill.tgz` bundles with an embedded lockfile and canonical file payloads.

## Reporter

Renders JSON, Markdown, HTML, and SARIF so developers can review locally and security teams can ingest findings in GitHub code scanning.

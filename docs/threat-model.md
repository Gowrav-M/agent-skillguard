# Threat Model

Agent SkillGuard treats an agent skill as executable supply chain.

## Assets

- User instructions and private context.
- Local files, credentials, tokens, and SSH material.
- Repository contents and git write access.
- MCP tool descriptors and agent runtime permissions.
- Skill review decisions and lockfiles.

## Threats

- Prompt injection hidden in Markdown, comments, YAML, HTML, or code blocks.
- Secret exfiltration instructions that ask an agent to read and transmit `.env`, token, SSH, or package-manager credential files.
- Download-execute chains such as `curl | sh` and `Invoke-WebRequest | iex`.
- Package lifecycle hooks that run code during installation.
- Bundled binaries, hidden files, symlinks, path traversal, and oversized payloads.
- Broad capabilities combining network, shell, and filesystem write.

## Security Boundary

SkillGuard is a static and packaging safety gate. It does not sandbox runtime execution. Runtime attack-path monitoring belongs in AgentOps tools such as Watchtower.

## Design Principles

- Local-first: no cloud dependency and no skill contents sent to an API.
- Deterministic: reports, locks, and bundles are reproducible.
- Evidence-first: every finding includes a target, evidence, severity, and recommendation.
- CI-friendly: SARIF output and fail thresholds make unsafe skills blockable in pull requests.

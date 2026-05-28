# Skill Update Firewall

First install is only one risk point. The harder enterprise problem is safe updating:

- A trusted skill adds shell access in a minor update.
- A `SKILL.md` change quietly changes agent behavior.
- A safe skill starts reading secrets or mutating MCP tools.
- A new installer hook appears in a dependency or script.

`agent-skillguard review-update` compares an approved skill with a candidate replacement and decides whether the update should be allowed, reviewed, or blocked.

```bash
agent-skillguard review-update ./approved/code-reviewer ./incoming/code-reviewer
```

## What It Compares

| Signal | Why It Matters |
| --- | --- |
| Added capabilities | Shows privilege creep such as shell, network, git write, or package install. |
| Removed capabilities | Useful for auditing least-privilege improvements. |
| Added files | Reveals new scripts, binaries, manifests, and tool descriptors. |
| Removed files | Shows behavior disappearing from the approved baseline. |
| Modified files | Flags instruction and script changes after approval. |
| New findings | Highlights new prompt injection, exfiltration, or dangerous automation. |
| Risk delta | Catches updates that materially increase total risk. |

## Decisions

| Decision | Meaning |
| --- | --- |
| `ALLOW` | No material drift from the approved version. |
| `REVIEW` | Files changed but no blocking risk was detected. |
| `BLOCK` | Candidate adds dangerous capabilities or new high/critical findings. |

## Why This Is Breakthrough

Skill registries and GitHub skill collections are growing quickly. Enterprises cannot manually reread every `SKILL.md` and bundled script on every update. The update firewall gives teams a deterministic review packet that fits pull requests, private marketplaces, and internal approval workflows.

Research signal: recent agent-skill lifecycle research calls out safe updating, quality control, interoperability, and long-term capability management as open problems. Supply-chain guidance from SLSA and GitHub artifact attestations also points toward downstream verification and policy decisions, not blind trust in the source.

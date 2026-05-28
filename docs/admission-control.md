# Skill Admission Control

Scanning answers: what is risky?

Admission answers: can this skill enter this organization, repository, or agent environment?

## Why This Is Industrial

Enterprise teams already use dependency review, artifact attestations, SBOMs, provenance, and policy gates for software packages. Agent skills need the same treatment because they can steer tool use, execute scripts, mutate repositories, and touch local credentials.

The admission controller turns SkillGuard into a pre-install and pre-publish gate:

```bash
agent-skillguard policy
agent-skillguard admit ./skills --require-lock --sarif
```

## Decisions

| Decision | Meaning |
| --- | --- |
| `ALLOW` | No findings and no policy violations. |
| `REVIEW` | Findings exist, but policy does not require blocking. |
| `BLOCK` | A finding or capability violates policy. |

## Default Policy

```json
{
  "schemaVersion": 1,
  "blockOnSeverity": "critical",
  "deniedCapabilities": ["secret-access", "mcp-tool-mutation"],
  "requireLockfile": false,
  "requireCleanScan": false,
  "allowInstallScripts": false
}
```

## Strong Enterprise Policy

```json
{
  "schemaVersion": 1,
  "blockOnSeverity": "high",
  "deniedCapabilities": [
    "secret-access",
    "mcp-tool-mutation",
    "package-install",
    "filesystem-write",
    "git-write"
  ],
  "requireLockfile": true,
  "requireCleanScan": true,
  "allowInstallScripts": false
}
```

## Research Signal

- [Microsoft](https://learn.microsoft.com/en-us/security/zero-trust/sfi/defend-indirect-prompt-injection) recommends defense in depth for indirect prompt injection: prompt shields, data marking, plan-drift detection, critic agents, and tool-chain analysis.
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) and [npm provenance](https://docs.npmjs.com/generating-provenance-statements/) show the direction of modern supply-chain trust: build provenance, signatures, transparent logs, and downstream verification.
- [OpenSSF Scorecard](https://openssf.org/scorecard/) shows that automated trust scoring helps consumers judge open-source risk.
- Recent [agent-skill research](https://arxiv.org/abs/2605.07358) frames skills as reusable procedural artifacts central to agent scalability, while still raising quality-control, interoperability, safe-update, and long-term management challenges.

SkillGuard applies those patterns to the missing layer: pre-install governance for agent skills.

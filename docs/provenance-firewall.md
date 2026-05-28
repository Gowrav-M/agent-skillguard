# Skill Provenance Firewall

Static scanning is necessary but incomplete. A clean skill can still be unsafe if the source is mutable, unapproved, or impossible to audit.

The provenance firewall answers:

- Where did this skill come from?
- Is the source host allowed?
- Is the source pinned to an immutable commit?
- Who published it?
- What exact digest was approved?

```bash
agent-skillguard trust ./skills/code-reviewer \
  --source https://github.com/org/repo/tree/main/skills/code-reviewer \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --publisher org \
  --write
```

## Outputs

```text
.skillguard/reports/skillguard-trust.json
.skillguard/reports/skillguard-trust.md
./skills/code-reviewer/skillguard.provenance.json
```

## Default Policy

```json
{
  "schemaVersion": 1,
  "allowedHosts": ["github.com"],
  "allowedPublishers": [],
  "requirePinnedCommit": true,
  "denyMutableRefs": true
}
```

## Decisions

| Decision | Meaning |
| --- | --- |
| `ALLOW` | Source host is approved and the skill is pinned to an immutable commit. |
| `REVIEW` | Non-blocking trust metadata is missing. |
| `BLOCK` | Source is mutable, unpinned, from an unapproved host, or from an unapproved publisher. |

## Why This Matters

Agent skill ecosystems are moving toward marketplaces, registries, GitHub skill collections, and vendor-provided skill packs. Enterprises need source identity and immutable approval records before those skills can be trusted.

This layer complements admission control and update review:

1. `trust` checks source and digest.
2. `admit` checks policy and findings.
3. `review-update` checks drift from the approved baseline.

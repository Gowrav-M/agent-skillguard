# Risk Baselines

Risk baselines make SkillGuard practical for existing repositories. A team can review the current findings once, record why they were accepted, and then fail CI only when new or expired risk appears.

## Create A Baseline

```bash
agent-skillguard baseline ./skills \
  --reason "initial security review of vendored skills" \
  --expires 2026-12-31
```

Outputs:

```text
.skillguard/baseline.json
.skillguard/reports/skillguard-baseline.md
```

The baseline stores scan findings, semantic intent signals, and attack graph paths by stable IDs, severity, category, target, title, acceptance reason, and optional expiry.

## Triage Against A Baseline

```bash
agent-skillguard triage ./skills \
  --baseline .skillguard/baseline.json \
  --fail-on high
```

Outputs:

```text
.skillguard/reports/skillguard-triage.json
.skillguard/reports/skillguard-triage.md
```

`triage` returns:

| Decision | Meaning |
| --- | --- |
| `ALLOW` | All current scan and intent risks are covered by active baseline entries. |
| `REVIEW` | New low, medium, or high risk exists outside the baseline. |
| `BLOCK` | New critical risk exists outside the baseline. |

Expired baseline entries no longer suppress matching findings. Use this for temporary exceptions that must be re-reviewed.

## Why This Matters

Real-world validation found that useful public skill repositories often contain review-worthy capability chains, natural-language intent signals, or cross-skill composition risk. A baseline lets enterprises adopt SkillGuard without pretending every existing finding is immediately fixable, while still preventing silent risk drift.

# Skill Passport

A Skill Passport is the approval record for an AI agent skill: where it came from, what it can do, why it was allowed or blocked, and what exact digest was reviewed.

```bash
agent-skillguard passport ./skills/code-reviewer \
  --source https://github.com/org/repo/tree/main/skills/code-reviewer \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --publisher org \
  --pack
```

## What It Runs

| Layer | Purpose |
| --- | --- |
| Provenance firewall | Verifies source host, publisher, commit pin, and skill digest. |
| Static scan | Finds prompt injection, exfiltration, risky scripts, hidden files, binaries, and unsafe manifests. |
| Capability contract | Compares declared capabilities to observed behavior. |
| Admission controller | Produces an allow, review, or block decision from policy. |
| Lock generation | Captures reproducible file hashes and capabilities. |
| Optional pack | Creates deterministic `.skill.tgz` evidence. |

## Outputs

```text
.skillguard/passports/<skill-name>/passport.json
.skillguard/passports/<skill-name>/passport.md
.skillguard/passports/<skill-name>/passport.html
.skillguard/passports/<skill-name>/skillguard.lock.json
.skillguard/passports/<skill-name>/<skill-name>.skill.tgz
```

## Verification

Passports are meant to be checked later by another developer, reviewer, or CI job:

```bash
agent-skillguard verify-passport .skillguard/passports/code-reviewer/passport.json \
  --skill-dir ./skills/code-reviewer \
  --bundle .skillguard/passports/code-reviewer/code-reviewer.skill.tgz
```

Verification checks:

- passport schema
- embedded lock digest
- optional current skill digest
- optional bundle digest
- consistency between the passport decision and embedded control decisions

## Decision Semantics

| Decision | Meaning |
| --- | --- |
| `ALLOW` | Trust, contract, and admission controls all allow the skill. |
| `REVIEW` | No blocking control fired, but one or more controls require review. |
| `BLOCK` | Trust, contract, or admission detected a blocking violation. |

## Why This Matters

Individual scanners are useful during development, but enterprises need durable evidence. A passport can be attached to pull requests, retained in audit records, shared with security reviewers, or stored alongside vendored skills.

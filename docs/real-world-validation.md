# Real-World Validation

Validation date: 2026-05-28

This report records a reproducible smoke test against public skill repositories. The goal is not to declare those repositories malicious. A high or critical result means SkillGuard found behavior that an enterprise reviewer should inspect before installing, vendoring, or approving the skill.

## Sample

| Repository | Commit | Why included |
| --- | --- | --- |
| [anthropics/skills](https://github.com/anthropics/skills) | `690f15cac7f7` | Official public Agent Skills repository. |
| [claude-office-skills/skills](https://github.com/claude-office-skills/skills) | `9c4c7d5cd281` | Large community office-work skill collection. |
| [mattpocock/skills](https://github.com/mattpocock/skills) | `e3b90b5238f3` | Public personal Claude skill set from a developer workflow. |
| [aisa-group/promptinject-agent-skills](https://github.com/aisa-group/promptinject-agent-skills) | `6171ca7a3bb6` | Research/adversarial prompt-injection skill material. |

## Commands

```bash
git clone --depth=1 https://github.com/anthropics/skills.git anthropics-skills
git clone --depth=1 https://github.com/claude-office-skills/skills.git claude-office-skills
git clone --depth=1 https://github.com/mattpocock/skills.git mattpocock-skills
git clone --depth=1 https://github.com/aisa-group/promptinject-agent-skills.git promptinject-agent-skills

node dist/cli.js scan <repo> --sarif
node dist/cli.js intent <repo>
```

## Results

| Repository | `SKILL.md` files | Skills scanned | Files inventoried | Static findings | Static risk | Intent decision | Intent signals | Intent risk |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| `anthropics-skills` | 18 | 18 | 389 | 17 | 100 | `review` | 15 | 100 |
| `claude-office-skills` | 137 | 137 | 142 | 6 | 100 | `review` | 39 | 100 |
| `mattpocock-skills` | 29 | 29 | 55 | 1 | 55 | `review` | 11 | 100 |
| `promptinject-agent-skills` | 2 | 2 | 123 | 2 | 100 | `review` | 2 | 100 |

## What It Found

Static scan categories:

| Repository | Main categories |
| --- | --- |
| `anthropics-skills` | broad network/shell/write capability chains, explicit secret-handling phrases, unpinned remote examples, one binary payload. |
| `claude-office-skills` | broad network/shell/write capability chains and explicit credential-theft wording in sample text. |
| `mattpocock-skills` | one broad network/shell/write capability chain. |
| `promptinject-agent-skills` | broad network/shell/write capability chains in presentation-related skills. |

Intent firewall categories:

| Repository | Main categories |
| --- | --- |
| `anthropics-skills` | approval-bypass language, persistence/memory language, missing approval boundaries for powerful capabilities. |
| `claude-office-skills` | missing approval boundaries for powerful capabilities. |
| `mattpocock-skills` | missing approval boundaries, approval-bypass language, persistence/memory language. |
| `promptinject-agent-skills` | approval-bypass language. |

## Validation-Driven Fix

The first pass exposed noisy matches in API-reference text where words like `token`, `POST`, or `upload` were not necessarily exfiltration. The scanner was tightened so critical secret-exfiltration findings now require stronger evidence such as:

- explicit steal/exfiltrate/harvest/leak language near secrets
- send/upload/post of sensitive material to an external target
- direct reading of `.env`, `.ssh`, credentials, secrets, or API keys

The Semantic Intent Firewall was also tightened so compliance/audit secret collection requires an action verb such as `collect`, `read`, `extract`, `export`, `send`, or `upload`.

## Interpretation

This validation proves four things:

- SkillGuard can parse real public skill repositories at non-trivial scale.
- It produces SARIF/JSON/Markdown artifacts without requiring cloud services or API keys.
- It catches obvious adversarial or review-worthy patterns in real skill material.
- Real-world validation improved the rules by reducing noisy API-reference matches.

Known limitation: these are deterministic heuristics, not proof of maliciousness. The right enterprise posture is to treat high-risk outputs as review gates and use Skill Passport for retained approval evidence.

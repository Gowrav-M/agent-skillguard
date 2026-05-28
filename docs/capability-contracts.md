# Capability Contracts

Agent skills need a least-privilege contract. A `SKILL.md` should declare what power it needs, and tooling should block behavior that exceeds that declaration.

```bash
agent-skillguard contract ./skills
```

## What It Checks

SkillGuard compares:

- `declaredCapabilities` from `SKILL.md` frontmatter
- observed capabilities inferred from scripts, manifests, URLs, tool descriptors, secret access language, shell commands, package installs, git writes, and MCP mutation patterns

## Decisions

| Decision | Meaning |
| --- | --- |
| `ALLOW` | Observed capabilities stay inside the declared contract. |
| `BLOCK` | Observed behavior exceeds the declared contract. |

## Example

Declared:

```yaml
capabilities: [filesystem-read]
```

Observed:

```text
filesystem-read, secret-access
```

Result:

```text
BLOCK contract.undeclared.secret-access
```

## Why This Matters

Enterprise approval cannot rely on prompt text alone. A skill that claims to be read-only but contains hidden instructions to read `.env` and send API keys is violating a least-privilege contract. This layer catches that mismatch before the skill is installed or run.

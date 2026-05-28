# Semantic Intent Firewall

Static scanners catch obvious payloads. Agent skills also create a softer risk: natural-language instructions can make the agent synthesize unsafe behavior later.

```bash
agent-skillguard intent ./skills --fail-on high
```

The firewall looks for intent-level signals:

- compliance-framed secret collection
- approval bypass language
- skill selection hijacking
- instruction priority inversion
- remote instruction loading
- persistent memory, startup, profile, or background behavior
- missing approval boundaries around powerful capabilities

Outputs:

```text
.skillguard/reports/skillguard-intent.json
.skillguard/reports/skillguard-intent.md
```

Skill Passport includes this review, so a passport can block a skill that has no obvious script payload but still tries to steer the agent into unsafe runtime behavior.

# Examples

`examples/skills` contains fixtures used by tests and the demo command.

| Example | Purpose |
| --- | --- |
| `safe-code-reviewer` | Read-only skill that should pass. |
| `prompt-injected-skill` | Hidden HTML comment tries to override policy and exfiltrate secrets. |
| `dangerous-installer` | Installer uses `curl | sh`. |
| `hidden-unicode` | Contains a hidden Unicode control character. |
| `mcp-mutating-tool` | Bundles a descriptor for mutating MCP-style tool behavior. |

Try:

```bash
npx agent-skillguard scan examples/skills --sarif
npx agent-skillguard admit examples/skills --sarif
npx agent-skillguard lock examples/skills/safe-code-reviewer
npx agent-skillguard pack examples/skills/safe-code-reviewer
npx agent-skillguard verify safe-code-reviewer.skill.tgz
```

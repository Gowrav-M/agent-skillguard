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
npx agent-skillguard passport examples/skills/safe-code-reviewer --source https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/safe-code-reviewer --commit 0123456789abcdef0123456789abcdef01234567 --publisher Gowrav-M --pack
npx agent-skillguard scan examples/skills --sarif
npx agent-skillguard trust examples/skills/safe-code-reviewer --source https://github.com/Gowrav-M/agent-skillguard/tree/main/examples/skills/safe-code-reviewer --commit 0123456789abcdef0123456789abcdef01234567 --publisher Gowrav-M
npx agent-skillguard contract examples/skills
npx agent-skillguard admit examples/skills --sarif
npx agent-skillguard review-update examples/skills/safe-code-reviewer examples/skills/dangerous-installer
npx agent-skillguard lock examples/skills/safe-code-reviewer
npx agent-skillguard pack examples/skills/safe-code-reviewer
npx agent-skillguard verify safe-code-reviewer.skill.tgz
```

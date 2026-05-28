# CI Usage

Run SkillGuard in pull requests to prevent unsafe skills from entering a repository.

```yaml
name: skillguard
on:
  pull_request:
    paths:
      - "skills/**"
      - ".github/workflows/skillguard.yml"

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - run: npx agent-skillguard scan ./skills --sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .skillguard/reports/skillguard-report.sarif
```

Use `--fail-on critical` for a softer first rollout and `--fail-on high` once teams are ready to block broad capability chains and install hooks.

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
      - run: npx agent-skillguard admit ./skills --require-lock --sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .skillguard/reports/skillguard-report.sarif
```

## Provenance Gate

For vendored skills, require immutable source metadata:

```yaml
- run: >
    npx agent-skillguard trust ./skills/code-reviewer
    --source https://github.com/org/repo/tree/main/skills/code-reviewer
    --commit ${{ github.sha }}
    --publisher org
```

## Capability Contract Gate

Block skills that use power they did not declare:

```yaml
- run: npx agent-skillguard contract ./skills
```

For early rollout, use `agent-skillguard admit ./skills --sarif` without `--require-lock`. Once the team has approved skill locks, enable `--require-lock` so unreviewed skill drift fails pull requests.

## Update Review

When a repository vendors approved skills and receives candidate updates in a separate folder, block risky drift:

```yaml
- run: npx agent-skillguard review-update ./skills-approved/code-reviewer ./skills-incoming/code-reviewer
```

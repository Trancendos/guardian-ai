# Portfolio Governance Gap Report

Generated at: 2026-02-22T17:29:57.712Z  
Organization: Trancendos

## Snapshot

- Total repositories reviewed: **95**
- Repositories with Dependabot: **19/95**
- Repositories with a security workflow: **9/95**
- Repositories with CI workflow: **34/95**
- Repositories with CodeQL: **8/95**
- Repositories with SECURITY.md: **9/95**
- Repositories with CODEOWNERS: **17/95**

## Architecture and modularity signals

- Repositories with `the-` prefix: **16**
- Repositories with `-ai` suffix: **21**
- This naming density indicates likely overlap in service boundaries.  
  Prioritize explicit contracts and repo ownership maps before additional splitting.

## Highest-risk repositories (top 40 by governance score)

| Repository | Risk tier | Score | Language | Updated (days ago) | Dependabot | Security WF | CI WF | CodeQL | SECURITY.md | CODEOWNERS |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| Trancendos/mcpmcp-server | critical | 8 | Unknown | 49 | N | N | N | N | N | N |
| Trancendos/github-app-check-trigger | critical | 8 | Unknown | 49 | N | N | N | N | N | N |
| Trancendos/engine-core | critical | 8 | TypeScript | 49 | N | N | N | N | N | N |
| Trancendos/skills-for-emu | critical | 8 | Unknown | 34 | N | N | N | N | N | N |
| Trancendos/qodo-ci-example | critical | 8 | JavaScript | 34 | N | N | N | N | N | N |
| Trancendos/qodo-ci | critical | 8 | Unknown | 34 | N | N | N | N | N | N |
| Trancendos/product-workshop | critical | 8 | HTML | 34 | N | N | N | N | N | N |
| Trancendos/pr-compliance-templates | critical | 8 | Unknown | 34 | N | N | N | N | N | N |
| Trancendos/command | critical | 8 | Unknown | 34 | N | N | N | N | N | N |
| Trancendos/BBDC-App-Releases | critical | 8 | Unknown | 34 | N | N | N | N | N | N |
| Trancendos/aware-swe-agent | critical | 8 | Python | 34 | N | N | N | N | N | N |
| Trancendos/auto-code-rover-action | critical | 8 | Unknown | 34 | N | N | N | N | N | N |
| Trancendos/ai-pr-reviewer | critical | 8 | Python | 33 | N | N | N | N | N | N |
| Trancendos/the-treasury | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-sanctuary | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-observatory | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-nexus | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-lighthouse | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-library | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-ice-box | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-hive | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-foundation | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-forge | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-dr-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-cryptex | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-citadel | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/the-agora | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/solarscene-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/serenity-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/sentinel-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/renik-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/queen-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/prometheus-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/porter-family-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/oracle-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/norman-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/nexus-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/mercury-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/lunascene-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |
| Trancendos/lille-sc-ai | critical | 8 | TypeScript | 29 | N | N | N | N | N | N |

## Governance rollout plan (N-to-N-1 and CVE management)

1. Apply a standard security baseline to every active repo:
   - `.github/dependabot.yml`
   - `.github/workflows/security.yml`
   - `.github/workflows/codeql.yml`
   - `SECURITY.md`
   - `CODEOWNERS`
2. Enforce branch protection requiring CI + security checks.
3. Add SBOM generation and artifact retention for all deployable repos.
4. Set remediation SLAs and automate issue creation for failed security checks.
5. Run this portfolio audit weekly and track closure by risk tier.

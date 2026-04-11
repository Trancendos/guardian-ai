# Security Operations Runbook

## Purpose

Provide a repeatable process to keep repositories continuously protected against
CVE exposure, dependency drift, and unmanaged integration risk.

## Baseline controls (required in each active repository)

1. `.github/dependabot.yml`
2. `.github/workflows/security.yml`
3. `.github/workflows/codeql.yml`
4. `SECURITY.md`
5. `CODEOWNERS`
6. Branch protection requiring CI + security workflows

## Proactive management measures

### 1) Continuous CVE detection

- `npm audit --audit-level=high` on push, PR, and schedule.
- Trivy filesystem scan for HIGH/CRITICAL vulnerability classes.
- CodeQL scan for semantic security issues.

### 2) Dependency freshness policy (N-to-N-1)

- Enforce with `npm run deps:n-policy`.
- Any package older than one major behind latest is non-compliant.
- Dependabot handles routine patch/minor updates automatically.

### 3) SBOM and traceability

- Generate CycloneDX SBOM in security workflow.
- Retain SBOM artifacts for incident response and compliance evidence.

### 4) SLA and escalation

- Critical: 24h
- High: 3 business days
- Medium: 14 days
- Low: next routine cycle

Escalate unresolved HIGH/CRITICAL items to platform owners immediately.

## Weekly operating cadence

1. Review failed security jobs across all repos.
2. Triage open Dependabot PRs and merge safe updates.
3. Re-run portfolio audit:

   ```bash
   npm run portfolio:audit
   ```

4. Rebuild remediation waves and publish tracker:

   ```bash
   npm run portfolio:plan
   ```

5. Queue remediation tasks (dry-run first):

   ```bash
   npm run portfolio:issues:dryrun
   node scripts/open-remediation-issues.mjs --wave 1 --limit 20 --execute
   ```

6. Track progress and blockers:

   ```bash
   npm run portfolio:issues:summary
   ```

7. Audit PR health and production readiness:

   ```bash
   npm run portfolio:pr:audit
   npm run portfolio:readiness
   ```

8. For stale draft PR backlog (safe cleanup), execute dry-run then close:

   ```bash
   npm run portfolio:pr:unblock:dryrun
   node scripts/unblock-pr-backlog.mjs --repo Trancendos/auto-code-rover-action --days 21 --limit 50
   ```

9. Prioritize repositories in `critical` risk tier until reduced to `medium` or lower.

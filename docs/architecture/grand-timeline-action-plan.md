# Grand Timeline: Repository Security and Modular Architecture Recovery

## Executive status

- Portfolio reviewed: **95 repositories**
- Governance baseline coverage is currently low:
  - Dependabot: **19/95**
  - Security workflow: **9/95**
  - CI workflow: **34/95**
  - CodeQL: **8/95**
  - SECURITY policy: **9/95**
  - CODEOWNERS: **17/95**
- Naming overlap signals modular boundary drift:
  - `the-*` repositories: **16**
  - `*-ai` repositories: **21**

Reference report: `docs/architecture/portfolio-gap-report.md`

## Scope requirements by repository class

### Class A: Core platform repos (must remain separate)

Examples: `shared-core`, `central-plexus`, `engine-core`, `infrastructure`, `secrets-portal`

Required:
- Strict security baseline controls
- Release/version contracts
- Backward-compatible API governance
- SBOM publication and signed release artifacts

### Class B: Domain service repos (evaluate for merge by bounded context)

Examples: `the-*`, many `*-ai` persona/domain repos

Required:
- Explicit service contract (OpenAPI/events/schema)
- Owner + escalation path
- Integration tests to and from orchestrators
- Decision per repo: keep separate vs merge into domain package

### Class C: Tooling/sandbox/fork repos (separate from production surface)

Examples: tutorials, upstream mirrors, experiments, demos

Required:
- Mark clearly as `sandbox`/`reference`
- Archive or move if not operationally required
- Exclude from production dependency graphs

## Merge vs separate recommendations

### Keep separate (high-value boundaries)

1. `shared-core` as canonical shared contracts/types library.
2. Security-sensitive services (`the-cryptex`, `the-void`, `secrets-portal`).
3. Infrastructure and orchestration control planes.

### Candidate merge groups (if code ownership and interfaces overlap)

1. `the-*` suite into fewer bounded-context repos:
   - `ops-platform` (observability, scheduling, orchestration)
   - `knowledge-platform` (library, workshop, hive, agora)
   - `security-platform` (citadel, cryptex, void)
2. `*-ai` personas with similar runtime/deployment into shared domain repos
   with internal modules rather than one-repo-per-agent.

Decision rule: if two repos share >60% runtime dependencies and deploy as one
unit, merge; if they have distinct data/security boundaries, keep separate.

## Timeline

### Phase 0 (Week 0-1): Stabilize controls

- Roll out security baseline files to all active repos.
- Enable branch protection and required checks.
- Produce first complete risk register from portfolio audit output.

### Phase 1 (Week 2-4): Reduce critical exposure

- Triage and fix all `critical` governance-score repos.
- Resolve HIGH/CRITICAL CVEs and enforce remediation SLA.
- Reach minimum baseline target:
  - Dependabot >= 70%
  - Security workflow >= 60%
  - CodeQL >= 50%

### Phase 2 (Week 5-8): Enforce modular contracts

- Define service contracts for Class B repos.
- Build ownership map and integration matrix.
- Complete merge/split decisions with RFC approvals.

### Phase 3 (Week 9-12): Execute architecture reshape

- Perform approved merge operations (with migration plans).
- Split repos only where data/security boundaries require isolation.
- Validate interoperability with integration tests and deployment canaries.

### Phase 4 (Week 13-16): Operationalize

- Weekly automated portfolio audit in CI.
- Dashboard for CVE, dependency lag, and contract compliance.
- Quarterly architecture review against domain boundaries.

## Completion review checklist

| Workstream | Target | Current status |
|---|---:|---|
| Security baseline adoption | 95/95 | In progress |
| N-to-N-1 policy enforcement | 95/95 | In progress |
| CVE SLA runbook adoption | 95/95 | In progress |
| Service contract inventory | 95/95 | Not started |
| Merge/split RFC decisions | all candidate groups | Not started |
| Integration test coverage for cross-repo flows | 100% critical flows | Not started |

## Definition of done

1. No repo is missing baseline security controls.
2. No production dependency is older than N-1.
3. No unresolved HIGH/CRITICAL CVEs beyond SLA.
4. Every repo has explicit owner, contract, and lifecycle state.
5. Merge/split execution complete with verified integration behavior.

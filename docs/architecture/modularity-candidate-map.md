# Modularity Candidate Map

Generated at: 2026-02-22T19:17:39.617Z

## Keep separate candidates (core/security boundaries)

- Trancendos/.github
- Trancendos/central-plexus
- Trancendos/engine-core
- Trancendos/guardian-ai
- Trancendos/infrastructure
- Trancendos/secrets-portal
- Trancendos/shared-core
- Trancendos/the-citadel
- Trancendos/the-cryptex
- Trancendos/the-void
- Trancendos/trancendos-ecosystem

## Candidate merge family: `the-*`

Count: **16**

- Trancendos/the-agora
- Trancendos/the-citadel
- Trancendos/the-cryptex
- Trancendos/the-dr-ai
- Trancendos/the-forge
- Trancendos/the-foundation
- Trancendos/the-hive
- Trancendos/the-ice-box
- Trancendos/the-library
- Trancendos/the-lighthouse
- Trancendos/the-nexus
- Trancendos/the-observatory
- Trancendos/the-sanctuary
- Trancendos/the-treasury
- Trancendos/the-void
- Trancendos/the-workshop

## Candidate merge family: `*-ai`

Count: **21**

- Trancendos/atlas-ai
- Trancendos/chronos-ai
- Trancendos/cornelius-ai
- Trancendos/dorris-ai
- Trancendos/echo-ai
- Trancendos/guardian-ai
- Trancendos/iris-ai
- Trancendos/lille-sc-ai
- Trancendos/lunascene-ai
- Trancendos/mercury-ai
- Trancendos/nexus-ai
- Trancendos/norman-ai
- Trancendos/oracle-ai
- Trancendos/porter-family-ai
- Trancendos/prometheus-ai
- Trancendos/queen-ai
- Trancendos/renik-ai
- Trancendos/sentinel-ai
- Trancendos/serenity-ai
- Trancendos/solarscene-ai
- Trancendos/the-dr-ai

## Decision rule

- Merge if two repos share the same deployment unit and >60% runtime dependencies.
- Keep separate if data domain, security boundary, or ownership boundary differs.
- Archive or exclude repos that are reference/sandbox-only.

## Wave 2 — Guardian AI: Full Zero-Trust IAM Implementation

Migrates Guardian's protection capabilities from the Trancendos monorepo into a standalone, production-ready service.

### What's included

**IAM — Role-Based Access Control** (`src/iam/permissions.ts`)
- 17 `AgentPermission` values covering agents, tasks, messages, admin, secrets, audit
- 5 `UserRole` types: `owner`, `admin`, `user`, `guest`, `agent`
- `PermissionChecker` class: `hasPermission`, `hasAllPermissions`, `hasAnyPermission`, `getEffectivePermissions`, `assertPermission`

**Agent Tokens — 500ms TTL** (`src/tokens/agent-tokens.ts`)
- `AgentTokenService` with HMAC-SHA256 signing and base64url encoding
- 500ms default TTL per PDF architecture specification
- Token revocation via JTI tracking
- Behavioral baseline management: `setBaseline`, `getBaseline`, `updateBaseline`
- Anomaly detection: `checkBehavior` with scoring (rate spike, unknown capability, unknown target)
- Context declaration validation: principle of least privilege enforcement
- Request rate tracking with 1-minute sliding window

**Zero-Trust Policy Engine** (`src/zero-trust/zero-trust.ts`)
- `ZeroTrustEngine` with 7-step evaluation pipeline
- 8 threat categories: `privilege_escalation`, `lateral_movement`, `data_exfiltration`, `replay_attack`, `impersonation`, `anomalous_behavior`, `policy_violation`, `sandbox_escape`
- 7 default policies (priority-ordered): block high-risk, challenge unknown agents, deny privilege escalation, monitor sandbox escape, block guest writes, require context declaration, allow owner full access
- Trust levels: `untrusted`, `low`, `medium`, `high`, `verified`
- Sandbox policy enforcement with resource limits and network policies
- Full audit log (capped at 10,000 entries) with filtering

**REST API** (`src/api/server.ts`) — 22 endpoints
- Token: issue, verify, revoke, history
- Zero-trust: evaluate, policies CRUD, audit log, stats
- Baselines: list, get, set, check behavior
- Sandbox: get, set, check operation
- Permissions: list roles, check permission
- System: health, metrics

**Bootstrap** (`src/index.ts`)
- Seeds behavioral baselines for 4 known system agents (cornelius-ai, the-dr-ai, norman-ai, dorris-ai)
- Seeds sandbox policies for the-dr-ai and norman-ai
- Graceful shutdown with final stats logging
- Hourly audit log stats cycle

### Migrated from
- `server/services/guardianEnhanced.ts`
- `server/services/agentAuth.ts`
- `server/services/agentSandbox.ts`
- `server/services/aiIntercommunication.ts`

### Architecture
Trancendos Industry 6.0 / 2060 Standard — Wave 2 Primary Agents
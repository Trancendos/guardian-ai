# Guardian AI

Zero-trust IAM gateway and behavioral security engine for the Trancendos 24-agent mesh.

## Overview

Guardian AI is the security backbone of the Trancendos Industry 6.0 architecture. It enforces zero-trust principles across all agent-to-agent and user-to-agent interactions, issuing short-lived cryptographic tokens, maintaining behavioral baselines, detecting threats in real time, and providing a full audit trail of every access decision.

**Migrated from:** `server/services/guardianEnhanced.ts` + `agentAuth.ts` + `agentSandbox.ts` + `aiIntercommunication.ts`

## Architecture

```
guardian-ai/
├── src/
│   ├── iam/
│   │   └── permissions.ts       # RBAC — 17 permissions, 5 roles
│   ├── tokens/
│   │   └── agent-tokens.ts      # 500ms TTL agent tokens + behavioral baseline
│   ├── zero-trust/
│   │   └── zero-trust.ts        # Zero-trust policy engine + threat detection
│   ├── api/
│   │   └── server.ts            # REST API — 22 endpoints
│   ├── utils/
│   │   └── logger.ts            # Pino structured logging
│   └── index.ts                 # Bootstrap + system agent seeding
├── package.json
├── tsconfig.json
└── README.md
```

## Core Principles

1. **Never trust, always verify** — every request is evaluated regardless of source
2. **Context declarations required** — agents must declare intent before token issuance
3. **Least privilege** — only grant what is explicitly needed for the declared task
4. **500ms TTL tokens** — short-lived cryptographic tokens prevent replay attacks
5. **Behavioral baselines** — anomaly detection flags deviations from normal patterns
6. **Full audit trail** — every access decision is logged with evidence

## Key Components

### IAM — Role-Based Access Control

Five roles with 17 granular permissions:

| Role    | Permissions |
|---------|-------------|
| `owner` | All 17 permissions |
| `admin` | 14 permissions (no manage_users, manage_secrets, modify_permissions) |
| `user`  | 7 permissions (view/delegate tasks, send messages, view logs) |
| `guest` | 3 permissions (view_agent, view_task, view_conversation) |
| `agent` | 8 permissions (delegate, send_message, view_conversation, execute_sandbox, view_logs, rollback, view_task, cancel_task) |

### Agent Tokens — 500ms TTL

```typescript
// Issue a token
const token = agentTokenService.issueToken(
  'cornelius-ai',           // issuer
  'the-dr-ai',              // target
  {
    taskId: 'task-123',
    requestedCapabilities: ['diagnose', 'heal'],
    declaredPurpose: 'Healing memory leak in service X',
    riskLevel: 'medium',
  },
  [AgentPermission.EXECUTE_SANDBOX, AgentPermission.ROLLBACK],
  500,                      // TTL in ms
);

// Verify a token
const result = agentTokenService.verifyToken(token, 'the-dr-ai');
// { valid: true, payload: { jti, iss, sub, iat, exp, context, permissions } }
```

Token structure:
- **Header:** `{ alg: 'HS256', typ: 'JWT' }`
- **Payload:** `{ jti, iss, sub, iat, exp, ttl, context, permissions }`
- **Signature:** HMAC-SHA256 with configurable secret

### Zero-Trust Policy Engine

Evaluates every request through a 7-step pipeline:

1. **Context validation** — declared purpose and capabilities must be present
2. **Behavioral baseline check** — compare against historical patterns
3. **Threat detection** — 5 threat categories (privilege escalation, lateral movement, data exfiltration, replay attack, impersonation)
4. **Trust level calculation** — `untrusted | low | medium | high | verified`
5. **Policy evaluation** — 7 default policies, priority-ordered
6. **Permission filtering** — grant only role-permitted, trust-level-appropriate permissions
7. **Token issuance** — 500ms token issued on allow/monitor decisions

Default policies (priority order):
1. Block High-Risk Requests (priority 1)
2. Challenge Unknown Agents (priority 2)
3. Monitor Privilege Escalation Attempts (priority 3)
4. Monitor Sandbox Escape Attempts (priority 4)
5. Block Guest Sensitive Operations (priority 5)
6. Require Context Declaration (priority 6)
7. Allow Owner Full Access (priority 10)

### Behavioral Baseline

Tracks per-agent behavioral patterns:
- `typicalRequestRate` — requests per minute
- `typicalCapabilities` — normal capability set
- `typicalTargets` — agents typically accessed
- `sampleCount` — observations used to build baseline

Anomaly scoring (0–1):
- Rate spike > 3x baseline → +0.4
- Unknown capability → +0.2 per capability
- Unknown target → +0.15 per target

### Sandbox Enforcement

Per-agent sandbox policies with:
- `allowedOperations` / `deniedOperations` — explicit operation lists
- `resourceLimits` — memory, CPU, disk, network, execution time
- `networkPolicy` — allowed/denied hosts and ports

## API Reference

### Token Endpoints

```
POST   /api/v1/tokens/issue
POST   /api/v1/tokens/verify
DELETE /api/v1/tokens/:jti
GET    /api/v1/tokens/history/:agentId
```

**Issue token:**
```json
POST /api/v1/tokens/issue
{
  "issuerAgentId": "cornelius-ai",
  "targetAgentId": "the-dr-ai",
  "context": {
    "taskId": "task-123",
    "requestedCapabilities": ["diagnose"],
    "declaredPurpose": "Diagnose memory leak",
    "riskLevel": "low"
  },
  "permissions": ["execute_sandbox"],
  "ttlMs": 500
}
```

**Verify token:**
```json
POST /api/v1/tokens/verify
{
  "token": "<token>",
  "expectedTarget": "the-dr-ai"
}
```

### Zero-Trust Endpoints

```
POST   /api/v1/zero-trust/evaluate
GET    /api/v1/zero-trust/policies
POST   /api/v1/zero-trust/policies
PUT    /api/v1/zero-trust/policies/:id
DELETE /api/v1/zero-trust/policies/:id
GET    /api/v1/zero-trust/audit
GET    /api/v1/zero-trust/stats
```

**Evaluate request:**
```json
POST /api/v1/zero-trust/evaluate
{
  "sourceAgentId": "cornelius-ai",
  "targetAgentId": "the-dr-ai",
  "sourceRole": "agent",
  "context": {
    "taskId": "task-123",
    "requestedCapabilities": ["diagnose", "heal"],
    "declaredPurpose": "Auto-healing triggered by anomaly detection",
    "riskLevel": "medium"
  },
  "requestedPermissions": ["execute_sandbox", "rollback"]
}
```

**Response:**
```json
{
  "requestId": "uuid",
  "allowed": true,
  "action": "allow",
  "trustLevel": "high",
  "grantedPermissions": ["execute_sandbox", "rollback"],
  "deniedPermissions": [],
  "appliedPolicies": ["Allow Owner Full Access"],
  "threats": [],
  "token": "<500ms-token>",
  "reason": "...",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "expiresAt": "2024-01-01T00:00:00.500Z"
}
```

### Baseline Endpoints

```
GET    /api/v1/baselines
GET    /api/v1/baselines/:agentId
POST   /api/v1/baselines/:agentId
POST   /api/v1/baselines/:agentId/check
```

### Sandbox Endpoints

```
GET    /api/v1/sandbox/:agentId
POST   /api/v1/sandbox/:agentId
POST   /api/v1/sandbox/:agentId/check
```

### Permission Endpoints

```
GET    /api/v1/permissions/roles
POST   /api/v1/permissions/check
```

### System Endpoints

```
GET    /health
GET    /metrics
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3004` | HTTP server port |
| `HOST` | `0.0.0.0` | HTTP server host |
| `NODE_ENV` | `development` | Environment |
| `LOG_LEVEL` | `info` | Pino log level |
| `TOKEN_SECRET` | auto-generated | HMAC secret for token signing |
| `DEFAULT_TOKEN_TTL_MS` | `500` | Default token TTL in milliseconds |
| `AUDIT_RETENTION_HOURS` | `24` | Audit log retention period |

## Getting Started

```bash
# Install dependencies
npm install

# Development (hot reload)
npm run dev

# Build
npm run build

# Production
npm start
```

## Integration with Agent Mesh

Guardian AI runs on port `3004` by default. All agents in the mesh should:

1. Call `POST /api/v1/zero-trust/evaluate` before any inter-agent operation
2. Include the returned token in subsequent requests
3. Tokens expire after 500ms — re-evaluate for each operation
4. Register behavioral baselines on startup via `POST /api/v1/baselines/:agentId`

## Threat Detection

Guardian detects 8 threat categories in real time:

| Category | Detection Method |
|----------|-----------------|
| `privilege_escalation` | Permissions beyond role scope |
| `lateral_movement` | >5 unique targets in 60 seconds |
| `data_exfiltration` | Multiple data permissions at high risk |
| `replay_attack` | >10 tokens in 2 seconds |
| `impersonation` | Role/ID mismatch |
| `anomalous_behavior` | Behavioral baseline deviation |
| `policy_violation` | Explicit policy denial |
| `sandbox_escape` | Sandbox operation outside policy |

---

*Part of the Trancendos Industry 6.0 / 2060 Standard architecture.*
*Migrated from the Trancendos monorepo — Wave 2 primary agents.*
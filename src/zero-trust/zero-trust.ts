/**
 * Guardian — Zero-Trust Policy Engine
 *
 * Implements "never trust, always verify" for all agent-to-agent
 * and user-to-agent interactions in the Trancendos mesh.
 *
 * Core principles:
 *   1. Every request is treated as potentially hostile
 *   2. Context declarations are mandatory before token issuance
 *   3. Least-privilege: only grant what is explicitly needed
 *   4. Continuous verification: tokens expire in 500ms
 *   5. Audit everything: every decision is logged
 *
 * Migrated from: server/services/guardianEnhanced.ts + agentSandbox.ts + aiIntercommunication.ts
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { AgentPermission, UserRole, ROLE_PERMISSIONS, permissionChecker } from '../iam/permissions';
import { agentTokenService, AgentContext, BehavioralBaseline } from '../tokens/agent-tokens';

// ============================================================================
// TYPES
// ============================================================================

export type TrustLevel = 'untrusted' | 'low' | 'medium' | 'high' | 'verified';
export type PolicyAction = 'allow' | 'deny' | 'challenge' | 'monitor';
export type ThreatCategory =
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'data_exfiltration'
  | 'replay_attack'
  | 'impersonation'
  | 'anomalous_behavior'
  | 'policy_violation'
  | 'sandbox_escape';

export interface ZeroTrustPolicy {
  id: string;
  name: string;
  description: string;
  priority: number;           // Lower = higher priority
  conditions: PolicyCondition[];
  action: PolicyAction;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface PolicyCondition {
  field: string;              // e.g. 'riskLevel', 'requestedCapabilities', 'sourceRole'
  operator: 'eq' | 'neq' | 'in' | 'not_in' | 'gt' | 'lt' | 'contains' | 'not_contains';
  value: unknown;
}

export interface ZeroTrustRequest {
  requestId: string;
  sourceAgentId: string;
  targetAgentId: string;
  sourceRole: UserRole | 'agent';
  context: AgentContext;
  requestedPermissions: AgentPermission[];
  timestamp: Date;
  ipAddress?: string;
  sessionId?: string;
}

export interface ZeroTrustDecision {
  requestId: string;
  allowed: boolean;
  action: PolicyAction;
  trustLevel: TrustLevel;
  grantedPermissions: AgentPermission[];
  deniedPermissions: AgentPermission[];
  appliedPolicies: string[];
  threats: ThreatAssessment[];
  token?: string;
  reason: string;
  timestamp: Date;
  expiresAt?: Date;
}

export interface ThreatAssessment {
  id: string;
  category: ThreatCategory;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;         // 0-1
  description: string;
  evidence: string[];
  mitigated: boolean;
}

export interface SandboxPolicy {
  agentId: string;
  allowedOperations: string[];
  deniedOperations: string[];
  resourceLimits: ResourceLimits;
  networkPolicy: NetworkPolicy;
  enabled: boolean;
}

export interface ResourceLimits {
  maxMemoryMb: number;
  maxCpuPercent: number;
  maxDiskMb: number;
  maxNetworkKbps: number;
  maxExecutionMs: number;
}

export interface NetworkPolicy {
  allowedHosts: string[];
  deniedHosts: string[];
  allowedPorts: number[];
  allowOutbound: boolean;
  allowInbound: boolean;
}

export interface AuditEntry {
  id: string;
  timestamp: Date;
  requestId: string;
  sourceAgentId: string;
  targetAgentId: string;
  action: PolicyAction;
  allowed: boolean;
  trustLevel: TrustLevel;
  threats: ThreatCategory[];
  appliedPolicies: string[];
  durationMs: number;
}

export interface ZeroTrustStats {
  totalRequests: number;
  allowedRequests: number;
  deniedRequests: number;
  challengedRequests: number;
  monitoredRequests: number;
  threatsDetected: number;
  threatsByCategory: Record<ThreatCategory, number>;
  averageDecisionMs: number;
  policyCount: number;
  sandboxCount: number;
}

// ============================================================================
// DEFAULT POLICIES
// ============================================================================

const DEFAULT_POLICIES: Omit<ZeroTrustPolicy, 'id' | 'createdAt' | 'updatedAt'>[] = [
  {
    name: 'Block High-Risk Requests',
    description: 'Deny any request with riskLevel=high unless from owner role',
    priority: 1,
    conditions: [
      { field: 'context.riskLevel', operator: 'eq', value: 'high' },
      { field: 'sourceRole', operator: 'neq', value: 'owner' },
    ],
    action: 'deny',
    enabled: true,
  },
  {
    name: 'Challenge Unknown Agents',
    description: 'Challenge requests from agents with no behavioral baseline',
    priority: 2,
    conditions: [
      { field: 'sourceRole', operator: 'eq', value: 'agent' },
      { field: 'hasBaseline', operator: 'eq', value: false },
    ],
    action: 'challenge',
    enabled: true,
  },
  {
    name: 'Monitor Privilege Escalation Attempts',
    description: 'Monitor requests for admin-level permissions from non-admin roles',
    priority: 3,
    conditions: [
      { field: 'requestedPermissions', operator: 'contains', value: AgentPermission.MODIFY_PERMISSIONS },
      { field: 'sourceRole', operator: 'not_in', value: ['owner', 'admin'] },
    ],
    action: 'deny',
    enabled: true,
  },
  {
    name: 'Allow Owner Full Access',
    description: 'Owner role has unrestricted access',
    priority: 10,
    conditions: [
      { field: 'sourceRole', operator: 'eq', value: 'owner' },
    ],
    action: 'allow',
    enabled: true,
  },
  {
    name: 'Block Guest Sensitive Operations',
    description: 'Guest role cannot perform write operations',
    priority: 5,
    conditions: [
      { field: 'sourceRole', operator: 'eq', value: 'guest' },
      { field: 'requestedPermissions', operator: 'contains', value: AgentPermission.CREATE_AGENT },
    ],
    action: 'deny',
    enabled: true,
  },
  {
    name: 'Monitor Sandbox Escape Attempts',
    description: 'Flag any attempt to execute outside declared sandbox',
    priority: 4,
    conditions: [
      { field: 'requestedPermissions', operator: 'contains', value: AgentPermission.EXECUTE_SANDBOX },
      { field: 'context.riskLevel', operator: 'in', value: ['medium', 'high'] },
    ],
    action: 'monitor',
    enabled: true,
  },
  {
    name: 'Require Context Declaration',
    description: 'All agent requests must have a declared purpose',
    priority: 6,
    conditions: [
      { field: 'context.declaredPurpose', operator: 'eq', value: '' },
    ],
    action: 'deny',
    enabled: true,
  },
];

// ============================================================================
// ZERO-TRUST ENGINE
// ============================================================================

export class ZeroTrustEngine {
  private policies: Map<string, ZeroTrustPolicy> = new Map();
  private sandboxPolicies: Map<string, SandboxPolicy> = new Map();
  private auditLog: AuditEntry[] = [];
  private stats: ZeroTrustStats;
  private decisionTimes: number[] = [];

  constructor() {
    this.stats = this.initStats();
    this.loadDefaultPolicies();
    logger.info({ policyCount: this.policies.size }, 'ZeroTrustEngine initialised');
  }

  // --------------------------------------------------------------------------
  // CORE DECISION ENGINE
  // --------------------------------------------------------------------------

  /**
   * Evaluate a zero-trust request and return an access decision.
   * This is the primary entry point for all access control.
   */
  evaluate(request: ZeroTrustRequest): ZeroTrustDecision {
    const startMs = Date.now();
    const threats: ThreatAssessment[] = [];
    const appliedPolicies: string[] = [];

    logger.debug({ requestId: request.requestId, source: request.sourceAgentId, target: request.targetAgentId }, 'Evaluating zero-trust request');

    // Step 1: Validate context declaration
    const contextValidation = agentTokenService.validateContextDeclaration(request.context);
    if (!contextValidation.valid) {
      const decision = this.buildDecision(request, 'deny', 'untrusted', [], request.requestedPermissions, ['context-validation'], threats, `Context declaration invalid: ${contextValidation.issues.join(', ')}`);
      this.recordAudit(request, decision, Date.now() - startMs);
      return decision;
    }

    // Step 2: Assess behavioral baseline
    const behaviorCheck = agentTokenService.checkBehavior(
      request.sourceAgentId,
      request.context.requestedCapabilities,
      request.targetAgentId,
    );

    if (!behaviorCheck.allowed) {
      threats.push({
        id: uuidv4(),
        category: 'anomalous_behavior',
        severity: 'high',
        confidence: behaviorCheck.anomalyScore,
        description: `Behavioral anomaly detected: ${behaviorCheck.reason}`,
        evidence: behaviorCheck.flags,
        mitigated: false,
      });
    }

    // Step 3: Detect threats
    const detectedThreats = this.detectThreats(request);
    threats.push(...detectedThreats);

    // Step 4: Calculate trust level
    const trustLevel = this.calculateTrustLevel(request, threats, behaviorCheck.anomalyScore);

    // Step 5: Evaluate policies
    const policyResult = this.evaluatePolicies(request, trustLevel, threats);
    appliedPolicies.push(...policyResult.appliedPolicies);

    // Step 6: Determine granted permissions
    const { granted, denied } = this.filterPermissions(
      request.requestedPermissions,
      request.sourceRole,
      policyResult.action,
      trustLevel,
    );

    // Step 7: Issue token if allowed
    let token: string | undefined;
    if (policyResult.action === 'allow' || policyResult.action === 'monitor') {
      try {
        token = agentTokenService.issueToken(
          request.sourceAgentId,
          request.targetAgentId,
          request.context,
          granted.map(p => p.toString()),
        );
        // Update behavioral baseline on successful access
        for (const cap of request.context.requestedCapabilities) {
          agentTokenService.updateBaseline(request.sourceAgentId, cap, request.targetAgentId);
        }
      } catch (err) {
        logger.warn({ err, requestId: request.requestId }, 'Token issuance failed');
      }
    }

    const allowed = policyResult.action === 'allow' || policyResult.action === 'monitor';
    const reason = this.buildReason(policyResult.action, trustLevel, threats, policyResult.reason);

    const decision = this.buildDecision(
      request,
      policyResult.action,
      trustLevel,
      granted,
      denied,
      appliedPolicies,
      threats,
      reason,
      token,
    );

    // Step 8: Update stats
    const durationMs = Date.now() - startMs;
    this.updateStats(decision, threats, durationMs);
    this.recordAudit(request, decision, durationMs);

    logger.info({
      requestId: request.requestId,
      source: request.sourceAgentId,
      target: request.targetAgentId,
      action: policyResult.action,
      trustLevel,
      threats: threats.length,
      durationMs,
    }, 'Zero-trust decision made');

    return decision;
  }

  // --------------------------------------------------------------------------
  // THREAT DETECTION
  // --------------------------------------------------------------------------

  private detectThreats(request: ZeroTrustRequest): ThreatAssessment[] {
    const threats: ThreatAssessment[] = [];

    // Check for privilege escalation
    const rolePerms = ROLE_PERMISSIONS[request.sourceRole] || [];
    const escalationAttempts = request.requestedPermissions.filter(
      p => !rolePerms.includes(p) && [
        AgentPermission.MODIFY_PERMISSIONS,
        AgentPermission.MANAGE_SECRETS,
        AgentPermission.MANAGE_USERS,
      ].includes(p),
    );
    if (escalationAttempts.length > 0) {
      threats.push({
        id: uuidv4(),
        category: 'privilege_escalation',
        severity: 'high',
        confidence: 0.9,
        description: `Attempted to acquire permissions beyond role scope: ${escalationAttempts.join(', ')}`,
        evidence: [`Role: ${request.sourceRole}`, `Requested: ${escalationAttempts.join(', ')}`],
        mitigated: true,
      });
    }

    // Check for lateral movement (agent accessing many different targets rapidly)
    const history = agentTokenService.getTokenHistory(request.sourceAgentId);
    const recentTargets = new Set(
      history
        .filter(t => Date.now() - t.iat < 60_000)
        .map(t => t.sub),
    );
    if (recentTargets.size > 5) {
      threats.push({
        id: uuidv4(),
        category: 'lateral_movement',
        severity: 'medium',
        confidence: 0.7,
        description: `Agent accessed ${recentTargets.size} different targets in the last 60 seconds`,
        evidence: [`Unique targets: ${recentTargets.size}`, `Threshold: 5`],
        mitigated: false,
      });
    }

    // Check for data exfiltration patterns
    const dataPerms = [AgentPermission.VIEW_LOGS, AgentPermission.VIEW_AUDIT_LOG, AgentPermission.VIEW_CONVERSATION];
    const dataRequests = request.requestedPermissions.filter(p => dataPerms.includes(p));
    if (dataRequests.length >= 3 && request.context.riskLevel === 'high') {
      threats.push({
        id: uuidv4(),
        category: 'data_exfiltration',
        severity: 'high',
        confidence: 0.75,
        description: 'Multiple data-access permissions requested at high risk level',
        evidence: [`Permissions: ${dataRequests.join(', ')}`, `Risk: ${request.context.riskLevel}`],
        mitigated: false,
      });
    }

    // Check for replay attacks (same JTI reuse attempt)
    const recentTokens = history.filter(t => Date.now() - t.iat < 2000);
    if (recentTokens.length > 10) {
      threats.push({
        id: uuidv4(),
        category: 'replay_attack',
        severity: 'medium',
        confidence: 0.65,
        description: `Unusually high token request rate: ${recentTokens.length} tokens in 2 seconds`,
        evidence: [`Token count: ${recentTokens.length}`, `Window: 2000ms`],
        mitigated: false,
      });
    }

    // Check for impersonation (agent claiming to be a different role)
    if (request.sourceRole === 'owner' && !request.sourceAgentId.startsWith('owner-')) {
      threats.push({
        id: uuidv4(),
        category: 'impersonation',
        severity: 'critical',
        confidence: 0.85,
        description: 'Agent claiming owner role but ID does not match owner pattern',
        evidence: [`AgentId: ${request.sourceAgentId}`, `ClaimedRole: ${request.sourceRole}`],
        mitigated: false,
      });
    }

    return threats;
  }

  // --------------------------------------------------------------------------
  // TRUST LEVEL CALCULATION
  // --------------------------------------------------------------------------

  private calculateTrustLevel(
    request: ZeroTrustRequest,
    threats: ThreatAssessment[],
    anomalyScore: number,
  ): TrustLevel {
    const criticalThreats = threats.filter(t => t.severity === 'critical' && !t.mitigated);
    const highThreats = threats.filter(t => t.severity === 'high' && !t.mitigated);

    if (criticalThreats.length > 0) return 'untrusted';
    if (highThreats.length > 0) return 'low';
    if (anomalyScore > 0.7) return 'low';
    if (anomalyScore > 0.4) return 'medium';

    const baseline = agentTokenService.getBaseline(request.sourceAgentId);
    if (!baseline) return 'low';

    if (request.context.riskLevel === 'low' && threats.length === 0 && anomalyScore < 0.2) {
      return 'verified';
    }

    if (request.context.riskLevel === 'medium' || threats.length > 0) {
      return 'medium';
    }

    return 'high';
  }

  // --------------------------------------------------------------------------
  // POLICY EVALUATION
  // --------------------------------------------------------------------------

  private evaluatePolicies(
    request: ZeroTrustRequest,
    trustLevel: TrustLevel,
    threats: ThreatAssessment[],
  ): { action: PolicyAction; appliedPolicies: string[]; reason: string } {
    const sortedPolicies = Array.from(this.policies.values())
      .filter(p => p.enabled)
      .sort((a, b) => a.priority - b.priority);

    const appliedPolicies: string[] = [];
    let finalAction: PolicyAction = 'allow'; // default allow
    let reason = 'Default allow';

    const hasBaseline = !!agentTokenService.getBaseline(request.sourceAgentId);

    // Build evaluation context
    const evalCtx: Record<string, unknown> = {
      'sourceRole': request.sourceRole,
      'context.riskLevel': request.context.riskLevel,
      'context.declaredPurpose': request.context.declaredPurpose,
      'requestedPermissions': request.requestedPermissions,
      'trustLevel': trustLevel,
      'hasBaseline': hasBaseline,
      'threatCount': threats.length,
    };

    for (const policy of sortedPolicies) {
      if (this.matchesConditions(policy.conditions, evalCtx)) {
        appliedPolicies.push(policy.name);
        finalAction = policy.action;
        reason = policy.description;

        // Deny is terminal — stop evaluating
        if (policy.action === 'deny') break;
      }
    }

    // Untrusted always denied regardless of policies
    if (trustLevel === 'untrusted') {
      finalAction = 'deny';
      reason = 'Trust level is untrusted — access denied';
      appliedPolicies.push('trust-level-override');
    }

    return { action: finalAction, appliedPolicies, reason };
  }

  private matchesConditions(conditions: PolicyCondition[], ctx: Record<string, unknown>): boolean {
    return conditions.every(cond => {
      const ctxValue = ctx[cond.field];
      switch (cond.operator) {
        case 'eq': return ctxValue === cond.value;
        case 'neq': return ctxValue !== cond.value;
        case 'in': return Array.isArray(cond.value) && (cond.value as unknown[]).includes(ctxValue);
        case 'not_in': return Array.isArray(cond.value) && !(cond.value as unknown[]).includes(ctxValue);
        case 'gt': return typeof ctxValue === 'number' && ctxValue > (cond.value as number);
        case 'lt': return typeof ctxValue === 'number' && ctxValue < (cond.value as number);
        case 'contains':
          if (Array.isArray(ctxValue)) return ctxValue.includes(cond.value);
          if (typeof ctxValue === 'string') return ctxValue.includes(cond.value as string);
          return false;
        case 'not_contains':
          if (Array.isArray(ctxValue)) return !ctxValue.includes(cond.value);
          if (typeof ctxValue === 'string') return !ctxValue.includes(cond.value as string);
          return true;
        default: return false;
      }
    });
  }

  // --------------------------------------------------------------------------
  // PERMISSION FILTERING
  // --------------------------------------------------------------------------

  private filterPermissions(
    requested: AgentPermission[],
    role: UserRole | 'agent',
    action: PolicyAction,
    trustLevel: TrustLevel,
  ): { granted: AgentPermission[]; denied: AgentPermission[] } {
    if (action === 'deny') {
      return { granted: [], denied: requested };
    }

    const rolePerms = ROLE_PERMISSIONS[role as UserRole] || [];
    const granted: AgentPermission[] = [];
    const denied: AgentPermission[] = [];

    for (const perm of requested) {
      // Trust level restrictions
      if (trustLevel === 'low' && [
        AgentPermission.MANAGE_SECRETS,
        AgentPermission.MANAGE_USERS,
        AgentPermission.MODIFY_PERMISSIONS,
        AgentPermission.ROLLBACK,
      ].includes(perm)) {
        denied.push(perm);
        continue;
      }

      if (rolePerms.includes(perm)) {
        granted.push(perm);
      } else {
        denied.push(perm);
      }
    }

    return { granted, denied };
  }

  // --------------------------------------------------------------------------
  // SANDBOX MANAGEMENT
  // --------------------------------------------------------------------------

  setSandboxPolicy(policy: SandboxPolicy): void {
    this.sandboxPolicies.set(policy.agentId, policy);
    logger.info({ agentId: policy.agentId }, 'Sandbox policy set');
  }

  getSandboxPolicy(agentId: string): SandboxPolicy | undefined {
    return this.sandboxPolicies.get(agentId);
  }

  checkSandboxOperation(agentId: string, operation: string): { allowed: boolean; reason: string } {
    const policy = this.sandboxPolicies.get(agentId);
    if (!policy || !policy.enabled) {
      return { allowed: true, reason: 'No sandbox policy — operation allowed' };
    }

    if (policy.deniedOperations.includes(operation)) {
      return { allowed: false, reason: `Operation '${operation}' explicitly denied by sandbox policy` };
    }

    if (policy.allowedOperations.length > 0 && !policy.allowedOperations.includes(operation)) {
      return { allowed: false, reason: `Operation '${operation}' not in allowed operations list` };
    }

    return { allowed: true, reason: 'Sandbox policy allows operation' };
  }

  // --------------------------------------------------------------------------
  // POLICY MANAGEMENT
  // --------------------------------------------------------------------------

  addPolicy(policy: Omit<ZeroTrustPolicy, 'id' | 'createdAt' | 'updatedAt'>): ZeroTrustPolicy {
    const full: ZeroTrustPolicy = {
      ...policy,
      id: uuidv4(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.policies.set(full.id, full);
    logger.info({ policyId: full.id, name: full.name }, 'Zero-trust policy added');
    return full;
  }

  updatePolicy(id: string, updates: Partial<ZeroTrustPolicy>): ZeroTrustPolicy | null {
    const existing = this.policies.get(id);
    if (!existing) return null;
    const updated = { ...existing, ...updates, id, updatedAt: new Date() };
    this.policies.set(id, updated);
    return updated;
  }

  deletePolicy(id: string): boolean {
    const deleted = this.policies.delete(id);
    if (deleted) logger.info({ policyId: id }, 'Zero-trust policy deleted');
    return deleted;
  }

  getPolicies(): ZeroTrustPolicy[] {
    return Array.from(this.policies.values()).sort((a, b) => a.priority - b.priority);
  }

  getPolicy(id: string): ZeroTrustPolicy | undefined {
    return this.policies.get(id);
  }

  // --------------------------------------------------------------------------
  // AUDIT LOG
  // --------------------------------------------------------------------------

  getAuditLog(options?: {
    sourceAgentId?: string;
    targetAgentId?: string;
    action?: PolicyAction;
    allowed?: boolean;
    limit?: number;
    since?: Date;
  }): AuditEntry[] {
    let entries = [...this.auditLog];

    if (options?.sourceAgentId) {
      entries = entries.filter(e => e.sourceAgentId === options.sourceAgentId);
    }
    if (options?.targetAgentId) {
      entries = entries.filter(e => e.targetAgentId === options.targetAgentId);
    }
    if (options?.action) {
      entries = entries.filter(e => e.action === options.action);
    }
    if (options?.allowed !== undefined) {
      entries = entries.filter(e => e.allowed === options.allowed);
    }
    if (options?.since) {
      entries = entries.filter(e => e.timestamp >= options.since!);
    }

    entries.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    if (options?.limit) {
      entries = entries.slice(0, options.limit);
    }

    return entries;
  }

  // --------------------------------------------------------------------------
  // STATS
  // --------------------------------------------------------------------------

  getStats(): ZeroTrustStats {
    return {
      ...this.stats,
      averageDecisionMs: this.decisionTimes.length > 0
        ? this.decisionTimes.reduce((a, b) => a + b, 0) / this.decisionTimes.length
        : 0,
      policyCount: this.policies.size,
      sandboxCount: this.sandboxPolicies.size,
    };
  }

  // --------------------------------------------------------------------------
  // PRIVATE HELPERS
  // --------------------------------------------------------------------------

  private loadDefaultPolicies(): void {
    for (const p of DEFAULT_POLICIES) {
      this.addPolicy(p);
    }
  }

  private buildDecision(
    request: ZeroTrustRequest,
    action: PolicyAction,
    trustLevel: TrustLevel,
    granted: AgentPermission[],
    denied: AgentPermission[],
    appliedPolicies: string[],
    threats: ThreatAssessment[],
    reason: string,
    token?: string,
  ): ZeroTrustDecision {
    const allowed = action === 'allow' || action === 'monitor';
    return {
      requestId: request.requestId,
      allowed,
      action,
      trustLevel,
      grantedPermissions: granted,
      deniedPermissions: denied,
      appliedPolicies,
      threats,
      token,
      reason,
      timestamp: new Date(),
      expiresAt: token ? new Date(Date.now() + 500) : undefined,
    };
  }

  private buildReason(
    action: PolicyAction,
    trustLevel: TrustLevel,
    threats: ThreatAssessment[],
    policyReason: string,
  ): string {
    const parts: string[] = [policyReason];
    if (threats.length > 0) {
      const unmitigated = threats.filter(t => !t.mitigated);
      if (unmitigated.length > 0) {
        parts.push(`${unmitigated.length} unmitigated threat(s): ${unmitigated.map(t => t.category).join(', ')}`);
      }
    }
    parts.push(`Trust level: ${trustLevel}`);
    parts.push(`Action: ${action}`);
    return parts.join(' | ');
  }

  private recordAudit(request: ZeroTrustRequest, decision: ZeroTrustDecision, durationMs: number): void {
    const entry: AuditEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      requestId: request.requestId,
      sourceAgentId: request.sourceAgentId,
      targetAgentId: request.targetAgentId,
      action: decision.action,
      allowed: decision.allowed,
      trustLevel: decision.trustLevel,
      threats: decision.threats.map(t => t.category),
      appliedPolicies: decision.appliedPolicies,
      durationMs,
    };
    this.auditLog.push(entry);

    // Keep last 10,000 entries
    if (this.auditLog.length > 10_000) {
      this.auditLog.splice(0, this.auditLog.length - 10_000);
    }
  }

  private updateStats(decision: ZeroTrustDecision, threats: ThreatAssessment[], durationMs: number): void {
    this.stats.totalRequests++;
    switch (decision.action) {
      case 'allow': this.stats.allowedRequests++; break;
      case 'deny': this.stats.deniedRequests++; break;
      case 'challenge': this.stats.challengedRequests++; break;
      case 'monitor': this.stats.monitoredRequests++; break;
    }
    this.stats.threatsDetected += threats.length;
    for (const t of threats) {
      this.stats.threatsByCategory[t.category] = (this.stats.threatsByCategory[t.category] || 0) + 1;
    }
    this.decisionTimes.push(durationMs);
    if (this.decisionTimes.length > 1000) this.decisionTimes.shift();
  }

  private initStats(): ZeroTrustStats {
    return {
      totalRequests: 0,
      allowedRequests: 0,
      deniedRequests: 0,
      challengedRequests: 0,
      monitoredRequests: 0,
      threatsDetected: 0,
      threatsByCategory: {
        privilege_escalation: 0,
        lateral_movement: 0,
        data_exfiltration: 0,
        replay_attack: 0,
        impersonation: 0,
        anomalous_behavior: 0,
        policy_violation: 0,
        sandbox_escape: 0,
      },
      averageDecisionMs: 0,
      policyCount: 0,
      sandboxCount: 0,
    };
  }
}

// Singleton export
export const zeroTrustEngine = new ZeroTrustEngine();
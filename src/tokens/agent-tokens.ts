/**
 * Guardian — Agent Token Service
 *
 * Short-lived JWT tokens for agent-to-agent authentication.
 * 500ms TTL by default (as per PDF architecture spec).
 * Implements context declarations and behavioral baseline verification.
 *
 * Migrated from: server/services/agentAuth.ts + guardianEnhanced.ts
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { createHmac, randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

// ============================================================================
// TYPES
// ============================================================================

export interface AgentTokenPayload {
  jti: string;         // JWT ID — unique per token
  iss: string;         // Issuer agent ID
  sub: string;         // Subject (target agent ID or 'any')
  iat: number;         // Issued at (ms)
  exp: number;         // Expiry (ms)
  ttl: number;         // TTL in ms
  context: AgentContext;
  permissions: string[];
}

export interface AgentContext {
  taskId?: string;
  orchestrationId?: string;
  intent?: string;
  requestedCapabilities: string[];
  declaredPurpose: string;
  riskLevel: 'low' | 'medium' | 'high';
}

export interface TokenVerificationResult {
  valid: boolean;
  payload?: AgentTokenPayload;
  reason?: string;
  expired?: boolean;
}

export interface BehavioralBaseline {
  agentId: string;
  typicalRequestRate: number;    // requests per minute
  typicalCapabilities: string[];
  typicalTargets: string[];
  anomalyThreshold: number;      // 0-1
  lastUpdated: Date;
}

export interface BehaviorCheck {
  agentId: string;
  timestamp: Date;
  requestedCapabilities: string[];
  targetAgent: string;
  anomalyScore: number;
  anomalies: string[];
  allowed: boolean;
}

// ============================================================================
// AGENT TOKEN SERVICE
// ============================================================================

export class AgentTokenService {
  private readonly secret: string;
  private readonly defaultTTL: number;
  private revokedTokens: Set<string> = new Set();
  private tokenHistory: Map<string, AgentTokenPayload[]> = new Map();
  private behavioralBaselines: Map<string, BehavioralBaseline> = new Map();
  private requestCounts: Map<string, { count: number; windowStart: number }> = new Map();

  constructor(secret?: string, defaultTTL = 500) {
    this.secret = secret || process.env.GUARDIAN_TOKEN_SECRET || randomBytes(32).toString('hex');
    this.defaultTTL = defaultTTL;
    logger.info(`[Guardian] 🔑 Agent Token Service initialized (default TTL: ${defaultTTL}ms)`);
  }

  // ── Token Generation ───────────────────────────────────────────────────────

  /**
   * Issue a short-lived agent token
   * Default TTL: 500ms (as per PDF architecture spec)
   */
  issueToken(
    issuerAgentId: string,
    targetAgentId: string,
    context: AgentContext,
    permissions: string[],
    ttlMs?: number
  ): string {
    const ttl = ttlMs ?? this.defaultTTL;
    const now = Date.now();

    const payload: AgentTokenPayload = {
      jti: uuidv4(),
      iss: issuerAgentId,
      sub: targetAgentId,
      iat: now,
      exp: now + ttl,
      ttl,
      context,
      permissions,
    };

    const token = this.sign(payload);

    // Track in history
    const history = this.tokenHistory.get(issuerAgentId) || [];
    history.push(payload);
    // Keep last 100 tokens per agent
    if (history.length > 100) history.shift();
    this.tokenHistory.set(issuerAgentId, history);

    logger.debug(`[Guardian] Token issued: ${issuerAgentId} -> ${targetAgentId} (TTL: ${ttl}ms)`);
    return token;
  }

  // ── Token Verification ─────────────────────────────────────────────────────

  /**
   * Verify an agent token
   */
  verifyToken(token: string, expectedTarget?: string): TokenVerificationResult {
    try {
      const payload = this.decode(token);
      if (!payload) {
        return { valid: false, reason: 'Invalid token format' };
      }

      // Check revocation
      if (this.revokedTokens.has(payload.jti)) {
        return { valid: false, reason: 'Token has been revoked', payload };
      }

      // Check expiry
      if (Date.now() > payload.exp) {
        return { valid: false, reason: 'Token expired', expired: true, payload };
      }

      // Check target
      if (expectedTarget && payload.sub !== expectedTarget && payload.sub !== 'any') {
        return { valid: false, reason: `Token not valid for target: ${expectedTarget}`, payload };
      }

      // Verify signature
      const expectedToken = this.sign(payload);
      if (token !== expectedToken) {
        return { valid: false, reason: 'Invalid signature' };
      }

      return { valid: true, payload };
    } catch (err) {
      return { valid: false, reason: `Verification error: ${String(err)}` };
    }
  }

  /**
   * Revoke a token by JTI
   */
  revokeToken(jti: string): void {
    this.revokedTokens.add(jti);
    logger.info(`[Guardian] Token revoked: ${jti}`);
  }

  // ── Behavioral Baseline ────────────────────────────────────────────────────

  /**
   * Set behavioral baseline for an agent
   */
  setBaseline(baseline: BehavioralBaseline): void {
    this.behavioralBaselines.set(baseline.agentId, baseline);
    logger.info(`[Guardian] Baseline set for agent: ${baseline.agentId}`);
  }

  /**
   * Check if a request matches the agent's behavioral baseline
   */
  checkBehavior(
    agentId: string,
    requestedCapabilities: string[],
    targetAgent: string
  ): BehaviorCheck {
    const baseline = this.behavioralBaselines.get(agentId);
    const anomalies: string[] = [];
    let anomalyScore = 0;

    if (baseline) {
      // Check for unusual capabilities
      const unusualCaps = requestedCapabilities.filter(
        c => !baseline.typicalCapabilities.includes(c)
      );
      if (unusualCaps.length > 0) {
        anomalies.push(`Unusual capabilities requested: ${unusualCaps.join(', ')}`);
        anomalyScore += 0.3 * unusualCaps.length;
      }

      // Check for unusual target
      if (!baseline.typicalTargets.includes(targetAgent)) {
        anomalies.push(`Unusual target agent: ${targetAgent}`);
        anomalyScore += 0.2;
      }

      // Check request rate
      const rateCheck = this.checkRequestRate(agentId, baseline.typicalRequestRate);
      if (rateCheck.exceeded) {
        anomalies.push(`Request rate exceeded: ${rateCheck.current}/min (baseline: ${baseline.typicalRequestRate}/min)`);
        anomalyScore += 0.5;
      }
    }

    anomalyScore = Math.min(1, anomalyScore);
    const allowed = !baseline || anomalyScore < (baseline?.anomalyThreshold ?? 0.7);

    if (!allowed) {
      logger.warn(`[Guardian] Behavioral anomaly detected for ${agentId}: score=${anomalyScore}`);
    }

    return {
      agentId,
      timestamp: new Date(),
      requestedCapabilities,
      targetAgent,
      anomalyScore,
      anomalies,
      allowed,
    };
  }

  /**
   * Update baseline from observed behavior (learning)
   */
  updateBaseline(agentId: string, capability: string, targetAgent: string): void {
    const baseline = this.behavioralBaselines.get(agentId);
    if (!baseline) {
      // Create new baseline from first observation
      this.setBaseline({
        agentId,
        typicalRequestRate: 10,
        typicalCapabilities: [capability],
        typicalTargets: [targetAgent],
        anomalyThreshold: 0.7,
        lastUpdated: new Date(),
      });
      return;
    }

    // Update existing baseline
    if (!baseline.typicalCapabilities.includes(capability)) {
      baseline.typicalCapabilities.push(capability);
    }
    if (!baseline.typicalTargets.includes(targetAgent)) {
      baseline.typicalTargets.push(targetAgent);
    }
    baseline.lastUpdated = new Date();
  }

  // ── Context Declaration ────────────────────────────────────────────────────

  /**
   * Validate a context declaration before issuing token
   */
  validateContextDeclaration(context: AgentContext): {
    valid: boolean;
    issues: string[];
  } {
    const issues: string[] = [];

    if (!context.declaredPurpose || context.declaredPurpose.length < 10) {
      issues.push('declaredPurpose must be at least 10 characters');
    }

    if (!context.requestedCapabilities || context.requestedCapabilities.length === 0) {
      issues.push('requestedCapabilities must not be empty');
    }

    if (context.requestedCapabilities.length > 10) {
      issues.push('requestedCapabilities must not exceed 10 items (principle of least privilege)');
    }

    return { valid: issues.length === 0, issues };
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private sign(payload: AgentTokenPayload): string {
    const data = JSON.stringify(payload);
    // 2060 Standard: Upgraded from SHA-256 → SHA-512 for quantum resistance
    // Migration path: sha512 (now) → ml_kem (2030) → slh_dsa (2060)
    const algorithm = process.env.GUARDIAN_TOKEN_ALGORITHM || 'sha512';
    const signature = createHmac(algorithm, this.secret).update(data).digest('hex');
    return `${Buffer.from(data).toString('base64url')}.${algorithm}.${signature}`;
  }

  private decode(token: string): AgentTokenPayload | null {
    try {
      const parts = token.split('.');
      // Support both legacy (2-part) and new (3-part with algorithm) format
      const dataB64 = parts[0];
      const data = Buffer.from(dataB64, 'base64url').toString('utf8');
      return JSON.parse(data) as AgentTokenPayload;
    } catch {
      return null;
    }
  }

  private verify(token: string): boolean {
    try {
      const parts = token.split('.');
      if (parts.length < 2) return false;
      const [dataB64, algOrSig, maybeSig] = parts;
      const data = Buffer.from(dataB64, 'base64url').toString('utf8');

      if (parts.length === 3) {
        // New format: data.algorithm.signature
        const algorithm = algOrSig;
        const signature = maybeSig;
        const expected = createHmac(algorithm, this.secret).update(data).digest('hex');
        return expected === signature;
      } else {
        // Legacy format: data.signature (sha256)
        const expected = createHmac('sha256', this.secret).update(data).digest('hex');
        return expected === algOrSig;
      }
    } catch {
      return false;
    }
  }

  private checkRequestRate(agentId: string, baselineRate: number): {
    exceeded: boolean;
    current: number;
  } {
    const now = Date.now();
    const windowMs = 60_000; // 1 minute window
    const entry = this.requestCounts.get(agentId);

    if (!entry || now - entry.windowStart > windowMs) {
      this.requestCounts.set(agentId, { count: 1, windowStart: now });
      return { exceeded: false, current: 1 };
    }

    entry.count++;
    const exceeded = entry.count > baselineRate * 2; // Allow 2x baseline before flagging
    return { exceeded, current: entry.count };
  }

  getTokenHistory(agentId: string): AgentTokenPayload[] {
    return this.tokenHistory.get(agentId) || [];
  }

  getBaseline(agentId: string): BehavioralBaseline | undefined {
    return this.behavioralBaselines.get(agentId);
  }

  getAllBaselines(): BehavioralBaseline[] {
    return Array.from(this.behavioralBaselines.values());
  }

  getRevokedCount(): number {
    return this.revokedTokens.size;
  }
}

export const agentTokenService = new AgentTokenService();
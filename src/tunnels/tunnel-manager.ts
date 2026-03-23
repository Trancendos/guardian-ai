/**
 * Sentinel Station — Tunnel Manager
 * 
 * Core tunnel lifecycle management integrated with Guardian's zero-trust engine.
 * 
 * @module tunnels/tunnel-manager
 */

import { v4 as uuidv4 } from 'uuid';
import { 
  WarpTunnel, 
  TunnelState, 
  TunnelRequest, 
  TunnelDecision,
  TunnelCondition,
  TunnelEvent,
  TunnelMetrics,
  ThreatLevel,
  SlipstreamClass
} from './tunnel-types';
import { pqcCrypto, PQCCryptoService } from './pqc-crypto';
import { slipstreamClassifier, SlipstreamClassifier } from './slipstream-classifier';
import { logger } from '../utils/logger';
import { ZeroTrustPolicy, ZeroTrustDecision, TrustLevel } from '../zero-trust/zero-trust';

// ============================================================================
// TUNNEL MANAGER
// ============================================================================

export class TunnelManager {
  private tunnels: Map<string, WarpTunnel> = new Map();
  private activeSessions: Map<string, string> = new Map(); // sessionId -> tunnelId
  
  private readonly defaultTtlSeconds = 3600; // 1 hour default
  private readonly maxTtlSeconds = 86400;    // 24 hour max
  private readonly minTtlSeconds = 60;       // 1 minute min
  
  constructor(
    private readonly pqc: PQCCryptoService = pqcCrypto,
    private readonly classifier: SlipstreamClassifier = slipstreamClassifier
  ) {}
  
  // ============================================================================
  // TUNNEL LIFECYCLE
  // ============================================================================
  
  /**
   * Request a new tunnel between locations
   */
  async requestTunnel(request: TunnelRequest): Promise<TunnelDecision> {
    logger.info('Tunnel request received', { 
      requestId: request.requestId,
      source: request.sourceLocation,
      target: request.targetLocation 
    });
    
    // 1. Classify the slipstream
    const slipstreamClass = this.classifier.classify(request);
    
    // 2. Calculate threat level
    const threatLevel = this.classifier.calculateThreatLevel(slipstreamClass, request.context);
    
    // 3. Determine duration
    const durationSeconds = this.clampDuration(request.requestedDuration, slipstreamClass);
    
    // 4. Generate PQC key pair
    const pqcAlgorithm = this.pqc.getRecommendedAlgorithm(threatLevel);
    const keyPair = await this.pqc.generateKeyPair(pqcAlgorithm);
    
    // 5. Create tunnel record
    const tunnelId = `tunnel-${uuidv4()}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + durationSeconds * 1000);
    
    const tunnel: WarpTunnel = {
      id: tunnelId,
      name: `${request.sourceLocation}-${request.targetLocation}-${slipstreamClass}`,
      sourceLocation: request.sourceLocation,
      targetLocation: request.targetLocation,
      state: 'dormant',
      slipstreamClass,
      pqcPublicKey: keyPair.publicKey,
      pqcAlgorithm: keyPair.algorithm,
      sessionToken: '',
      threatLevel,
      createdAt: now,
      activatedAt: null,
      expiresAt,
      lastActivityAt: now,
      bytesTransferred: 0,
      messagesExchanged: 0,
      avgLatencyMs: 0,
      createdBy: request.requestedBy,
      approvedBy: [],
      auditLog: [{
        timestamp: now,
        action: 'tunnel_requested',
        actor: request.requestedBy,
        details: { requestId: request.requestId, slipstreamClass, threatLevel }
      }]
    };
    
    // 6. Apply conditions
    const conditions = this.generateConditions(slipstreamClass, request);
    
    // 7. Store tunnel
    this.tunnels.set(tunnelId, tunnel);
    
    logger.info('Tunnel created', { 
      tunnelId, 
      state: 'dormant',
      slipstreamClass,
      threatLevel 
    });
    
    return {
      requestId: request.requestId,
      approved: true,
      tunnel,
      conditions,
      expiresAt
    };
  }
  
  /**
   * Activate a dormant tunnel (PQC handshake complete)
   */
  async activateTunnel(tunnelId: string, sessionToken: string): Promise<WarpTunnel> {
    const tunnel = this.tunnels.get(tunnelId);
    
    if (!tunnel) {
      throw new Error(`Tunnel not found: ${tunnelId}`);
    }
    
    if (tunnel.state !== 'dormant') {
      throw new Error(`Tunnel not in dormant state: ${tunnel.state}`);
    }
    
    tunnel.state = 'active';
    tunnel.activatedAt = new Date();
    tunnel.sessionToken = sessionToken;
    tunnel.lastActivityAt = new Date();
    
    tunnel.auditLog.push({
      timestamp: new Date(),
      action: 'tunnel_activated',
      actor: 'system',
      details: { sessionTokenHash: this.hashToken(sessionToken) }
    });
    
    logger.info('Tunnel activated', { tunnelId, slipstreamClass: tunnel.slipstreamClass });
    
    return tunnel;
  }
  
  /**
   * Get tunnel by ID
   */
  getTunnel(tunnelId: string): WarpTunnel | undefined {
    return this.tunnels.get(tunnelId);
  }
  
  /**
   * List all tunnels, optionally filtered by state
   */
  listTunnels(state?: TunnelState): WarpTunnel[] {
    const all = Array.from(this.tunnels.values());
    
    if (state) {
      return all.filter(t => t.state === state);
    }
    
    return all;
  }
  
  /**
   * Get active tunnels for a location
   */
  getTunnelsForLocation(location: string): WarpTunnel[] {
    return Array.from(this.tunnels.values()).filter(
      t => (t.sourceLocation === location || t.targetLocation === location) && t.state === 'active'
    );
  }
  
  /**
   * Drain a tunnel (graceful shutdown)
   */
  async drainTunnel(tunnelId: string, reason: string): Promise<WarpTunnel> {
    const tunnel = this.tunnels.get(tunnelId);
    
    if (!tunnel) {
      throw new Error(`Tunnel not found: ${tunnelId}`);
    }
    
    tunnel.state = 'draining';
    tunnel.auditLog.push({
      timestamp: new Date(),
      action: 'tunnel_draining',
      actor: 'system',
      details: { reason }
    });
    
    logger.info('Tunnel draining', { tunnelId, reason });
    
    return tunnel;
  }
  
  /**
   * Terminate a tunnel
   */
  async terminateTunnel(tunnelId: string, reason: string): Promise<WarpTunnel> {
    const tunnel = this.tunnels.get(tunnelId);
    
    if (!tunnel) {
      throw new Error(`Tunnel not found: ${tunnelId}`);
    }
    
    tunnel.state = 'terminated';
    tunnel.auditLog.push({
      timestamp: new Date(),
      action: 'tunnel_terminated',
      actor: 'system',
      details: { reason, bytesTransferred: tunnel.bytesTransferred }
    });
    
    logger.info('Tunnel terminated', { 
      tunnelId, 
      reason, 
      totalBytes: tunnel.bytesTransferred,
      totalMessages: tunnel.messagesExchanged
    });
    
    return tunnel;
  }
  
  /**
   * Update tunnel metrics
   */
  updateMetrics(tunnelId: string, bytesDelta: number, latencyMs: number): void {
    const tunnel = this.tunnels.get(tunnelId);
    
    if (!tunnel) {
      return;
    }
    
    tunnel.bytesTransferred += bytesDelta;
    tunnel.messagesExchanged += 1;
    tunnel.lastActivityAt = new Date();
    
    // Rolling average latency
    tunnel.avgLatencyMs = (tunnel.avgLatencyMs + latencyMs) / 2;
  }
  
  /**
   * Elevate threat level
   */
  async elevateThreat(tunnelId: string, newLevel: ThreatLevel, reason: string): Promise<WarpTunnel> {
    const tunnel = this.tunnels.get(tunnelId);
    
    if (!tunnel) {
      throw new Error(`Tunnel not found: ${tunnelId}`);
    }
    
    const previousLevel = tunnel.threatLevel;
    tunnel.threatLevel = newLevel;
    
    tunnel.auditLog.push({
      timestamp: new Date(),
      action: 'threat_elevated',
      actor: 'system',
      details: { previousLevel, newLevel, reason }
    });
    
    logger.warn('Tunnel threat elevated', { 
      tunnelId, 
      previousLevel, 
      newLevel, 
      reason 
    });
    
    // Auto-terminate on black threat
    if (newLevel === 'black') {
      await this.terminateTunnel(tunnelId, `Black threat level: ${reason}`);
    }
    
    return tunnel;
  }
  
  /**
   * Generate CloudEvent for tunnel state change
   */
  generateEvent(tunnel: WarpTunnel, eventType: TunnelEvent['type']): TunnelEvent {
    return {
      specversion: '1.0',
      type: eventType,
      source: 'sentinel-station',
      id: `event-${uuidv4()}`,
      time: new Date().toISOString(),
      data: {
        tunnelId: tunnel.id,
        tunnel,
        details: {}
      }
    };
  }
  
  // ============================================================================
  // PRIVATE METHODS
  // ============================================================================
  
  private clampDuration(requested: number, slipstreamClass: SlipstreamClass): number {
    const config = this.classifier.getConfig(slipstreamClass);
    const maxForClass = config.maxDuration;
    
    return Math.min(
      Math.max(requested, this.minTtlSeconds),
      Math.min(maxForClass, this.maxTtlSeconds)
    );
  }
  
  private generateConditions(slipstreamClass: SlipstreamClass, request: TunnelRequest): TunnelCondition[] {
    const config = this.classifier.getConfig(slipstreamClass);
    
    const conditions: TunnelCondition[] = [
      { type: 'max_duration', value: config.maxDuration },
      { type: 'monitoring_level', value: config.securityLevel >= 4 ? 'enhanced' : 'standard' }
    ];
    
    // Add data classification constraints
    if (request.context.dataClassification === 'restricted') {
      conditions.push({ type: 'allowed_operations', value: ['read-only'] });
    }
    
    return conditions;
  }
  
  private hashToken(token: string): string {
    // Simple hash for logging (not cryptographic)
    return token.substring(0, 8) + '...';
  }
}

// Singleton instance
export const tunnelManager = new TunnelManager();
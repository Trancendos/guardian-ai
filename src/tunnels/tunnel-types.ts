/**
 * Sentinel Station — Tunnel Type Definitions
 * 
 * Core types for Trans-Warp Slipstream tunnels with PQC security.
 * 
 * @module tunnels/tunnel-types
 */

// ============================================================================
// TUNNEL STATE & CLASSIFICATION
// ============================================================================

export type TunnelState = 
  | 'dormant'      // Created but not activated
  | 'handshaking'  // PQC key exchange in progress
  | 'active'       // Operational and passing traffic
  | 'draining'     // Graceful shutdown, no new sessions
  | 'terminated';  // Closed and archived

export type ThreatLevel = 'green' | 'amber' | 'red' | 'black';

export type SlipstreamClass = 
  | 'alpha'   // Ultra-low latency (<10ms), intra-region
  | 'beta'    // Standard latency (10-50ms), cross-region
  | 'gamma'   // High-throughput, batch operations
  | 'delta';  // Emergency/evacuation, maximum security

export type PQCAlgorithm = 
  | 'CRYSTALS-Kyber-1024'    // Key encapsulation
  | 'CRYSTALS-Dilithium-5'   // Digital signatures
  | 'SPHINCS+-SHA2-256f';    // Backup signatures

// ============================================================================
// TUNNEL INTERFACE
// ============================================================================

export interface WarpTunnel {
  id: string;                          // Unique tunnel identifier
  name: string;                        // Human-readable name
  
  // Location endpoints
  sourceLocation: string;              // Origin location (e.g., 'the-citadel')
  targetLocation: string;              // Destination location (e.g., 'the-void')
  
  // State management
  state: TunnelState;
  slipstreamClass: SlipstreamClass;
  
  // Security
  pqcPublicKey: string;               // Post-quantum public key
  pqcAlgorithm: PQCAlgorithm;
  sessionToken: string;               // Short-lived session token
  threatLevel: ThreatLevel;
  
  // Timing
  createdAt: Date;
  activatedAt: Date | null;
  expiresAt: Date;                    // Hard deadline
  lastActivityAt: Date;
  
  // Metrics
  bytesTransferred: number;
  messagesExchanged: number;
  avgLatencyMs: number;
  
  // Governance
  createdBy: string;                  // Agent or user ID
  approvedBy: string[];               // TIGA gate approvals
  auditLog: TunnelAuditEntry[];
}

export interface TunnelAuditEntry {
  timestamp: Date;
  action: string;
  actor: string;
  details: Record<string, unknown>;
}

// ============================================================================
// TUNNEL REQUEST & DECISION
// ============================================================================

export interface TunnelRequest {
  requestId: string;
  sourceLocation: string;
  targetLocation: string;
  requestedClass: SlipstreamClass;
  requestedDuration: number;          // seconds
  purpose: string;
  requestedBy: string;
  context: TunnelContext;
}

export interface TunnelContext {
  securityClearance: 'public' | 'internal' | 'confidential' | 'top-secret';
  dataClassification: 'public' | 'internal' | 'confidential' | 'restricted';
  urgency: 'low' | 'medium' | 'high' | 'critical';
  complianceRequirements: string[];   // e.g., ['GDPR', 'HIPAA', 'SOC2']
}

export interface TunnelDecision {
  requestId: string;
  approved: boolean;
  tunnel?: WarpTunnel;
  denialReason?: string;
  conditions: TunnelCondition[];
  expiresAt: Date;
}

export interface TunnelCondition {
  type: 'max_bytes' | 'max_duration' | 'allowed_operations' | 'monitoring_level';
  value: unknown;
}

// ============================================================================
// PQC KEY MATERIAL
// ============================================================================

export interface PQCKeyPair {
  publicKey: string;
  privateKey: string;
  algorithm: PQCAlgorithm;
  createdAt: Date;
  expiresAt: Date;
}

export interface PQCSessionKeys {
  encapsulatedKey: string;
  sharedSecret: string;
  derivedKey: string;
  algorithm: PQCAlgorithm;
}

// ============================================================================
// TUNNEL METRICS
// ============================================================================

export interface TunnelMetrics {
  tunnelId: string;
  collectedAt: Date;
  
  // Traffic
  bytesIn: number;
  bytesOut: number;
  packetsIn: number;
  packetsOut: number;
  
  // Performance
  latencyMs: number;
  jitterMs: number;
  packetLoss: number;
  
  // Security
  threatsBlocked: number;
  anomaliesDetected: number;
  lastThreatType: string | null;
}

// ============================================================================
// TUNNEL EVENT (for CloudEvents integration)
// ============================================================================

export interface TunnelEvent {
  specversion: '1.0';
  type: 'tunnel.created' | 'tunnel.activated' | 'tunnel.deactivated' | 'tunnel.terminated' | 'tunnel.threat.detected';
  source: string;
  id: string;
  time: string;
  data: {
    tunnelId: string;
    tunnel: WarpTunnel;
    details?: Record<string, unknown>;
  };
}
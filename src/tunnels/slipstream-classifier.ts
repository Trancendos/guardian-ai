/**
 * Sentinel Station — Slipstream Classifier
 * 
 * Classifies tunnel requests into appropriate slipstream classes
 * based on latency requirements, data volume, and security level.
 * 
 * @module tunnels/slipstream-classifier
 */

import { 
  SlipstreamClass, 
  TunnelRequest, 
  TunnelContext,
  ThreatLevel 
} from './tunnel-types';
import { logger } from '../utils/logger';

// ============================================================================
// SLIPSTREAM CLASS DEFINITIONS
// ============================================================================

interface SlipstreamClassConfig {
  name: SlipstreamClass;
  maxLatencyMs: number;
  minThroughputMbps: number;
  maxDuration: number;      // seconds
  securityLevel: number;    // 1-5
  useCases: string[];
}

const SLIPSTREAM_CONFIGS: Record<SlipstreamClass, SlipstreamClassConfig> = {
  alpha: {
    name: 'alpha',
    maxLatencyMs: 10,
    minThroughputMbps: 100,
    maxDuration: 300,       // 5 minutes max
    securityLevel: 3,
    useCases: ['real-time-sync', 'agent-mesh', 'live-collaboration']
  },
  beta: {
    name: 'beta',
    maxLatencyMs: 50,
    minThroughputMbps: 50,
    maxDuration: 3600,      // 1 hour max
    securityLevel: 4,
    useCases: ['cross-region-data', 'api-calls', 'scheduled-jobs']
  },
  gamma: {
    name: 'gamma',
    maxLatencyMs: 500,
    minThroughputMbps: 500,
    maxDuration: 86400,     // 24 hours max
    securityLevel: 3,
    useCases: ['backups', 'bulk-transfers', 'model-training']
  },
  delta: {
    name: 'delta',
    maxLatencyMs: 100,
    minThroughputMbps: 10,
    maxDuration: 600,       // 10 minutes max
    securityLevel: 5,       // Maximum security
    useCases: ['emergency-evacuation', 'security-incident', 'disaster-recovery']
  }
};

// ============================================================================
// CLASSIFIER SERVICE
// ============================================================================

export class SlipstreamClassifier {
  
  /**
   * Classify a tunnel request into the appropriate slipstream class
   */
  classify(request: TunnelRequest): SlipstreamClass {
    const { context, requestedClass, purpose } = request;
    
    // If explicitly requested and valid, honor it
    if (requestedClass && this.validateClassRequest(requestedClass, context)) {
      logger.info('Honoring explicit slipstream class request', { 
        requestedClass, 
        requestId: request.requestId 
      });
      return requestedClass;
    }
    
    // Auto-classify based on context
    const autoClass = this.autoClassify(context, purpose);
    
    logger.info('Auto-classified tunnel request', {
      requestId: request.requestId,
      classifiedAs: autoClass,
      context
    });
    
    return autoClass;
  }
  
  /**
   * Get configuration for a slipstream class
   */
  getConfig(slipstreamClass: SlipstreamClass): SlipstreamClassConfig {
    return SLIPSTREAM_CONFIGS[slipstreamClass];
  }
  
  /**
   * Calculate threat level adjustment for slipstream
   */
  calculateThreatLevel(
    slipstreamClass: SlipstreamClass, 
    context: TunnelContext
  ): ThreatLevel {
    const config = SLIPSTREAM_CONFIGS[slipstreamClass];
    
    // Base threat level on security clearance and data classification
    if (context.dataClassification === 'restricted') {
      return 'black';
    }
    
    if (context.urgency === 'critical' && context.securityClearance === 'top-secret') {
      return 'black';
    }
    
    if (context.urgency === 'high' || context.securityClearance === 'confidential') {
      return 'red';
    }
    
    if (context.dataClassification === 'confidential' || context.complianceRequirements.length > 0) {
      return 'amber';
    }
    
    return 'green';
  }
  
  /**
   * Estimate latency for a given source-target pair and class
   */
  estimateLatency(
    sourceLocation: string, 
    targetLocation: string, 
    slipstreamClass: SlipstreamClass
  ): number {
    const config = SLIPSTREAM_CONFIGS[slipstreamClass];
    
    // In production: actual network latency measurement
    // For now: estimate based on location type
    const isLocalMesh = this.areLocationsInSameMesh(sourceLocation, targetLocation);
    
    if (isLocalMesh) {
      return Math.min(config.maxLatencyMs, 5); // Very fast for local
    }
    
    // Cross-region estimate
    return Math.min(config.maxLatencyMs, config.maxLatencyMs * 0.8);
  }
  
  // ============================================================================
  // PRIVATE METHODS
  // ============================================================================
  
  private validateClassRequest(
    requestedClass: SlipstreamClass, 
    context: TunnelContext
  ): boolean {
    const config = SLIPSTREAM_CONFIGS[requestedClass];
    
    // Delta class requires top-secret clearance
    if (requestedClass === 'delta' && context.securityClearance !== 'top-secret') {
      logger.warn('Delta class requested without top-secret clearance', { context });
      return false;
    }
    
    // High security level classes require adequate clearance
    if (config.securityLevel >= 4 && context.securityClearance === 'public') {
      logger.warn('High-security class requested with public clearance', { 
        requestedClass, 
        clearance: context.securityClearance 
      });
      return false;
    }
    
    return true;
  }
  
  private autoClassify(context: TunnelContext, purpose: string): SlipstreamClass {
    // Emergency/critical = delta
    if (context.urgency === 'critical') {
      return 'delta';
    }
    
    // High urgency = alpha or beta based on data class
    if (context.urgency === 'high') {
      return context.dataClassification === 'public' ? 'alpha' : 'beta';
    }
    
    // Batch/bulk operations = gamma
    if (purpose.toLowerCase().includes('backup') || 
        purpose.toLowerCase().includes('bulk') ||
        purpose.toLowerCase().includes('batch')) {
      return 'gamma';
    }
    
    // Compliance requirements suggest beta for auditability
    if (context.complianceRequirements.length > 0) {
      return 'beta';
    }
    
    // Default to beta for standard operations
    return 'beta';
  }
  
  private areLocationsInSameMesh(source: string, target: string): boolean {
    // In production: actual mesh topology check
    // For now: check if both are 'the-*' locations
    const localLocations = [
      'the-citadel', 'the-void', 'the-hive', 'the-lighthouse',
      'the-forge', 'the-library', 'the-agora', 'the-sanctuary',
      'the-treasury', 'the-nexus', 'the-observatory', 'the-foundation',
      'the-cryptex', 'the-workshop', 'the-dr-ai'
    ];
    
    return localLocations.includes(source) && localLocations.includes(target);
  }
}

// Singleton instance
export const slipstreamClassifier = new SlipstreamClassifier();
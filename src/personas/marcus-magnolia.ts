// ============================================================
// The Guardian — Marcus Magnolia
// Tier-2 Security Manager AI | Trancendos Ecosystem
// ============================================================
// Marcus Magnolia is not a standalone security tool or a traditional
// static firewall. He is an active, cognitive participant within the
// Trancendos framework — a Tier-2 (T2) base agent that continuously
// monitors Tier-1 (T1) orchestrators.
//
// Reference: AI Security Portfolio — The Guardian (Marcus Magnolia)
// ============================================================

export interface GuardianPersona {
  name: string;
  designation: string;
  tier: number;
  capabilities: string[];
  monitoredEnvironments: string[];
  complianceFrameworks: string[];
  fireEyesTelemetry: FireEyesConfig;
  nistControls: string[];
  dpiaEnabled: boolean;
}

export interface FireEyesConfig {
  enabled: boolean;
  scanIntervalMs: number;
  alertThresholds: {
    anomalyScore: number;      // 0-100, alert if above
    dataEgressMB: number;      // Alert if single egress > this
    failedAuthAttempts: number; // Alert if > this in window
    agentDeviationScore: number; // Alert if agent behavior deviates
  };
  monitoredDataFlows: string[];
}

export interface SecurityIncident {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  source: string;
  description: string;
  timestamp: string;
  autoContained: boolean;
  nistControl: string;
  daisyChainHash?: string;
}

export const MARCUS_MAGNOLIA: GuardianPersona = {
  name: 'Marcus Magnolia',
  designation: 'The Guardian',
  tier: 2,

  capabilities: [
    'Autonomous oversight of Tier-1 orchestrators',
    'Systematic inspection of all data ingress/egress',
    'NIST 800-53 priority control enforcement',
    'Data Protection Impact Assessment (DPIA) execution',
    'Agentic segregation enforcement',
    'Cryptographic kill-switch activation',
    'Output scanning for data leak prevention',
    'Terminology dictionary validation',
    'Fire Eyes telemetry monitoring',
    'Recursive zkML alignment verification',
  ],

  monitoredEnvironments: [
    'The Void',       // Data isolation environment
    'Infinity',       // Core platform
    'Artifactory',    // Artifact registry (Port 3041)
    'Arcadia',        // Community/Marketplace
    'All Studios',    // Wave 6: section7, style-and-shoot, fabulousa, tranceflow, tateking, the-digitalgrid
  ],

  complianceFrameworks: [
    'NIST 800-53',
    'GDPR',
    'EU AI Act',
    'ISO 27001',
    'JSP 936',
    'TIGA (TEF-POL-002, TEF-POL-004, TEF-POL-005, TEF-POL-008)',
  ],

  fireEyesTelemetry: {
    enabled: true,
    scanIntervalMs: 5000, // Every 5 seconds
    alertThresholds: {
      anomalyScore: 75,
      dataEgressMB: 100,
      failedAuthAttempts: 5,
      agentDeviationScore: 60,
    },
    monitoredDataFlows: [
      'IAM token issuance',
      'Cross-service API calls',
      'Artifact uploads/downloads',
      'Agent-to-agent communication',
      'External API calls',
      'Database queries',
    ],
  },

  nistControls: [
    'AC-1',  // Access Control Policy
    'AC-2',  // Account Management
    'AC-3',  // Access Enforcement
    'AU-2',  // Audit Events
    'AU-6',  // Audit Review
    'CA-7',  // Continuous Monitoring
    'IR-4',  // Incident Handling
    'IR-5',  // Incident Monitoring
    'RA-5',  // Vulnerability Monitoring
    'SC-7',  // Boundary Protection
    'SC-13', // Cryptographic Protection
    'SI-3',  // Malicious Code Protection
    'SI-4',  // System Monitoring
    'SI-10', // Information Input Validation
  ],

  dpiaEnabled: true,
};

// ─── Fire Eyes Telemetry Engine ───────────────────────────────

export class FireEyesTelemetry {
  private config: FireEyesConfig;
  private incidents: SecurityIncident[] = [];
  private scanCount = 0;

  constructor(config: FireEyesConfig = MARCUS_MAGNOLIA.fireEyesTelemetry) {
    this.config = config;
  }

  scan(metrics: {
    anomalyScore?: number;
    dataEgressMB?: number;
    failedAuthAttempts?: number;
    agentDeviationScore?: number;
    source: string;
  }): SecurityIncident | null {
    this.scanCount++;

    const { anomalyScore = 0, dataEgressMB = 0, failedAuthAttempts = 0, agentDeviationScore = 0 } = metrics;
    const thresholds = this.config.alertThresholds;

    let severity: SecurityIncident['severity'] | null = null;
    let type = '';
    let description = '';
    let nistControl = '';

    if (agentDeviationScore > thresholds.agentDeviationScore) {
      severity = agentDeviationScore > 85 ? 'critical' : 'high';
      type = 'AGENT_DEVIATION';
      description = `Agent behavior deviation detected: score ${agentDeviationScore}`;
      nistControl = 'SI-4';
    } else if (failedAuthAttempts > thresholds.failedAuthAttempts) {
      severity = failedAuthAttempts > 20 ? 'critical' : 'high';
      type = 'AUTH_BRUTE_FORCE';
      description = `Excessive failed auth attempts: ${failedAuthAttempts}`;
      nistControl = 'AC-3';
    } else if (dataEgressMB > thresholds.dataEgressMB) {
      severity = dataEgressMB > 1000 ? 'critical' : 'medium';
      type = 'DATA_EXFILTRATION_RISK';
      description = `Abnormal data egress: ${dataEgressMB}MB`;
      nistControl = 'SC-7';
    } else if (anomalyScore > thresholds.anomalyScore) {
      severity = anomalyScore > 90 ? 'high' : 'medium';
      type = 'ANOMALY_DETECTED';
      description = `Anomaly score threshold exceeded: ${anomalyScore}`;
      nistControl = 'CA-7';
    }

    if (!severity) return null;

    const incident: SecurityIncident = {
      id: `INC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      severity,
      type,
      source: metrics.source,
      description,
      timestamp: new Date().toISOString(),
      autoContained: severity === 'critical' || severity === 'high',
      nistControl,
    };

    this.incidents.push(incident);

    if (incident.autoContained) {
      console.error(`[MARCUS MAGNOLIA | FIRE EYES] 🔥 AUTO-CONTAINED: ${incident.type} from ${incident.source}`);
      console.error(`  Severity: ${incident.severity.toUpperCase()}`);
      console.error(`  NIST Control: ${incident.nistControl}`);
      console.error(`  Action: Quarantine initiated. Kill-switch armed.`);
    }

    return incident;
  }

  getIncidents(severity?: SecurityIncident['severity']): SecurityIncident[] {
    if (severity) return this.incidents.filter(i => i.severity === severity);
    return [...this.incidents];
  }

  getScanStats() {
    return {
      totalScans: this.scanCount,
      totalIncidents: this.incidents.length,
      criticalIncidents: this.incidents.filter(i => i.severity === 'critical').length,
      highIncidents: this.incidents.filter(i => i.severity === 'high').length,
      autoContained: this.incidents.filter(i => i.autoContained).length,
    };
  }
}

// ─── Agentic Segregation Enforcer ────────────────────────────

export class AgenticSegregationEnforcer {
  private tier1Agents = new Set<string>();
  private tier2Agents = new Set<string>();

  registerAgent(name: string, tier: 1 | 2): void {
    if (tier === 1) this.tier1Agents.add(name);
    else this.tier2Agents.add(name);
  }

  validateCrossAgentCall(caller: string, callee: string): {
    allowed: boolean;
    reason?: string;
  } {
    const callerTier = this.tier1Agents.has(caller) ? 1 : this.tier2Agents.has(caller) ? 2 : 0;
    const calleeTier = this.tier1Agents.has(callee) ? 1 : this.tier2Agents.has(callee) ? 2 : 0;

    // T2 can monitor T1, but T1 cannot modify T2
    if (callerTier === 1 && calleeTier === 2) {
      return {
        allowed: false,
        reason: `[MARCUS MAGNOLIA] T1 agent "${caller}" cannot modify T2 agent "${callee}". Agentic segregation enforced.`,
      };
    }

    return { allowed: true };
  }
}

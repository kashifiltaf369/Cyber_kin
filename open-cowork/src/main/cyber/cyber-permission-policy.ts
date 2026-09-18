import { v4 as uuidv4 } from 'uuid';
import type {
  CyberCapabilityDefinition,
  CyberCapabilityExecutionContext,
  CyberCapabilityName,
} from './cyber-capability-registry';

export type CyberActionRiskCategory =
  | 'READ_ONLY'
  | 'ANALYSIS'
  | 'LOW_RISK_ACTION'
  | 'HIGH_RISK_ACTION'
  | 'DESTRUCTIVE_ACTION';

export type CyberApprovalState = 'NOT_REQUIRED' | 'APPROVED' | 'DENIED' | 'REQUIRES_EXPLICIT_HUMAN_APPROVAL';

export interface CyberActionAuditRecord {
  id: string;
  actor: 'human' | 'agent' | 'system';
  agent: string;
  timestamp: number;
  investigationId: string | null;
  capabilityName: CyberCapabilityName;
  actionCategory: CyberActionRiskCategory;
  target: string;
  parameters: Record<string, unknown>;
  result: { status: 'allowed' | 'denied' | 'executed' | 'failed'; summary: string; details?: Record<string, unknown> };
  approvalState: CyberApprovalState;
}

export interface CyberPermissionDecision {
  allowed: boolean;
  approvalState: CyberApprovalState;
  reason: string;
  requiresExplicitApproval: boolean;
}

export interface CyberPermissionContext {
  sessionId: string;
  investigationId: string | null;
  actor?: CyberActionAuditRecord['actor'];
  agent?: string;
}

function deepFreeze<T>(value: T): T {
  if (value === null || value === undefined) return value;
  if (typeof value !== 'object') return value;
  if (Object.isFrozen(value)) return value;
  const proto = Object.getPrototypeOf(value);
  if (proto !== null && proto !== Object.prototype && proto !== Array.prototype) return value;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) deepFreeze(value[i]);
  } else {
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record)) deepFreeze(record[key]);
  }
  return Object.freeze(value);
}

function deepCloneAuditRecord(record: CyberActionAuditRecord): CyberActionAuditRecord {
  return JSON.parse(JSON.stringify(record)) as CyberActionAuditRecord;
}

export class CyberActionAuditTrail {
  private readonly records: CyberActionAuditRecord[] = [];
  private readonly appendedIds = new Set<string>();

  append(record: Omit<CyberActionAuditRecord, 'id'>): CyberActionAuditRecord {
    const withId = { id: uuidv4(), ...record };
    const deeplyFrozen = deepFreeze(withId) as CyberActionAuditRecord;
    this.records.push(deeplyFrozen);
    this.appendedIds.add(deeplyFrozen.id);
    return deeplyFrozen;
  }

  list(): CyberActionAuditRecord[] {
    return this.records.map((r) => deepCloneAuditRecord(r));
  }

  getByInvestigationId(investigationId: string): CyberActionAuditRecord[] {
    return this.records
      .filter((item) => item.investigationId === investigationId)
      .map((r) => deepCloneAuditRecord(r));
  }

  hasRecord(id: string): boolean {
    return this.appendedIds.has(id);
  }
}

export function classifyCapabilityRisk(capability: Pick<CyberCapabilityDefinition, 'name' | 'riskLevel' | 'tags' | 'permissionsRequired'>): CyberActionRiskCategory {
  const tags = capability.tags.map((tag) => tag.toLowerCase());
  const permissions = capability.permissionsRequired.map((item) => item.toLowerCase());
  const text = [capability.name, ...tags, ...permissions].join(' ').toLowerCase();

  if (/delete|remove|destructive|remediation|quarantine/.test(text)) {
    return 'DESTRUCTIVE_ACTION';
  }
  if (/kill|disable|firewall|isolate|contain|terminate|write|modify/.test(text) || capability.riskLevel === 'HIGH') {
    return 'HIGH_RISK_ACTION';
  }
  if (/analysis|pcap|hash|enrich|correlat/.test(text) || capability.riskLevel === 'MEDIUM') {
    return 'ANALYSIS';
  }
  if (/read|query|search|lookup/.test(text) || (/inspect/.test(text) && capability.riskLevel === 'LOW')) {
    return 'READ_ONLY';
  }
  if (/inspect/.test(text)) {
    return 'ANALYSIS';
  }
  // Fail closed: anything unmatched (including any remaining HIGH risk
  // capability) is treated as a high-risk action and requires approval.
  return 'HIGH_RISK_ACTION';
}

export function extractCapabilityTarget(input: unknown): string {
  if (!input || typeof input !== 'object') return 'unknown';
  const record = input as Record<string, unknown>;
  for (const key of ['filePath', 'sourcePath', 'directoryPath', 'indicator', 'query', 'target', 'entityId']) {
    const value = record[key];
    if (typeof value === 'string' && value.trim()) return value;
  }
  return 'unknown';
}

export class CyberPermissionPolicy {
  decide(
    capability: Pick<CyberCapabilityDefinition, 'name' | 'riskLevel' | 'tags' | 'permissionsRequired'>,
    _input: unknown,
    explicitApproval = false
  ): CyberPermissionDecision {
    const category = classifyCapabilityRisk(capability);
    if (category === 'HIGH_RISK_ACTION' || category === 'DESTRUCTIVE_ACTION') {
      if (!explicitApproval) {
        return {
          allowed: false,
          approvalState: 'REQUIRES_EXPLICIT_HUMAN_APPROVAL',
          reason: `Capability ${capability.name} is ${category} and requires explicit human approval.`,
          requiresExplicitApproval: true,
        };
      }
      return {
        allowed: true,
        approvalState: 'APPROVED',
        reason: `Capability ${capability.name} approved for ${category}.`,
        requiresExplicitApproval: true,
      };
    }

    return {
      allowed: true,
      approvalState: 'NOT_REQUIRED',
      reason: `Capability ${capability.name} is categorized as ${category}.`,
      requiresExplicitApproval: false,
    };
  }

  audit(
    trail: CyberActionAuditTrail,
    capability: Pick<CyberCapabilityDefinition, 'name' | 'riskLevel' | 'tags' | 'permissionsRequired'>,
    input: unknown,
    context: CyberPermissionContext,
    decision: CyberPermissionDecision,
    outcome: CyberActionAuditRecord['result']
  ): CyberActionAuditRecord {
    return trail.append({
      actor: context.actor || 'agent',
      agent: context.agent || context.sessionId,
      timestamp: Date.now(),
      investigationId: context.investigationId,
      capabilityName: capability.name,
      actionCategory: classifyCapabilityRisk(capability),
      target: extractCapabilityTarget(input),
      parameters: (input && typeof input === 'object' ? (input as Record<string, unknown>) : {}) || {},
      result: outcome,
      approvalState: decision.approvalState,
    });
  }
}

export interface CyberCapabilityAuditContext extends CyberCapabilityExecutionContext {
  explicitHumanApproval?: boolean;
}

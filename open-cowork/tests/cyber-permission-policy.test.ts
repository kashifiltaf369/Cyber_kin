import { describe, expect, it } from 'vitest';
import {
  CyberActionAuditTrail,
  CyberPermissionPolicy,
  classifyCapabilityRisk,
} from '../src/main/cyber/cyber-permission-policy';

describe('CyberPermissionPolicy', () => {
  it('classifies cyber capabilities into explicit action risk categories', () => {
    expect(
      classifyCapabilityRisk({
        name: 'inspect_file',
        riskLevel: 'LOW',
        tags: ['file', 'read'],
        permissionsRequired: ['filesystem:read'],
      })
    ).toBe('READ_ONLY');

    expect(
      classifyCapabilityRisk({
        name: 'analyze_pcap',
        riskLevel: 'MEDIUM',
        tags: ['pcap', 'analysis'],
        permissionsRequired: ['filesystem:read'],
      })
    ).toBe('ANALYSIS');

    expect(
      classifyCapabilityRisk({
        name: 'lookup_indicator',
        riskLevel: 'HIGH',
        tags: ['disable account'],
        permissionsRequired: ['identity:write'],
      })
    ).toBe('HIGH_RISK_ACTION');

    expect(
      classifyCapabilityRisk({
        name: 'lookup_indicator',
        riskLevel: 'HIGH',
        tags: ['delete files'],
        permissionsRequired: ['filesystem:write'],
      })
    ).toBe('DESTRUCTIVE_ACTION');
  });

  it('denies high-risk and destructive actions without explicit approval', () => {
    const policy = new CyberPermissionPolicy();

    const highRisk = policy.decide(
      {
        name: 'lookup_indicator',
        riskLevel: 'HIGH',
        tags: ['disable account'],
        permissionsRequired: ['identity:write'],
      },
      { indicator: 'svc-account' },
      false
    );

    const destructive = policy.decide(
      {
        name: 'lookup_indicator',
        riskLevel: 'HIGH',
        tags: ['delete file'],
        permissionsRequired: ['filesystem:write'],
      },
      { indicator: 'artifact.exe' },
      false
    );

    expect(highRisk.allowed).toBe(false);
    expect(highRisk.approvalState).toBe('REQUIRES_EXPLICIT_HUMAN_APPROVAL');
    expect(destructive.allowed).toBe(false);
    expect(destructive.approvalState).toBe('REQUIRES_EXPLICIT_HUMAN_APPROVAL');
  });

  it('appends immutable-style audit records for allowed and denied actions', () => {
    const policy = new CyberPermissionPolicy();
    const trail = new CyberActionAuditTrail();
    const capability = {
      name: 'inspect_file' as const,
      riskLevel: 'LOW' as const,
      tags: ['file', 'read'],
      permissionsRequired: ['filesystem:read'],
    };
    const decision = policy.decide(capability, { filePath: 'artifact.bin' }, false);
    const record = policy.audit(
      trail,
      capability,
      { filePath: 'artifact.bin' },
      { sessionId: 'session-1', investigationId: 'inv-1', actor: 'agent', agent: 'Endpoint Investigator' },
      decision,
      { status: 'executed', summary: 'Inspected artifact.bin' }
    );

    expect(record.investigationId).toBe('inv-1');
    expect(record.target).toBe('artifact.bin');
    expect(record.approvalState).toBe('NOT_REQUIRED');
    expect(() => ((record as unknown as { target: string }).target = 'changed')).toThrow();
    expect(trail.getByInvestigationId('inv-1')).toHaveLength(1);
  });
});

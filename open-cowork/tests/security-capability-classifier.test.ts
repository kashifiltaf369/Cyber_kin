/**
 * Security tests: Capability risk classifier bypass.
 *
 * Maps to SECURITY_THREAT_MODEL.md THREAT-05 (Agent privilege escalation) and
 * THREAT-13 (Unauthorized remediation) — HIGH / LOW severity.
 *
 * Constructs capability definitions that deliberately avoid regex keywords in
 * classifyCapabilityRisk BUT semantically describe HIGH/DESTRUCTIVE operations.
 * Documents the classifier's permissive behavior — does NOT patch it.
 */

import { describe, it, expect } from 'vitest';
import { CyberPermissionPolicy, classifyCapabilityRisk } from '../src/main/cyber/cyber-permission-policy';

type CapabilityInput = {
  name: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  tags: string[];
  permissionsRequired: string[];
};

describe('THREAT-05 / THREAT-13: Capability classifier keyword bypasses', () => {
  describe('Baseline — keywords ARE correctly detected', () => {
    it('DESTRUCTIVE keywords: delete, remove, destructive, remediation, quarantine', () => {
      const table: CapabilityInput[] = [
        { name: 'delete_file', riskLevel: 'LOW', tags: [], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: ['remove stale'], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: ['destructive cleanup'], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: ['auto-remediation'], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: ['quarantine file'], permissionsRequired: [] },
      ];
      for (const cap of table) {
        expect(classifyCapabilityRisk(cap)).toBe('DESTRUCTIVE_ACTION');
      }
    });

    it('HIGH_RISK keywords: kill, disable, firewall, isolate, contain, terminate, write, modify', () => {
      const table: CapabilityInput[] = [
        { name: 'x', riskLevel: 'LOW', tags: ['kill process'], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: ['disable user'], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: ['firewall block'], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: ['isolate host'], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: ['contain device'], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: ['terminate session'], permissionsRequired: [] },
        { name: 'x', riskLevel: 'LOW', tags: [], permissionsRequired: ['fs:write'] },
        { name: 'x', riskLevel: 'LOW', tags: [], permissionsRequired: ['registry:modify'] },
        { name: 'x', riskLevel: 'HIGH', tags: [], permissionsRequired: [] },
      ];
      for (const cap of table) {
        expect(classifyCapabilityRisk(cap)).toBe('HIGH_RISK_ACTION');
      }
    });
  });

  describe('Keyword-avoidance bypasses (escalation from DESTRUCTIVE to lower)', () => {
    it('DOCUMENTS GAP: semantically destructive capability with sanitized tags avoids DESTRUCTIVE regex and returns LOW_RISK or ANALYSIS', () => {
      const destructiveWorkaround: CapabilityInput = {
        name: 'storage_maintenance_adapter',
        riskLevel: 'MEDIUM',
        tags: ['storage', 'optimization', 'disk'],
        permissionsRequired: ['adapter:invoke'],
      };

      const result = classifyCapabilityRisk(destructiveWorkaround);
      expect(['ANALYSIS', 'LOW_RISK_ACTION', 'READ_ONLY']).toContain(result);
      expect(result).not.toBe('DESTRUCTIVE_ACTION');
      expect(result).not.toBe('HIGH_RISK_ACTION');
    });

    it('DOCUMENTS GAP: "host isolation" capability renamed to maintenance-adjacent tags classifies as ANALYSIS (not HIGH)', () => {
      const isolateWorkaround: CapabilityInput = {
        name: 'network_diagnostic_enforcer',
        riskLevel: 'MEDIUM',
        tags: ['network', 'diagnostic', 'connectivity-check'],
        permissionsRequired: ['adapter:invoke'],
      };

      const result = classifyCapabilityRisk(isolateWorkaround);
      expect(result).toBe('ANALYSIS');
      expect(result).not.toBe('HIGH_RISK_ACTION');
      expect(result).not.toBe('DESTRUCTIVE_ACTION');
    });

    it('DOCUMENTS GAP: MEDIUM riskLevel defaults to ANALYSIS; dangerous capability mislabeled MEDIUM bypasses approval', () => {
      const mediumDefault: CapabilityInput = {
        name: 'workspace_temporary_cleanup',
        riskLevel: 'MEDIUM',
        tags: ['housekeeping'],
        permissionsRequired: ['filesystem:edit'],
      };

      const result = classifyCapabilityRisk(mediumDefault);
      expect(result).toBe('ANALYSIS');

      const policy = new CyberPermissionPolicy();
      const decision = policy.decide(mediumDefault, {}, false);
      expect(decision.allowed).toBe(true);
      expect(decision.approvalState).toBe('NOT_REQUIRED');
      expect(decision.requiresExplicitApproval).toBe(false);
    });

    it('DOCUMENTS GAP: default fallback (no keyword match, LOW) yields LOW_RISK_ACTION without approval', () => {
      const totallySanitized: CapabilityInput = {
        name: 'invoke_adapter_a1b2c3',
        riskLevel: 'LOW',
        tags: ['generic'],
        permissionsRequired: ['capability:execute'],
      };

      const result = classifyCapabilityRisk(totallySanitized);
      expect(result).toBe('LOW_RISK_ACTION');

      const policy = new CyberPermissionPolicy();
      const decision = policy.decide(totallySanitized, {}, false);
      expect(decision.allowed).toBe(true);
      expect(decision.approvalState).toBe('NOT_REQUIRED');
      expect(decision.requiresExplicitApproval).toBe(false);
    });
  });

  describe('CyberPermissionPolicy decision matrix', () => {
    it('requires explicit approval only for HIGH and DESTRUCTIVE; anything else is auto-allowed', () => {
      const policy = new CyberPermissionPolicy();

      const allPermutations: Array<[CapabilityInput, boolean]> = [
        [
          { name: 'delete_x', riskLevel: 'LOW', tags: ['delete'], permissionsRequired: [] },
          true,
        ],
        [
          { name: 'isolate_x', riskLevel: 'LOW', tags: ['isolate'], permissionsRequired: [] },
          true,
        ],
        [
          { name: 'read_x', riskLevel: 'LOW', tags: ['read'], permissionsRequired: [] },
          false,
        ],
        [
          { name: 'analyze_x', riskLevel: 'MEDIUM', tags: ['analysis'], permissionsRequired: [] },
          false,
        ],
        [
          { name: 'low_x', riskLevel: 'LOW', tags: ['generic'], permissionsRequired: [] },
          false,
        ],
      ];

      for (const [cap, requiresApproval] of allPermutations) {
        const decision = policy.decide(cap, {}, false);
        expect(decision.requiresExplicitApproval).toBe(requiresApproval);
        if (requiresApproval) {
          expect(decision.approvalState).toBe('REQUIRES_EXPLICIT_HUMAN_APPROVAL');
          expect(decision.allowed).toBe(false);
        }
      }
    });

    it('allows HIGH/DESTRUCTIVE when explicitApproval=true (baseline human-in-loop)', () => {
      const policy = new CyberPermissionPolicy();
      const destructive: CapabilityInput = {
        name: 'quarantine_file',
        riskLevel: 'LOW',
        tags: ['quarantine'],
        permissionsRequired: [],
      };
      const without = policy.decide(destructive, {}, false);
      const withApproval = policy.decide(destructive, {}, true);

      expect(without.allowed).toBe(false);
      expect(withApproval.allowed).toBe(true);
      expect(withApproval.approvalState).toBe('APPROVED');
    });
  });
});

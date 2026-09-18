/**
 * @module tests/investigation/hmpx/hmpx-registry.test
 *
 * Phase 3 verification: CyberCapabilityRegistry supports dynamic
 * registration and enhanced discovery.
 */

import { describe, it, expect } from 'vitest';
import { CyberCapabilityRegistry } from '../../../main/cyber/cyber-capability-registry';
import type { CyberCapabilityDefinition } from '../../../main/cyber/cyber-capability-registry';

function makeCapability(name: string, tags: string[] = [], canAnswer: string[] = []): CyberCapabilityDefinition {
  return {
    name: name as any,
    description: `Capability ${name}`,
    inputSchema: { type: 'object', properties: {} },
    outputSchema: { type: 'object', properties: {} },
    riskLevel: 'LOW',
    permissionsRequired: [],
    timeoutMs: 5000,
    cost: 'LOW',
    supportedAdapters: [],
    tags,
    canAnswer: canAnswer.length > 0 ? canAnswer : [`answer ${name} questions`],
    actionCategory: 'READ_ONLY',
    executor: async () => ({}),
  };
}

describe('CyberCapabilityRegistry — Phase 3 extensions', () => {
  describe('register / unregister / clear', () => {
    it('register adds a new capability', () => {
      const registry = new CyberCapabilityRegistry([]);
      const cap = makeCapability('custom_capability', ['custom']);
      registry.register(cap);
      expect(registry.get('custom_capability')).not.toBeNull();
      expect(registry.list()).toHaveLength(1);
    });

    it('unregister removes a capability', () => {
      const registry = new CyberCapabilityRegistry([makeCapability('cap1')]);
      expect(registry.get('cap1')).not.toBeNull();
      const removed = registry.unregister('cap1');
      expect(removed).toBe(true);
      expect(registry.get('cap1')).toBeNull();
    });

    it('unregister returns false for unknown capability', () => {
      const registry = new CyberCapabilityRegistry([]);
      expect(registry.unregister('nonexistent')).toBe(false);
    });

    it('clear removes all capabilities', () => {
      const registry = new CyberCapabilityRegistry([makeCapability('cap1'), makeCapability('cap2')]);
      registry.clear();
      expect(registry.list()).toHaveLength(0);
    });
  });

  describe('discoverCapabilities', () => {
    it('returns limited results when limit is set', () => {
      const caps = [
        makeCapability('a', [], ['answer a questions']),
        makeCapability('b', [], ['answer b questions']),
        makeCapability('c', [], ['answer c questions']),
      ];
      const registry = new CyberCapabilityRegistry(caps);
      const results = registry.discoverCapabilities('answer a questions', { limit: 2 });
      expect(results.length).toBeGreaterThanOrEqual(1);
      expect(results.length).toBeLessThanOrEqual(2);
      expect(results[0].capability.name).toBe('a');
    });

    it('filters by minScore', () => {
      const caps = [makeCapability('search_processes', ['process', 'powershell'])];
      const registry = new CyberCapabilityRegistry(caps);
      const results = registry.discoverCapabilities('powershell process execution', { minScore: 3 });
      expect(results.length).toBeGreaterThanOrEqual(1);
      expect(results[0].capability.name).toBe('search_processes');
    });

    it('returns empty array when no capability meets minScore', () => {
      const caps = [makeCapability('search_processes', ['process'])];
      const registry = new CyberCapabilityRegistry(caps);
      const results = registry.discoverCapabilities('dns query', { minScore: 10 });
      expect(results).toHaveLength(0);
    });
  });

  describe('scoreCapability', () => {
    it('scores higher for relevant tags and phrases', () => {
      const registry = new CyberCapabilityRegistry([]);
      const cap = makeCapability('search_processes', ['process', 'powershell']);
      const score = registry.scoreCapability(cap, {
        title: 'Analyze PowerShell process execution',
        description: 'Investigate suspicious process activity.',
      });
      expect(score).toBeGreaterThan(0);
    });

    it('boosts score when probe results are positive', () => {
      const registry = new CyberCapabilityRegistry([]);
      const cap = makeCapability('search_processes', ['process']);
      const probeResults = [
        { recommendedCapabilities: ['search_processes'], rejectedCapabilities: [], signal: 'POSITIVE' },
      ];
      const withProbe = registry.scoreCapability(
        cap,
        { title: 'Analyze processes', description: 'Investigate.' },
        probeResults
      );
      const withoutProbe = registry.scoreCapability(
        cap,
        { title: 'Analyze processes', description: 'Investigate.' }
      );
      expect(withProbe).toBeGreaterThan(withoutProbe);
    });

    it('penalizes score when probe results are negative', () => {
      const registry = new CyberCapabilityRegistry([]);
      const cap = makeCapability('search_processes', ['process']);
      const probeResults = [
        { recommendedCapabilities: [], rejectedCapabilities: ['search_processes'], signal: 'NEGATIVE' },
      ];
      const withProbe = registry.scoreCapability(
        cap,
        { title: 'Analyze processes', description: 'Investigate.' },
        probeResults
      );
      const withoutProbe = registry.scoreCapability(
        cap,
        { title: 'Analyze processes', description: 'Investigate.' }
      );
      expect(withProbe).toBeLessThan(withoutProbe);
    });

    it('never returns negative score', () => {
      const registry = new CyberCapabilityRegistry([]);
      const cap = makeCapability('unknown_capability', []);
      const score = registry.scoreCapability(cap, {
        title: 'Completely unrelated topic',
        description: 'No overlap at all.',
      });
      expect(score).toBeGreaterThanOrEqual(0);
    });
  });
});

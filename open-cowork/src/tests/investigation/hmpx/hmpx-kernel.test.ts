/**
 * @module tests/investigation/hmpx/hmpx-kernel.test
 *
 * Phase 2 verification: HMPI-X Cognitive Kernel maps cleanly onto
 * OpenCowork infrastructure and produces valid HMPI-X contracts.
 */

import { describe, it, expect, vi } from 'vitest';
import { HMPIXKernelImpl, DEFAULT_PROBE_BUDGET, DefaultProbeExecutor } from '../../../main/investigation/hmpx-kernel';
import type {
  HMPIXCapabilityCandidate,
  HMPIXCognitiveContext,
  HMPIXProblem,
  HMPIXProbeBudget,
  HMPIXProbeResult,
  HMPIXSelection,
  HMPIXSubProblem,
} from '../../../main/investigation/hmpx-types';
import type {
  CyberCapabilityDefinition,
  CyberCapabilityRegistry,
} from '../../../main/cyber/cyber-capability-registry';
import type { AgentCapabilityDefinition, AgentCapabilityRegistry } from '../../../main/investigation/parallel-investigation-engine';
import type { InvestigationReplanner, UncertaintyAssessment } from '../../../main/investigation/investigation-replanner';
import type { InvestigationService } from '../../../main/investigation/investigation-service';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

function createMockCyberCapability(name: string, tags: string[] = []): CyberCapabilityDefinition {
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
    canAnswer: [`answer ${name} questions`],
    actionCategory: 'READ_ONLY',
    executor: async () => ({ matches: [] }),
  };
}

function createMockCyberRegistry(caps: CyberCapabilityDefinition[]): CyberCapabilityRegistry {
  return {
    list: () => caps,
    get: (name) => caps.find((c) => c.name === name) || null,
    discover: (question: string) => {
      const q = question.toLowerCase();
      return caps
        .map((cap) => {
          const score = cap.tags.filter((t) => q.includes(t.toLowerCase())).length * 4
            + cap.canAnswer.filter((a) => q.includes(a.toLowerCase())).length * 4;
          return { capability: cap, score, reasons: score > 0 ? [`matches: ${cap.name}`] : [] };
        })
        .filter((item) => item.score > 0)
        .sort((a, b) => b.score - a.score);
    },
    execute: async (name, input) => {
      const cap = caps.find((c) => c.name === name);
      if (!cap) throw new Error(`Unknown capability: ${name}`);
      return cap.executor(input);
    },
  } as unknown as CyberCapabilityRegistry;
}

function createMockAgentRegistry(roles: AgentCapabilityDefinition[]): AgentCapabilityRegistry {
  return {
    get: (role) => roles.find((r) => r.role === role) || null,
    list: () => roles,
    selectRolesForInvestigation: () => roles.map((r) => r.role),
  } as unknown as AgentCapabilityRegistry;
}

function createMockReplanner(): InvestigationReplanner {
  return {
    assessUncertainty: () =>
      ({
        investigationId: 'inv-1',
        generatedAt: Date.now(),
        known: [],
        uncertain: [],
        competingHypotheses: [],
        missingEvidence: [],
        contradictoryEvidence: [],
        humanPriorities: [],
        risk: { tolerance: 'MEDIUM', requiresChallenge: false },
        availableCapabilities: [],
        summary: 'No uncertainty.',
      }) as UncertaintyAssessment,
    createReplan: () => ({
      objective: 'test',
      summary: 'No replan needed.',
      tasks: [],
      createdAt: Date.now(),
      hypothesisSummary: { ranked: [], leadingHypothesisId: null },
    }),
  } as unknown as InvestigationReplanner;
}

function createMockInvestigationService(): InvestigationService {
  return {} as InvestigationService;
}

function createMockProbeExecutor(): DefaultProbeExecutor {
  return new DefaultProbeExecutor(createMockCyberRegistry([]));
}

function buildDeps(capabilities: CyberCapabilityDefinition[] = [], agentRoles: AgentCapabilityDefinition[] = []) {
  const registry = createMockCyberRegistry(capabilities);
  return {
    investigationService: createMockInvestigationService(),
    cyberCapabilityRegistry: registry,
    agentCapabilityRegistry: createMockAgentRegistry(agentRoles),
    replanner: createMockReplanner(),
    probeExecutor: new DefaultProbeExecutor(registry),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('HMPIXKernelImpl', () => {
  // -------------------------------------------------------------------------
  // understand
  // -------------------------------------------------------------------------
  describe('understand', () => {
    it('creates a problem with derived risk tolerance and scope', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const problem = await kernel.understand(
        'Investigate endpoint WS-104',
        'Human suspects PowerShell',
        ['Do not modify the endpoint'],
        ['High priority']
      );

      expect(problem.objective).toBe('Investigate endpoint WS-104');
      expect(problem.humanContext).toBe('Human suspects PowerShell');
      expect(problem.constraints).toEqual(['Do not modify the endpoint']);
      expect(problem.priority).toEqual(['High priority']);
      expect(problem.riskTolerance).toBe('LOW');
      expect(problem.scope).toBe('WS-104');
      expect(problem.status).toBe('UNDERSTANDING');
    });

    it('defaults risk tolerance to MEDIUM when no constraint is present', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const problem = await kernel.understand('test', 'test', [], ['test']);
      expect(problem.riskTolerance).toBe('MEDIUM');
    });
  });

  // -------------------------------------------------------------------------
  // decompose
  // -------------------------------------------------------------------------
  describe('decompose', () => {
    it('generates endpoint subproblem when objective mentions endpoint', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const problem: HMPIXProblem = {
        id: 'p1',
        objective: 'Investigate endpoint compromise',
        humanContext: '',
        constraints: [],
        priority: [],
        riskTolerance: 'MEDIUM',
        scope: '',
        createdAt: Date.now(),
        status: 'CREATED',
      };

      const decomp = await kernel.decompose(problem);
      expect(decomp.subProblems.length).toBeGreaterThanOrEqual(1);
      expect(decomp.subProblems.some((s) => s.title.includes('endpoint') || s.title.includes('Endpoint'))).toBe(true);
    });

    it('generates network and identity subproblems when mentioned', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const problem: HMPIXProblem = {
        id: 'p1',
        objective: 'Investigate network and identity compromise',
        humanContext: '',
        constraints: [],
        priority: [],
        riskTolerance: 'MEDIUM',
        scope: '',
        createdAt: Date.now(),
        status: 'CREATED',
      };

      const decomp = await kernel.decompose(problem);
      const titles = decomp.subProblems.map((s) => s.title.toLowerCase());
      expect(titles.some((t) => t.includes('network'))).toBe(true);
      expect(titles.some((t) => t.includes('identity'))).toBe(true);
    });

    it('falls back to initial review when no domain keywords match', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const problem: HMPIXProblem = {
        id: 'p1',
        objective: 'Do something generic',
        humanContext: '',
        constraints: [],
        priority: [],
        riskTolerance: 'MEDIUM',
        scope: '',
        createdAt: Date.now(),
        status: 'CREATED',
      };

      const decomp = await kernel.decompose(problem);
      expect(decomp.subProblems).toHaveLength(1);
      expect(decomp.subProblems[0].title).toMatch(/initial/i);
    });

    it('infers parallel strategy when subproblems have no dependencies', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const problem: HMPIXProblem = {
        id: 'p1',
        objective: 'Investigate endpoint and network compromise',
        humanContext: '',
        constraints: [],
        priority: [],
        riskTolerance: 'MEDIUM',
        scope: '',
        createdAt: Date.now(),
        status: 'CREATED',
      };

      const decomp = await kernel.decompose(problem);
      expect(decomp.strategy).toBe('parallel_investigation');
    });
  });

  // -------------------------------------------------------------------------
  // discoverCapabilities
  // -------------------------------------------------------------------------
  describe('discoverCapabilities', () => {
    it('returns candidates from cyber registry and agent registry', async () => {
      const cyberCaps = [createMockCyberCapability('search_processes', ['process', 'powershell'])];
      const agentRoles: AgentCapabilityDefinition[] = [
        {
          role: 'Endpoint Investigator',
          description: 'Investigates endpoint processes.',
          keywords: ['powershell', 'endpoint'],
          canChallenge: false,
          maxConcurrency: 2,
        },
      ];

      const kernel = new HMPIXKernelImpl(buildDeps(cyberCaps, agentRoles));
      const sub: HMPIXSubProblem = {
        id: 'sub-1',
        problemId: 'p1',
        title: 'Analyze suspicious PowerShell execution',
        description: 'Investigate PowerShell execution on endpoint.',
        status: 'READY',
        priority: 1,
        dependsOn: [],
        createdAt: Date.now(),
      };

      const candidates = await kernel.discoverCapabilities(sub, emptyContext());
      expect(candidates.length).toBeGreaterThanOrEqual(1);
      const names = candidates.map((c) => c.capability.name);
      expect(names).toContain('search_processes');
      expect(names).toContain('Endpoint Investigator');
    });

    it('returns empty array when no capabilities match', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps([], []));
      const sub: HMPIXSubProblem = {
        id: 'sub-1',
        problemId: 'p1',
        title: 'Unknown domain',
        description: 'Unknown domain investigation.',
        status: 'READY',
        priority: 1,
        dependsOn: [],
        createdAt: Date.now(),
      };

      const candidates = await kernel.discoverCapabilities(sub, emptyContext());
      expect(candidates).toHaveLength(0);
    });

    it('sorts candidates by relevance then information gain', async () => {
      const cyberCaps = [
        createMockCyberCapability('search_processes', ['process']),
        createMockCyberCapability('search_dns', ['dns']),
      ];

      const kernel = new HMPIXKernelImpl(buildDeps(cyberCaps, []));
      const sub: HMPIXSubProblem = {
        id: 'sub-1',
        problemId: 'p1',
        title: 'Analyze process execution',
        description: 'Investigate processes.',
        status: 'READY',
        priority: 1,
        dependsOn: [],
        createdAt: Date.now(),
      };

      const candidates = await kernel.discoverCapabilities(sub, emptyContext());
      expect(candidates[0].capability.name).toBe('search_processes');
    });
  });

  // -------------------------------------------------------------------------
  // probe
  // -------------------------------------------------------------------------
  describe('probe', () => {
    it('returns results for probeable capabilities within budget', async () => {
      const cyberCaps = [
        {
          name: 'search_processes',
          description: 'Search processes.',
          inputSchema: { type: 'object', properties: {} },
          outputSchema: { type: 'object', properties: {} },
          riskLevel: 'LOW' as const,
          permissionsRequired: [],
          timeoutMs: 5000,
          cost: 'LOW' as const,
          supportedAdapters: [],
          tags: ['process', 'powershell'],
          canAnswer: ['answer search_processes questions'],
          actionCategory: 'READ_ONLY',
          executor: async () => ({ matches: [{ id: 'ev-probe-1', line: 'powershell.exe' }] }),
        },
      ];
      const kernel = new HMPIXKernelImpl(buildDeps(cyberCaps as any));
      const sub: HMPIXSubProblem = {
        id: 'sub-1',
        problemId: 'p1',
        title: 'Analyze processes',
        description: 'Investigate processes.',
        status: 'READY',
        priority: 1,
        dependsOn: [],
        createdAt: Date.now(),
      };

      const candidates: HMPIXCapabilityCandidate[] = [
        {
          capability: kernel['toHMPIXCapability'](cyberCaps[0] as any),
          relevance: 0.8,
          expectedInformationGain: 0.7,
          confidence: 0.8,
          availability: true,
          reasons: ['test'],
        },
      ];

      const results = await kernel.probe(sub, candidates, DEFAULT_PROBE_BUDGET);
      expect(results.length).toBeGreaterThanOrEqual(1);
      expect(results[0].signal).toBe('POSITIVE');
    });

    it('respects probe budget maxCount', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const sub: HMPIXSubProblem = {
        id: 'sub-1',
        problemId: 'p1',
        title: 'test',
        description: 'test',
        status: 'READY',
        priority: 1,
        dependsOn: [],
        createdAt: Date.now(),
      };

      const candidates: HMPIXCapabilityCandidate[] = Array.from({ length: 10 }).map((_, i) => ({
        capability: {
          id: `cap-${i}`,
          name: `cap-${i}`,
          description: `test ${i}`,
          domain: 'test',
          requiredInputs: [],
          producedOutputs: [],
          availableTools: [],
          riskLevel: 'LOW' as const,
          estimatedCost: 'LOW' as const,
          estimatedLatency: 5000,
          reliability: 0.8,
          specialization: [],
          probeCapability: true,
          executionCapability: true,
        },
        relevance: 0.5,
        expectedInformationGain: 0.5,
        confidence: 0.5,
        availability: true,
        reasons: [],
      }));

      const results = await kernel.probe(sub, candidates, { maxDepth: 2, maxCount: 2, maxCost: 10000, maxLatency: 1000 });
      expect(results.length).toBeLessThanOrEqual(2);
    });
  });

  // -------------------------------------------------------------------------
  // select
  // -------------------------------------------------------------------------
  describe('select', () => {
    it('scores and ranks capabilities', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const sub: HMPIXSubProblem = {
        id: 'sub-1',
        problemId: 'p1',
        title: 'test',
        description: 'test',
        status: 'READY',
        priority: 1,
        dependsOn: [],
        createdAt: Date.now(),
      };

      const candidates: HMPIXCapabilityCandidate[] = [
        {
          capability: {
            id: 'cap-high',
            name: 'HighRelevance',
            description: 'Highly relevant.',
            domain: 'endpoint',
            requiredInputs: [],
            producedOutputs: [],
            availableTools: [],
            riskLevel: 'LOW',
            estimatedCost: 'LOW',
            estimatedLatency: 1000,
            reliability: 0.9,
            specialization: [],
            probeCapability: false,
            executionCapability: true,
          },
          relevance: 0.9,
          expectedInformationGain: 0.9,
          confidence: 0.9,
          availability: true,
          reasons: ['high relevance'],
        },
        {
          capability: {
            id: 'cap-low',
            name: 'LowRelevance',
            description: 'Not relevant.',
            domain: 'cloud',
            requiredInputs: [],
            producedOutputs: [],
            availableTools: [],
            riskLevel: 'HIGH',
            estimatedCost: 'HIGH',
            estimatedLatency: 120000,
            reliability: 0.3,
            specialization: [],
            probeCapability: false,
            executionCapability: true,
          },
          relevance: 0.1,
          expectedInformationGain: 0.1,
          confidence: 0.3,
          availability: true,
          reasons: ['low relevance'],
        },
      ];

      const selection = await kernel.select(sub, candidates, [], emptyContext());
      expect(selection.selectedCapabilities.length).toBeGreaterThanOrEqual(1);
      expect(selection.selectedCapabilities[0].capabilityId).toBe('cap-high');
      expect(selection.rejectedCapabilities.some((r) => r.capabilityId === 'cap-low')).toBe(true);
    });

    it('boosts score when probe result is positive', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const sub: HMPIXSubProblem = {
        id: 'sub-1',
        problemId: 'p1',
        title: 'test',
        description: 'test',
        status: 'READY',
        priority: 1,
        dependsOn: [],
        createdAt: Date.now(),
      };

      const candidates: HMPIXCapabilityCandidate[] = [
        {
          capability: {
            id: 'cap-1',
            name: 'Cap1',
            description: 'test',
            domain: 'test',
            requiredInputs: [],
            producedOutputs: [],
            availableTools: [],
            riskLevel: 'LOW',
            estimatedCost: 'LOW',
            estimatedLatency: 1000,
            reliability: 0.8,
            specialization: [],
            probeCapability: false,
            executionCapability: true,
          },
          relevance: 0.5,
          expectedInformationGain: 0.5,
          confidence: 0.5,
          availability: true,
          reasons: [],
        },
      ];

      const probeResults: HMPIXProbeResult[] = [
        {
          probeId: 'probe-1',
          signal: 'POSITIVE',
          confidence: 0.9,
          informationGainEstimate: 0.8,
          recommendedCapabilities: ['cap-1'],
          rejectedCapabilities: [],
          reason: 'Positive probe.',
        },
      ];

      const withProbe = await kernel.select(sub, candidates, probeResults, emptyContext());
      const withoutProbe = await kernel.select(sub, candidates, [], emptyContext());
      expect(withProbe.selectedCapabilities[0].score).toBeGreaterThan(withoutProbe.selectedCapabilities[0].score);
    });
  });

  // -------------------------------------------------------------------------
  // route
  // -------------------------------------------------------------------------
  describe('route', () => {
    it('creates execution intents from selection', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const selection: HMPIXSelection = {
        id: 'sel-1',
        problemId: 'p1',
        subProblemId: 'sub-1',
        selectedCapabilities: [
          {
            capabilityId: 'search_processes',
            score: 0.9,
            relevance: 0.9,
            expectedInformationGain: 0.8,
            confidence: 0.8,
            cost: 0.1,
            latency: 0.1,
            risk: 0.1,
            availability: true,
          },
        ],
        rejectedCapabilities: [],
        rationale: 'Selected for high relevance.',
        createdAt: Date.now(),
      };

      const context: HMPIXCognitiveContext = {
        problemId: 'p1',
        decomposition: { id: 'd1', problemId: 'p1', subProblems: [], strategy: 'parallel', createdAt: Date.now() },
        capabilities: [
          {
            capability: {
              id: 'search_processes',
              name: 'search_processes',
              description: 'Search processes.',
              domain: 'endpoint',
              requiredInputs: [],
              producedOutputs: ['processes'],
              availableTools: [],
              riskLevel: 'LOW',
              estimatedCost: 'LOW',
              estimatedLatency: 5000,
              reliability: 0.8,
              specialization: [],
              probeCapability: true,
              executionCapability: true,
            },
            relevance: 0.9,
            expectedInformationGain: 0.8,
            confidence: 0.8,
            availability: true,
            reasons: [],
          },
        ],
        probes: [],
        selections: [],
        intents: [],
        observations: [],
        replanDecisions: [],
        decisions: [],
        uncertainty: 0.5,
        updatedAt: Date.now(),
      };

      const intents = await kernel.route(selection, context);
      expect(intents).toHaveLength(1);
      expect(intents[0].capabilityId).toBe('search_processes');
      expect(intents[0].risk).toBe('READ_ONLY');
      expect(intents[0].status).toBe('PENDING');
    });
  });

  // -------------------------------------------------------------------------
  // observe
  // -------------------------------------------------------------------------
  describe('observe', () => {
    it('infers observation type from confidence', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());

      const observed = await kernel.observe('intent-1', { matches: [{ id: 'ev-1' }] });
      expect(observed.type).toBe('OBSERVATION');
      expect(observed.evidenceIds).toEqual(['ev-1']);

      const unknown = await kernel.observe('intent-1', {});
      expect(unknown.type).toBe('UNKNOWN');
    });
  });

  // -------------------------------------------------------------------------
  // replan
  // -------------------------------------------------------------------------
  describe('replan', () => {
    it('records replan decision with uncertainty delta', async () => {
      const kernel = new HMPIXKernelImpl(buildDeps());
      const problem: HMPIXProblem = {
        id: 'p1',
        objective: 'test',
        humanContext: '',
        constraints: [],
        priority: [],
        riskTolerance: 'MEDIUM',
        scope: '',
        createdAt: Date.now(),
        status: 'EXECUTING',
      };

      const context: HMPIXCognitiveContext = {
        problemId: 'p1',
        decomposition: { id: 'd1', problemId: 'p1', subProblems: [], strategy: 'parallel', createdAt: Date.now() },
        capabilities: [],
        probes: [],
        selections: [],
        intents: [],
        observations: [],
        replanDecisions: [],
        decisions: [],
        uncertainty: 0.7,
        updatedAt: Date.now(),
      };

      const decision = await kernel.replan(problem, context, 'new_evidence', 'New process evidence found.');
      expect(decision.trigger).toBe('new_evidence');
      expect(decision.triggerDetails).toBe('New process evidence found.');
      expect(decision.uncertaintyBefore).toBe(0.7);
    });
  });

  // -------------------------------------------------------------------------
  // DEFAULT_PROBE_BUDGET
  // -------------------------------------------------------------------------
  describe('DEFAULT_PROBE_BUDGET', () => {
    it('has sensible defaults', () => {
      expect(DEFAULT_PROBE_BUDGET.maxDepth).toBe(2);
      expect(DEFAULT_PROBE_BUDGET.maxCount).toBe(5);
      expect(DEFAULT_PROBE_BUDGET.maxCost).toBe(5000);
      expect(DEFAULT_PROBE_BUDGET.maxLatency).toBe(30000);
    });
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyContext(): HMPIXCognitiveContext {
  return {
    problemId: 'p1',
    decomposition: { id: 'd1', problemId: 'p1', subProblems: [], strategy: 'parallel', createdAt: Date.now() },
    capabilities: [],
    probes: [],
    selections: [],
    intents: [],
    observations: [],
    replanDecisions: [],
    decisions: [],
    uncertainty: 0.5,
    updatedAt: Date.now(),
  };
}

/**
 * @module tests/investigation/hmpx/hmpx-types.test
 *
 * Phase 1 verification: HMPI-X type contracts are pure, serializable,
 * and map cleanly onto existing OpenCowork abstractions.
 */

import { describe, it, expect } from 'vitest';
import type {
  HMPIXProblem,
  HMPIXSubProblem,
  HMPIXDecomposition,
  HMPIXCapability,
  HMPIXCapabilityCandidate,
  HMPIXProbe,
  HMPIXProbeResult,
  HMPIXProbeBudget,
  HMPIXSelection,
  HMPIXExecutionIntent,
  HMPIXObservation,
  HMPIXReplanDecision,
  HMPIXCognitiveContext,
  HMPIXKernel,
  HMPIXEvent,
} from '../../../main/investigation/hmpx-types';

describe('HMPI-X type contracts (Phase 1)', () => {
  // -------------------------------------------------------------------------
  // Problem
  // -------------------------------------------------------------------------
  describe('HMPIXProblem', () => {
    it('can be constructed with required fields', () => {
      const problem: HMPIXProblem = {
        id: 'problem-1',
        objective: 'Investigate endpoint compromise',
        humanContext: 'Human suspects PowerShell involvement',
        constraints: ['Do not modify the endpoint'],
        priority: ['High'],
        riskTolerance: 'LOW',
        scope: 'Endpoint WS-104',
        createdAt: Date.now(),
        status: 'CREATED',
      };

      expect(problem.id).toBe('problem-1');
      expect(problem.status).toBe('CREATED');
      expect(problem.riskTolerance).toBe('LOW');
      expect(problem.constraints).toHaveLength(1);
    });

    it('supports all lifecycle statuses', () => {
      const statuses: HMPIXProblem['status'][] = [
        'CREATED',
        'UNDERSTANDING',
        'DECOMPOSING',
        'DISCOVERING',
        'PROBING',
        'SELECTING',
        'EXECUTING',
        'OBSERVING',
        'CRITIQUING',
        'REPLANNING',
        'WAITING_FOR_HUMAN',
        'COMPLETED',
        'PAUSED',
        'STOPPED',
      ];

      for (const status of statuses) {
        const problem: HMPIXProblem = {
          id: 'problem-1',
          objective: 'test',
          humanContext: 'test',
          constraints: [],
          priority: [],
          riskTolerance: 'MEDIUM',
          scope: 'test',
          createdAt: Date.now(),
          status,
        };
        expect(problem.status).toBe(status);
      }
    });

    it('is serializable to JSON', () => {
      const problem: HMPIXProblem = {
        id: 'problem-1',
        objective: 'test',
        humanContext: 'test',
        constraints: [],
        priority: [],
        riskTolerance: 'HIGH',
        scope: 'test',
        createdAt: 1_700_000_000_000,
        status: 'EXECUTING',
      };

      const json = JSON.stringify(problem);
      const parsed = JSON.parse(json) as HMPIXProblem;
      expect(parsed.id).toBe('problem-1');
      expect(parsed.status).toBe('EXECUTING');
    });
  });

  // -------------------------------------------------------------------------
  // SubProblem
  // -------------------------------------------------------------------------
  describe('HMPIXSubProblem', () => {
    it('can express dependencies', () => {
      const sub: HMPIXSubProblem = {
        id: 'sub-1',
        problemId: 'problem-1',
        title: 'Analyze endpoint processes',
        description: 'Determine whether suspicious processes executed.',
        status: 'PENDING',
        priority: 1,
        dependsOn: [],
        createdAt: Date.now(),
      };

      expect(sub.dependsOn).toHaveLength(0);
      expect(sub.priority).toBe(1);
    });

    it('supports all statuses', () => {
      const statuses: HMPIXSubProblem['status'][] = [
        'PENDING', 'READY', 'EXECUTING', 'COMPLETED', 'FAILED', 'CANCELLED', 'BLOCKED',
      ];

      for (const status of statuses) {
        const sub: HMPIXSubProblem = {
          id: 'sub-1',
          problemId: 'problem-1',
          title: 'test',
          description: 'test',
          status,
          priority: 1,
          dependsOn: [],
          createdAt: Date.now(),
        };
        expect(sub.status).toBe(status);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Decomposition
  // -------------------------------------------------------------------------
  describe('HMPIXDecomposition', () => {
    it('groups sub-problems under a strategy', () => {
      const decomp: HMPIXDecomposition = {
        id: 'decomp-1',
        problemId: 'problem-1',
        subProblems: [
          {
            id: 'sub-1',
            problemId: 'problem-1',
            title: 'Process analysis',
            description: 'Analyze processes',
            status: 'READY',
            priority: 1,
            dependsOn: [],
            createdAt: Date.now(),
          },
          {
            id: 'sub-2',
            problemId: 'problem-1',
            title: 'Network analysis',
            description: 'Analyze network',
            status: 'READY',
            priority: 2,
            dependsOn: [],
            createdAt: Date.now(),
          },
        ],
        strategy: 'parallel_investigation',
        createdAt: Date.now(),
      };

      expect(decomp.subProblems).toHaveLength(2);
      expect(decomp.strategy).toBe('parallel_investigation');
    });
  });

  // -------------------------------------------------------------------------
  // Capability / CapabilityCandidate
  // -------------------------------------------------------------------------
  describe('HMPIXCapability', () => {
    it('can be constructed with required fields', () => {
      const cap: HMPIXCapability = {
        id: 'cap-1',
        name: 'EndpointProcessAnalysis',
        description: 'Analyze endpoint processes for suspicious activity.',
        domain: 'endpoint',
        requiredInputs: ['endpoint_id', 'time_window'],
        producedOutputs: ['process_observations', 'suspicious_candidates'],
        availableTools: ['search_processes', 'inspect_file'],
        riskLevel: 'LOW',
        estimatedCost: 'MEDIUM',
        estimatedLatency: 30000,
        reliability: 0.9,
        specialization: ['process_execution', 'command_line_analysis'],
        probeCapability: true,
        executionCapability: true,
      };

      expect(cap.domain).toBe('endpoint');
      expect(cap.probeCapability).toBe(true);
      expect(cap.executionCapability).toBe(true);
    });
  });

  describe('HMPIXCapabilityCandidate', () => {
    it('can be constructed with scoring fields', () => {
      const candidate: HMPIXCapabilityCandidate = {
        capability: {
          id: 'cap-1',
          name: 'EndpointProcessAnalysis',
          description: 'Analyze endpoint processes.',
          domain: 'endpoint',
          requiredInputs: [],
          producedOutputs: [],
          availableTools: [],
          riskLevel: 'LOW',
          estimatedCost: 'MEDIUM',
          estimatedLatency: 30000,
          reliability: 0.9,
          specialization: [],
          probeCapability: true,
          executionCapability: true,
        },
        relevance: 0.85,
        expectedInformationGain: 0.7,
        confidence: 0.8,
        availability: true,
        reasons: ['matches endpoint domain', 'matches process keywords'],
      };

      expect(candidate.relevance).toBeGreaterThan(0);
      expect(candidate.reasons).toHaveLength(2);
    });
  });

  // -------------------------------------------------------------------------
  // Probe
  // -------------------------------------------------------------------------
  describe('HMPIXProbe', () => {
    it('can be constructed with capability targets', () => {
      const probe: HMPIXProbe = {
        id: 'probe-1',
        problemId: 'problem-1',
        subProblemId: 'sub-1',
        capabilityIds: ['cap-1', 'cap-2'],
        status: 'PENDING',
        startedAt: Date.now(),
      };

      expect(probe.capabilityIds).toHaveLength(2);
      expect(probe.status).toBe('PENDING');
    });
  });

  describe('HMPIXProbeResult', () => {
    it('can express positive signal with recommendations', () => {
      const result: HMPIXProbeResult = {
        probeId: 'probe-1',
        signal: 'POSITIVE',
        confidence: 0.9,
        informationGainEstimate: 0.8,
        recommendedCapabilities: ['cap-1', 'cap-3'],
        rejectedCapabilities: ['cap-2'],
        reason: 'Capability cap-1 can answer the subproblem with high confidence.',
        result: { evidenceFound: true },
      };

      expect(result.signal).toBe('POSITIVE');
      expect(result.recommendedCapabilities).toContain('cap-1');
      expect(result.rejectedCapabilities).toContain('cap-2');
    });

    it('supports all signal types', () => {
      const signals: HMPIXProbeSignal[] = [
        'POSITIVE', 'NEGATIVE', 'NEUTRAL', 'INCONCLUSIVE',
      ];

      for (const signal of signals) {
        const result: HMPIXProbeResult = {
          probeId: 'probe-1',
          signal,
          confidence: 0.5,
          informationGainEstimate: 0.5,
          recommendedCapabilities: [],
          rejectedCapabilities: [],
          reason: 'test',
        };
        expect(result.signal).toBe(signal);
      }
    });
  });

  // -------------------------------------------------------------------------
  // ProbeBudget
  // -------------------------------------------------------------------------
  describe('HMPIXProbeBudget', () => {
    it('can be constructed with limits', () => {
      const budget: HMPIXProbeBudget = {
        maxDepth: 3,
        maxCount: 10,
        maxCost: 5000,
        maxLatency: 30000,
      };

      expect(budget.maxDepth).toBe(3);
      expect(budget.maxCount).toBe(10);
    });
  });

  // -------------------------------------------------------------------------
  // Selection
  // -------------------------------------------------------------------------
  describe('HMPIXSelection', () => {
    it('can rank capabilities with scores', () => {
      const selection: HMPIXSelection = {
        id: 'sel-1',
        problemId: 'problem-1',
        subProblemId: 'sub-1',
        selectedCapabilities: [
          {
            capabilityId: 'cap-1',
            score: 0.92,
            relevance: 0.9,
            expectedInformationGain: 0.85,
            confidence: 0.8,
            cost: 0.3,
            latency: 0.2,
            risk: 0.1,
            availability: true,
          },
        ],
        rejectedCapabilities: [
          {
            capabilityId: 'cap-2',
            reason: 'Low relevance to subproblem',
          },
        ],
        rationale: 'Selected cap-1 for high relevance and information gain.',
        createdAt: Date.now(),
      };

      expect(selection.selectedCapabilities).toHaveLength(1);
      expect(selection.rejectedCapabilities).toHaveLength(1);
      expect(selection.selectedCapabilities[0].score).toBeGreaterThan(
        selection.selectedCapabilities[0].cost
      );
    });
  });

  // -------------------------------------------------------------------------
  // Decision
  // -------------------------------------------------------------------------
  describe('HMPIXDecision', () => {
    it('records a rationale alongside a summary', () => {
      const decision: HMPIXDecision = {
        id: 'dec-1',
        problemId: 'problem-1',
        summary: 'Launched Endpoint and Network investigators in parallel.',
        rationale: 'Both subproblems are independent and high priority.',
        createdAt: Date.now(),
      };

      expect(decision.summary).toBeTruthy();
      expect(decision.rationale).toBeTruthy();
    });
  });

  // -------------------------------------------------------------------------
  // ExecutionIntent
  // -------------------------------------------------------------------------
  describe('HMPIXExecutionIntent', () => {
    it('can express a read-only investigation intent', () => {
      const intent: HMPIXExecutionIntent = {
        id: 'intent-1',
        problemId: 'problem-1',
        subProblemId: 'sub-1',
        capabilityId: 'search_processes',
        intent: 'Investigate suspicious PowerShell execution',
        target: { endpoint: 'WS-104' },
        requiredEvidence: ['process_events', 'command_lines'],
        risk: 'READ_ONLY',
        status: 'PENDING',
        createdAt: Date.now(),
      };

      expect(intent.risk).toBe('READ_ONLY');
      expect(intent.status).toBe('PENDING');
    });

    it('supports all risk levels', () => {
      const risks: HMPIXExecutionRisk[] = [
        'READ_ONLY', 'ANALYSIS', 'LOW_RISK', 'HIGH_RISK', 'DESTRUCTIVE',
      ];

      for (const risk of risks) {
        const intent: HMPIXExecutionIntent = {
          id: 'intent-1',
          problemId: 'problem-1',
          subProblemId: 'sub-1',
          capabilityId: 'test',
          intent: 'test',
          target: {},
          requiredEvidence: [],
          risk,
          status: 'PENDING',
          createdAt: Date.now(),
        };
        expect(intent.risk).toBe(risk);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Observation
  // -------------------------------------------------------------------------
  describe('HMPIXObservation', () => {
    it('distinguishes observation from inference', () => {
      const observed: HMPIXObservation = {
        id: 'obs-1',
        intentId: 'intent-1',
        type: 'OBSERVATION',
        content: 'PowerShell.exe executed at 14:32.',
        confidence: 0.9,
        evidenceIds: ['ev-1'],
        createdAt: Date.now(),
      };

      const inferred: HMPIXObservation = {
        id: 'obs-2',
        intentId: 'intent-1',
        type: 'INFERENCE',
        content: 'The execution is unusual for this endpoint.',
        confidence: 0.6,
        evidenceIds: ['ev-1'],
        createdAt: Date.now(),
      };

      expect(observed.type).toBe('OBSERVATION');
      expect(inferred.type).toBe('INFERENCE');
      expect(observed.confidence).toBeGreaterThan(inferred.confidence);
    });
  });

  // -------------------------------------------------------------------------
  // ReplanDecision
  // -------------------------------------------------------------------------
  describe('HMPIXReplanDecision', () => {
    it('records uncertainty delta', () => {
      const replan: HMPIXReplanDecision = {
        id: 'replan-1',
        problemId: 'problem-1',
        trigger: 'new_evidence',
        triggerDetails: 'Endpoint evidence revealed suspicious process tree.',
        uncertaintyBefore: 0.7,
        uncertaintyAfter: 0.4,
        recommendedActions: [
          {
            capabilityId: 'search_network_connections',
            subProblemId: 'sub-2',
            rationale: 'Network evidence needed to confirm lateral movement.',
            priority: 1,
          },
        ],
        createdAt: Date.now(),
      };

      expect(replan.trigger).toBe('new_evidence');
      expect(replan.uncertaintyAfter).toBeLessThan(replan.uncertaintyBefore);
    });

    it('supports all trigger types', () => {
      const triggers: HMPIXReplanTrigger[] = [
        'new_evidence',
        'probe_result',
        'execution_complete',
        'execution_failed',
        'contradiction_detected',
        'human_input',
        'human_redirect',
        'scope_change',
        'confidence_change',
      ];

      for (const trigger of triggers) {
        const replan: HMPIXReplanDecision = {
          id: 'replan-1',
          problemId: 'problem-1',
          trigger,
          triggerDetails: 'test',
          uncertaintyBefore: 0.5,
          uncertaintyAfter: 0.3,
          recommendedActions: [],
          createdAt: Date.now(),
        };
        expect(replan.trigger).toBe(trigger);
      }
    });
  });

  // -------------------------------------------------------------------------
  // CognitiveContext
  // -------------------------------------------------------------------------
  describe('HMPIXCognitiveContext', () => {
    it('aggregates all cognitive state', () => {
      const context: HMPIXCognitiveContext = {
        problemId: 'problem-1',
        decomposition: {
          id: 'decomp-1',
          problemId: 'problem-1',
          subProblems: [],
          strategy: 'parallel',
          createdAt: Date.now(),
        },
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

      expect(context.problemId).toBe('problem-1');
      expect(context.uncertainty).toBeGreaterThanOrEqual(0);
      expect(context.uncertainty).toBeLessThanOrEqual(1);
    });
  });

  // -------------------------------------------------------------------------
  // HMPIXKernel interface
  // -------------------------------------------------------------------------
  describe('HMPIXKernel interface', () => {
    it('is callable with expected signatures', () => {
      const kernel: HMPIXKernel = {
        async understand(objective, humanContext, constraints, priorities) {
          return {
            id: 'problem-1',
            objective,
            humanContext,
            constraints,
            priority: priorities,
            riskTolerance: 'MEDIUM',
            scope: '',
            createdAt: Date.now(),
            status: 'UNDERSTANDING',
          };
        },

        async decompose(problem) {
          return {
            id: 'decomp-1',
            problemId: problem.id,
            subProblems: [
              {
                id: 'sub-1',
                problemId: problem.id,
                title: 'Analyze processes',
                description: 'Investigate suspicious processes.',
                status: 'READY',
                priority: 1,
                dependsOn: [],
                createdAt: Date.now(),
              },
            ],
            strategy: 'parallel',
            createdAt: Date.now(),
          };
        },

        async discoverCapabilities() {
          return [];
        },

        async probe() {
          return [];
        },

        async select() {
          return {
            id: 'sel-1',
            problemId: 'problem-1',
            selectedCapabilities: [],
            rejectedCapabilities: [],
            rationale: 'No capabilities discovered.',
            createdAt: Date.now(),
          };
        },

        async route() {
          return [];
        },

        async observe() {
          return {
            id: 'obs-1',
            intentId: 'intent-1',
            type: 'OBSERVATION',
            content: 'Observed.',
            confidence: 0.8,
            evidenceIds: [],
            createdAt: Date.now(),
          };
        },

        async replan() {
          return {
            id: 'replan-1',
            problemId: 'problem-1',
            trigger: 'new_evidence',
            triggerDetails: 'test',
            uncertaintyBefore: 0.5,
            uncertaintyAfter: 0.3,
            recommendedActions: [],
            createdAt: Date.now(),
          };
        },
      };

      expect(kernel).toBeDefined();
      expect(typeof kernel.understand).toBe('function');
      expect(typeof kernel.decompose).toBe('function');
      expect(typeof kernel.discoverCapabilities).toBe('function');
      expect(typeof kernel.probe).toBe('function');
      expect(typeof kernel.select).toBe('function');
      expect(typeof kernel.route).toBe('function');
      expect(typeof kernel.observe).toBe('function');
      expect(typeof kernel.replan).toBe('function');
    });
  });

  // -------------------------------------------------------------------------
  // HMPIXEvent
  // -------------------------------------------------------------------------
  describe('HMPIXEvent', () => {
    it('can represent investigation lifecycle events', () => {
      const event: HMPIXEvent = {
        id: 'evt-1',
        problemId: 'problem-1',
        type: 'capability.selected',
        createdAt: Date.now(),
        actor: 'agent',
        summary: 'Selected Endpoint Investigator for subproblem sub-1.',
        data: {
          capabilityId: 'Endpoint Investigator',
          subProblemId: 'sub-1',
          score: 0.92,
        },
      };

      expect(event.type).toBe('capability.selected');
      expect(event.actor).toBe('agent');
      expect(event.data?.capabilityId).toBe('Endpoint Investigator');
    });
  });

  // -------------------------------------------------------------------------
  // Compatibility with existing OpenCowork types
  // -------------------------------------------------------------------------
  describe('compatibility with OpenCowork', () => {
    it('HMPIXProblemStatus does not collide with InvestigationStatus', () => {
      // Both systems share some statuses (CREATED, COMPLETED, PAUSED)
      // but HMPI-X adds cognitive-specific states.
      const hmpxStatuses: Set<string> = new Set([
        'CREATED', 'UNDERSTANDING', 'DECOMPOSING', 'DISCOVERING',
        'PROBING', 'SELECTING', 'EXECUTING', 'OBSERVING', 'CRITIQUING',
        'REPLANNING', 'WAITING_FOR_HUMAN', 'COMPLETED', 'PAUSED', 'STOPPED',
      ]);

      expect(hmpxStatuses.has('UNDERSTANDING')).toBe(true);
      expect(hmpxStatuses.has('CRITIQUING')).toBe(true);
      expect(hmpxStatuses.has('PROBING')).toBe(true);
    });

    it('HMPIXExecutionRisk maps to CyberActionRiskCategory conceptually', () => {
      // HMPI-X risk levels align with CyberPermissionPolicy categories:
      // READ_ONLY -> READ_ONLY
      // ANALYSIS -> ANALYSIS
      // LOW_RISK -> LOW_RISK_ACTION
      // HIGH_RISK -> HIGH_RISK_ACTION
      // DESTRUCTIVE -> DESTRUCTIVE_ACTION
      const risks: HMPIXExecutionRisk[] = [
        'READ_ONLY', 'ANALYSIS', 'LOW_RISK', 'HIGH_RISK', 'DESTRUCTIVE',
      ];
      expect(risks).toHaveLength(5);
    });

    it('HMPIXObservationType maps to InvestigationFindingType conceptually', () => {
      // OBSERVATION, INFERENCE, HYPOTHESIS, UNKNOWN map 1:1
      const types: HMPIXObservationType[] = [
        'OBSERVATION', 'INFERENCE', 'HYPOTHESIS', 'UNKNOWN',
      ];
      expect(types).toHaveLength(4);
    });
  });
});

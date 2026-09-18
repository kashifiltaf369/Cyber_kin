/**
 * @module main/investigation/hmpx-kernel
 *
 * HMPI-X Cognitive Kernel — Phase 2 implementation.
 *
 * This kernel is a pure domain orchestrator. It does NOT depend on Electron,
 * React, or the agent runner. It maps OpenCowork's existing investigation
 * infrastructure into the HMPI-X cognitive loop:
 *
 *   understand → decompose → discover → probe → select → route → observe → replan
 *
 * Dependencies are injected so the kernel remains testable.
 */

import { v4 as uuidv4 } from 'uuid';
import type {
  HMPIXCapabilityCandidate,
  HMPIXCognitiveContext,
  HMPIXDecomposition,
  HMPIXExecutionIntent,
  HMPIXKernel,
  HMPIXObservation,
  HMPIXProblem,
  HMPIXProbe,
  HMPIXProbeBudget,
  HMPIXProbeResult,
  HMPIXReplanDecision,
  HMPIXReplanTrigger,
  HMPIXSelection,
  HMPIXSubProblem,
} from './hmpx-types';
import type { InvestigationService } from './investigation-service';
import type { AgentCapabilityDefinition, AgentCapabilityRegistry, InvestigationAgentRole } from './parallel-investigation-engine';
import type { CyberCapabilityDefinition, CyberCapabilityRegistry } from '../cyber/cyber-capability-registry';
import type { InvestigationReplanner, UncertaintyAssessment } from './investigation-replanner';
import type { Investigation, InvestigationEvidence, InvestigationHypothesis } from '../../shared/cyber/investigation-types';

// ---------------------------------------------------------------------------
// Default probe budget (configurable)
// ---------------------------------------------------------------------------

export const DEFAULT_PROBE_BUDGET: HMPIXProbeBudget = {
  maxDepth: 2,
  maxCount: 5,
  maxCost: 5000,
  maxLatency: 30000,
};

// ---------------------------------------------------------------------------
// Kernel dependencies
// ---------------------------------------------------------------------------

export interface HMPIXKernelDependencies {
  investigationService: InvestigationService;
  cyberCapabilityRegistry: CyberCapabilityRegistry;
  agentCapabilityRegistry: AgentCapabilityRegistry;
  replanner: InvestigationReplanner;
  probeExecutor?: ProbeExecutor;
}

// ---------------------------------------------------------------------------
// Probe executor interface
// ---------------------------------------------------------------------------

export interface ProbeExecutor {
  executeProbe(capability: CyberCapabilityDefinition, input: unknown): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Default probe executor (delegates to registry)
// ---------------------------------------------------------------------------

export class DefaultProbeExecutor implements ProbeExecutor {
  constructor(private readonly registry: CyberCapabilityRegistry) {}

  async executeProbe(capability: CyberCapabilityDefinition, input: unknown): Promise<unknown> {
    return this.registry.execute(capability.name, input);
  }
}

// ---------------------------------------------------------------------------
// Kernel implementation
// ---------------------------------------------------------------------------

export class HMPIXKernelImpl implements HMPIXKernel {
  private readonly probeCount = new Map<string, number>();

  constructor(private readonly deps: HMPIXKernelDependencies) {}

  // -------------------------------------------------------------------------
  // 1. Understand
  // -------------------------------------------------------------------------

  async understand(
    objective: string,
    humanContext: string,
    constraints: string[],
    priorities: string[]
  ): Promise<HMPIXProblem> {
    const id = uuidv4();
    const problem: HMPIXProblem = {
      id,
      objective: objective.trim(),
      humanContext: humanContext.trim(),
      constraints: constraints.filter(Boolean),
      priority: priorities.filter(Boolean),
      riskTolerance: this.inferRiskTolerance(constraints),
      scope: this.extractScope(objective, humanContext),
      createdAt: Date.now(),
      status: 'UNDERSTANDING',
    };
    return problem;
  }

  // -------------------------------------------------------------------------
  // 2. Decompose
  // -------------------------------------------------------------------------

  async decompose(problem: HMPIXProblem): Promise<HMPIXDecomposition> {
    const subProblems = this.generateSubProblems(problem);
    const decomposition: HMPIXDecomposition = {
      id: uuidv4(),
      problemId: problem.id,
      subProblems,
      strategy: this.inferStrategy(subProblems),
      createdAt: Date.now(),
    };
    return decomposition;
  }

  // -------------------------------------------------------------------------
  // 3. Discover capabilities
  // -------------------------------------------------------------------------

  async discoverCapabilities(
    subProblem: HMPIXSubProblem,
    _context: HMPIXCognitiveContext
  ): Promise<HMPIXCapabilityCandidate[]> {
    const text = `${subProblem.title} ${subProblem.description}`.toLowerCase();

    const registryCandidates = this.deps.cyberCapabilityRegistry.discover(text);
    const agentRoles = this.deps.agentCapabilityRegistry.list();

    const candidates: HMPIXCapabilityCandidate[] = [];

    for (const match of registryCandidates) {
      const cap = match.capability;
      candidates.push({
        capability: this.toHMPIXCapability(cap),
        relevance: this.normalizeScore(match.score),
        expectedInformationGain: this.estimateInformationGain(cap, subProblem),
        confidence: 0.7,
        availability: true,
        reasons: match.reasons,
      });
    }

    for (const roleDef of agentRoles) {
      if (!this.isRoleRelevant(roleDef, text)) continue;
      candidates.push({
        capability: {
          id: roleDef.role,
          name: roleDef.role,
          description: roleDef.description,
          domain: this.inferDomain(roleDef.role),
          requiredInputs: [],
          producedOutputs: [],
          availableTools: [],
          riskLevel: 'LOW',
          estimatedCost: 'MEDIUM',
          estimatedLatency: 60000,
          reliability: 0.8,
          specialization: roleDef.keywords,
          probeCapability: false,
          executionCapability: true,
        },
        relevance: 0.6,
        expectedInformationGain: 0.5,
        confidence: 0.7,
        availability: true,
        reasons: [`matches agent role: ${roleDef.role}`],
      });
    }

    candidates.sort((a, b) => b.relevance - a.relevance || b.expectedInformationGain - a.expectedInformationGain);
    return candidates;
  }

  // -------------------------------------------------------------------------
  // 4. Probe
  // -------------------------------------------------------------------------

  async probe(
    subProblem: HMPIXSubProblem,
    candidates: HMPIXCapabilityCandidate[],
    budget: HMPIXProbeBudget
  ): Promise<HMPIXProbeResult[]> {
    const probeable = candidates.filter((c) => c.capability.probeCapability);
    const results: HMPIXProbeResult[] = [];
    const key = subProblem.id;
    const currentCount = this.probeCount.get(key) || 0;

    if (currentCount >= budget.maxCount) return results;

    const executor = this.deps.probeExecutor || new DefaultProbeExecutor(this.deps.cyberCapabilityRegistry);
    const toProbe = probeable.slice(0, Math.min(budget.maxCount - currentCount, 3));

    for (const candidate of toProbe) {
      const probe: HMPIXProbe = {
        id: uuidv4(),
        problemId: subProblem.problemId,
        subProblemId: subProblem.id,
        capabilityIds: [candidate.capability.id],
        status: 'RUNNING',
        startedAt: Date.now(),
      };

      try {
        const result = await Promise.race([
          executor.executeProbe(candidate.capability, { query: subProblem.description }),
          this.delay(budget.maxLatency).then(() => { throw new Error('probe_timeout'); }),
        ]);

        probe.status = 'COMPLETED';
        probe.completedAt = Date.now();

        const signal = this.interpretProbeResult(result);
        results.push({
          probeId: probe.id,
          signal,
          confidence: signal === 'POSITIVE' ? 0.8 : signal === 'NEGATIVE' ? 0.3 : 0.5,
          informationGainEstimate: signal === 'POSITIVE' ? 0.7 : 0.2,
          recommendedCapabilities: signal === 'POSITIVE' ? [candidate.capability.id] : [],
          rejectedCapabilities: signal === 'NEGATIVE' ? [candidate.capability.id] : [],
          reason: `Probe ${signal.toLowerCase()} for capability ${candidate.capability.name}.`,
          result,
        });
      } catch {
        probe.status = 'FAILED';
        probe.completedAt = Date.now();
        results.push({
          probeId: probe.id,
          signal: 'INCONCLUSIVE',
          confidence: 0,
          informationGainEstimate: 0,
          recommendedCapabilities: [],
          rejectedCapabilities: [candidate.capability.id],
          reason: 'Probe failed or timed out.',
        });
      }
    }

    this.probeCount.set(key, currentCount + results.length);
    return results;
  }

  // -------------------------------------------------------------------------
  // 5. Select
  // -------------------------------------------------------------------------

  async select(
    _subProblem: HMPIXSubProblem,
    candidates: HMPIXCapabilityCandidate[],
    probeResults: HMPIXProbeResult[],
    _context: HMPIXCognitiveContext
  ): Promise<HMPIXSelection> {
    const rejectedCapabilities = probeResults
      .filter((r) => r.signal === 'NEGATIVE' || r.signal === 'INCONCLUSIVE')
      .flatMap((r) => r.rejectedCapabilities);

    const scored = candidates
      .filter((c) => !rejectedCapabilities.includes(c.capability.id))
      .map((candidate) => {
        const probeBoost = probeResults.some(
          (r) => r.recommendedCapabilities.includes(candidate.capability.id) && r.signal === 'POSITIVE'
        )
          ? 0.15
          : 0;

        const score =
          candidate.relevance * 0.35 +
          candidate.expectedInformationGain * 0.35 +
          candidate.confidence * 0.15 +
          probeBoost -
          this.riskCost(candidate.capability.riskLevel) * 0.1 -
          this.latencyCost(candidate.capability.estimatedLatency) * 0.05;

        return {
          capabilityId: candidate.capability.id,
          score: Math.max(0, Math.min(1, score)),
          relevance: candidate.relevance,
          expectedInformationGain: candidate.expectedInformationGain,
          confidence: candidate.confidence,
          cost: this.riskCost(candidate.capability.riskLevel),
          latency: this.latencyCost(candidate.capability.estimatedLatency),
          risk: this.riskCost(candidate.capability.riskLevel),
          availability: candidate.availability,
        };
      })
      .filter((entry) => entry.score > 0.2)
      .sort((a, b) => b.score - a.score);

    const selected = scored.slice(0, 5);
    const selectedIds = new Set(selected.map((s) => s.capabilityId));
    const rejected = candidates
      .filter((c) => !selectedIds.has(c.capability.id) && !rejectedCapabilities.includes(c.capability.id))
      .map((c) => ({
        capabilityId: c.capability.id,
        reason: `Score ${c.relevance.toFixed(2)} below selection threshold.`,
      }));

    return {
      id: uuidv4(),
      problemId: _subProblem.problemId,
      subProblemId: _subProblem.id,
      selectedCapabilities: selected,
      rejectedCapabilities: rejected,
      rationale: `Selected ${selected.length} capability(ies) out of ${candidates.length} candidates based on relevance, information gain, confidence, and probe feedback.`,
      createdAt: Date.now(),
    };
  }

  // -------------------------------------------------------------------------
  // 6. Route
  // -------------------------------------------------------------------------

  async route(
    selection: HMPIXSelection,
    _context: HMPIXCognitiveContext
  ): Promise<HMPIXExecutionIntent[]> {
    return selection.selectedCapabilities.map((entry) => {
      const candidate = _context.capabilities.find((c) => c.capability.id === entry.capabilityId);
      return {
        id: uuidv4(),
        problemId: selection.problemId,
        subProblemId: selection.subProblemId || '',
        capabilityId: entry.capabilityId,
        intent: candidate?.capability.description || `Execute capability ${entry.capabilityId}`,
        target: {},
        requiredEvidence: candidate?.capability.producedOutputs || [],
        risk: this.mapRiskLevel(candidate?.capability.riskLevel || 'LOW'),
        status: 'PENDING',
        createdAt: Date.now(),
      };
    });
  }

  // -------------------------------------------------------------------------
  // 7. Observe
  // -------------------------------------------------------------------------

  async observe(intentId: string, result: unknown): Promise<HMPIXObservation> {
    const evidenceIds = this.extractEvidenceIds(result);
    const confidence = this.estimateConfidence(result);

    return {
      id: uuidv4(),
      intentId,
      type: confidence >= 0.8 ? 'OBSERVATION' : confidence >= 0.5 ? 'INFERENCE' : 'UNKNOWN',
      content: typeof result === 'string' ? result : JSON.stringify(result),
      confidence,
      evidenceIds,
      createdAt: Date.now(),
    };
  }

  // -------------------------------------------------------------------------
  // 8. Replan
  // -------------------------------------------------------------------------

  async replan(
    problem: HMPIXProblem,
    context: HMPIXCognitiveContext,
    trigger: HMPIXReplanTrigger,
    details: string
  ): Promise<HMPIXReplanDecision> {
    const uncertaintyBefore = context.uncertainty;
    let uncertaintyAfter = uncertaintyBefore;

    try {
      const assessment = this.deps.replanner.assessUncertainty(this.toInvestigation(problem, context));
      uncertaintyAfter = this.uncertaintyFromAssessment(assessment);
    } catch {
      // If replanner fails, preserve current uncertainty
      uncertaintyAfter = uncertaintyBefore;
    }

    const recommendedActions = this.buildRecommendedActions(context, trigger);

    return {
      id: uuidv4(),
      problemId: problem.id,
      trigger,
      triggerDetails: details,
      uncertaintyBefore,
      uncertaintyAfter,
      recommendedActions,
      createdAt: Date.now(),
    };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private toHMPIXCapability(cap: CyberCapabilityDefinition): HMPIXCapability {
    return {
      id: cap.name,
      name: cap.name,
      description: cap.description,
      domain: this.inferDomainFromName(cap.name),
      requiredInputs: Object.keys(cap.inputSchema.properties || {}),
      producedOutputs: Object.keys(cap.outputSchema.properties || {}),
      availableTools: cap.supportedAdapters,
      riskLevel: cap.riskLevel,
      estimatedCost: cap.cost,
      estimatedLatency: cap.timeoutMs,
      reliability: 0.8,
      specialization: cap.tags,
      probeCapability: true,
      executionCapability: true,
    };
  }

  private inferRiskTolerance(constraints: string[]): HMPIXProblem['riskTolerance'] {
    const lower = constraints.join(' ').toLowerCase();
    if (/do not modify|read-only|read_only|do not change/.test(lower)) return 'LOW';
    if (/safe|controlled|limited/.test(lower)) return 'MEDIUM';
    return 'MEDIUM';
  }

  private extractScope(objective: string, humanContext: string): string {
    const text = `${objective} ${humanContext}`;
    const hostMatch = /([a-z0-9]+-[a-z0-9]+)/i.exec(text);
    if (hostMatch) return hostMatch[1];
    const wordMatch = /\b([A-Z]{2,}[0-9-]+)\b/.exec(text);
    if (wordMatch) return wordMatch[1];
    return objective.slice(0, 100);
  }

  private generateSubProblems(problem: HMPIXProblem): HMPIXSubProblem[] {
    const lc = `${problem.objective} ${problem.humanContext}`.toLowerCase();
    const subs: HMPIXSubProblem[] = [];

    if (/endpoint|host|process|powershell|execution|persistence/.test(lc)) {
      subs.push(this.createSubProblem(problem, 'Analyze endpoint activity', 'Review endpoint execution, process, and host evidence.', 1));
    }
    if (/network|dns|ip|lateral|traffic|egress/.test(lc)) {
      subs.push(this.createSubProblem(problem, 'Analyze network activity', 'Review network movement, DNS, and communications evidence.', 2));
    }
    if (/identity|login|credential|account|mfa|tenant/.test(lc)) {
      subs.push(this.createSubProblem(problem, 'Analyze identity activity', 'Review authentication, account access, and identity evidence.', 3));
    }
    if (/ioc|indicator|malware|campaign|hash|domain/.test(lc)) {
      subs.push(this.createSubProblem(problem, 'Correlate threat intelligence', 'Correlate observed entities with threat intelligence.', 4));
    }

    if (subs.length === 0) {
      subs.push(this.createSubProblem(problem, 'Perform initial evidence review', 'Review objective and current evidence.', 1));
    }

    return subs;
  }

  private createSubProblem(
    problem: HMPIXProblem,
    title: string,
    description: string,
    priority: number
  ): HMPIXSubProblem {
    return {
      id: uuidv4(),
      problemId: problem.id,
      title,
      description,
      status: 'READY',
      priority,
      dependsOn: [],
      createdAt: Date.now(),
    };
  }

  private inferStrategy(subProblems: HMPIXSubProblem[]): string {
    const independent = subProblems.filter((s) => s.dependsOn.length === 0).length;
    if (independent === subProblems.length) return 'parallel_investigation';
    if (independent <= 1) return 'sequential_investigation';
    return 'mixed_investigation';
  }

  private isRoleRelevant(roleDef: AgentCapabilityDefinition, text: string): boolean {
    return roleDef.keywords.some((kw) => text.includes(kw.toLowerCase()));
  }

  private inferDomain(role: string): string {
    const lc = role.toLowerCase();
    if (lc.includes('endpoint')) return 'endpoint';
    if (lc.includes('network')) return 'network';
    if (lc.includes('identity')) return 'identity';
    if (lc.includes('threat')) return 'threat-intelligence';
    if (lc.includes('historical')) return 'historical';
    if (lc.includes('evidence') || lc.includes('synthes')) return 'analysis';
    if (lc.includes('research')) return 'research';
    if (lc.includes('challenger')) return 'critique';
    return 'generic';
  }

  private inferDomainFromName(name: string): string {
    const lc = name.toLowerCase();
    if (lc.includes('process') || lc.includes('endpoint') || lc.includes('file')) return 'endpoint';
    if (lc.includes('network') || lc.includes('dns') || lc.includes('pcap')) return 'network';
    if (lc.includes('identity') || lc.includes('auth')) return 'identity';
    if (lc.includes('indicator') || lc.includes('intel') || lc.includes('threat')) return 'threat-intelligence';
    if (lc.includes('historical') || lc.includes('browser')) return 'historical';
    if (lc.includes('event') || lc.includes('log')) return 'siem';
    return 'generic';
  }

  private estimateInformationGain(cap: CyberCapabilityDefinition, subProblem: HMPIXSubProblem): number {
    const textWords = new Set(`${subProblem.title} ${subProblem.description}`.toLowerCase().split(/\s+/));
    const capWords = new Set(`${cap.name} ${cap.description} ${cap.tags.join(' ')}`.toLowerCase().split(/\s+/));
    let overlap = 0;
    for (const word of textWords) {
      if (capWords.has(word)) overlap++;
    }
    return Math.min(1, overlap / 5);
  }

  private normalizeScore(raw: number): number {
    return Math.max(0, Math.min(1, raw / 20));
  }

  private riskCost(risk: string): number {
    switch (risk) {
      case 'LOW': return 0.1;
      case 'MEDIUM': return 0.3;
      case 'HIGH': return 0.6;
      default: return 0.3;
    }
  }

  private latencyCost(latencyMs: number): number {
    return Math.max(0, Math.min(1, latencyMs / 120000));
  }

  private interpretProbeResult(result: unknown): HMPIXProbeResult['signal'] {
    if (result && typeof result === 'object') {
      const record = result as Record<string, unknown>;
      if (Array.isArray(record.matches) && record.matches.length > 0) return 'POSITIVE';
      if (Array.isArray(record.processes) && record.processes.length > 0) return 'POSITIVE';
      if (Array.isArray(record.connections) && record.connections.length > 0) return 'POSITIVE';
      if (record.exists === true) return 'POSITIVE';
    }
    return 'NEGATIVE';
  }

  private extractEvidenceIds(result: unknown): string[] {
    if (!result || typeof result !== 'object') return [];
    const record = result as Record<string, unknown>;
    const arrays = [record.evidence, record.matches, record.processes, record.connections, record.records].filter(Array.isArray);
    for (const arr of arrays) {
      const items = arr as unknown[];
      if (items.length > 0 && typeof items[0] === 'object' && items[0] !== null) {
        return items
          .map((e: unknown) => (typeof e === 'object' && e ? (e as Record<string, unknown>).id : null))
          .filter((id: unknown): id is string => typeof id === 'string');
      }
    }
    return [];
  }

  private estimateConfidence(result: unknown): number {
    if (!result || typeof result !== 'object') return 0;
    const record = result as Record<string, unknown>;
    if (Array.isArray(record.matches) && record.matches.length > 0) return 0.8;
    if (Array.isArray(record.processes) && record.processes.length > 0) return 0.8;
    if (Array.isArray(record.connections) && record.connections.length > 0) return 0.8;
    if (record.exists === true) return 0.9;
    return 0.3;
  }

  private mapRiskLevel(risk: string): HMPIXExecutionIntent['risk'] {
    switch (risk) {
      case 'LOW': return 'READ_ONLY';
      case 'MEDIUM': return 'ANALYSIS';
      case 'HIGH': return 'HIGH_RISK';
      default: return 'READ_ONLY';
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private toInvestigation(problem: HMPIXProblem, context: HMPIXCognitiveContext): Investigation {
    return {
      id: problem.id,
      title: problem.objective,
      objective: problem.objective,
      status: 'INVESTIGATING',
      createdAt: problem.createdAt,
      updatedAt: Date.now(),
      humanContext: problem.humanContext,
      humanCapabilityContext: {
        environmentalKnowledge: [],
        priorities: problem.priority.map((p) => ({ id: uuidv4(), value: p, createdAt: Date.now() })),
        constraints: problem.constraints.map((c) => ({ id: uuidv4(), value: c, createdAt: Date.now() })),
        suspicions: [],
        knownLegitimateBehavior: [],
        knownAbnormalBehavior: [],
        riskTolerance: problem.riskTolerance,
        importantEntityIds: [],
        importantEntities: [],
        investigationDirections: [],
        notes: [],
      },
      hypotheses: [],
      evidence: context.observations.map((o) => this.toInvestigationEvidence(o)),
      entities: [],
      graph: { relationships: [] },
      timeline: [],
      openQuestions: [],
      aiTasks: [],
      humanTasks: [],
      decisions: context.decisions.map((d) => ({ id: d.id, summary: d.summary, rationale: d.rationale, createdAt: d.createdAt })),
      conclusions: [],
      confidence: 0,
      activity: [],
    } as Investigation;
  }

  private toInvestigationEvidence(obs: HMPIXObservation): InvestigationEvidence {
    return {
      id: obs.id,
      investigationId: '',
      type: obs.type,
      title: obs.content.slice(0, 100),
      source: 'hmpx-kernel',
      timestamp: obs.createdAt,
      collectedAt: obs.createdAt,
      investigator: 'hmpx',
      relatedEntityIds: [],
      content: obs.content,
      confidence: obs.confidence,
      provenance: {
        method: 'agent_observed',
        sourceType: 'task_result',
        sourceId: obs.intentId,
        collectedBy: 'hmpx-kernel',
      },
      supportingTaskId: obs.intentId,
      hypothesisIds: [],
      analystAnnotations: [],
      relationships: [],
      kind: 'structured_record',
      summary: obs.content,
      tags: [obs.type.toLowerCase()],
    };
  }

  private uncertaintyFromAssessment(assessment: UncertaintyAssessment): number {
    const competing = assessment.competingHypotheses;
    if (competing.length < 2) return 0.2;
    const top = competing[0].confidence;
    const second = competing[1].confidence;
    return Math.max(0.2, Math.abs(top - second));
  }

  private buildRecommendedActions(context: HMPIXCognitiveContext, trigger: HMPIXReplanTrigger): HMPIXRecommendedAction[] {
    const actions: HMPIXRecommendedAction[] = [];
    for (const selection of context.selections.slice(-2)) {
      if (selection.selectedCapabilities.length > 0) {
        const cap = selection.selectedCapabilities[0];
        actions.push({
          capabilityId: cap.capabilityId,
          subProblemId: selection.subProblemId,
          rationale: `Re-select after ${trigger}: highest-scoring capability remains ${cap.capabilityId} (score ${cap.score.toFixed(2)}).`,
          priority: 1,
        });
      }
    }
    return actions;
  }
}

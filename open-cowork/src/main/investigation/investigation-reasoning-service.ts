import type {
  Investigation,
  InvestigationConclusion,
  InvestigationEvidence,
  InvestigationHypothesis,
} from '../../shared/cyber/investigation-types';
import { HypothesisService, type HypothesisAssessmentInput } from './hypothesis-service';
import { ConclusionService, type DeriveConclusionInput } from './conclusion-service';

export interface InvestigationReasoningSnapshot {
  supportedHypotheses: InvestigationHypothesis[];
  weakenedHypotheses: InvestigationHypothesis[];
  openHypotheses: InvestigationHypothesis[];
  linkedEvidence: InvestigationEvidence[];
  orphanEvidence: InvestigationEvidence[];
  latestConclusion: InvestigationConclusion | null;
}

export interface ReasoningSynthesisInput {
  assessments?: HypothesisAssessmentInput[];
  conclusion?: DeriveConclusionInput;
}

export interface ReasoningSynthesisResult {
  hypotheses: InvestigationHypothesis[];
  evidence: InvestigationEvidence[];
  conclusion?: InvestigationConclusion;
  snapshot: InvestigationReasoningSnapshot;
}

export class InvestigationReasoningService {
  constructor(
    private readonly hypothesisService = new HypothesisService(),
    private readonly conclusionService = new ConclusionService()
  ) {}

  summarize(investigation: Investigation): InvestigationReasoningSnapshot {
    const linkedEvidence = investigation.evidence.filter(
      (item) => item.hypothesisIds.length > 0 || item.relationships.some((relationship) => relationship.targetHypothesisId)
    );
    const orphanEvidence = investigation.evidence.filter(
      (item) => !linkedEvidence.some((linked) => linked.id === item.id)
    );
    return {
      supportedHypotheses: investigation.hypotheses.filter((item) => item.status === 'SUPPORTED'),
      weakenedHypotheses: investigation.hypotheses.filter((item) => item.status === 'WEAKENED'),
      openHypotheses: investigation.hypotheses.filter((item) => item.status === 'OPEN'),
      linkedEvidence,
      orphanEvidence,
      latestConclusion: investigation.conclusions[0] || null,
    };
  }

  synthesize(investigation: Investigation, input: ReasoningSynthesisInput = {}): ReasoningSynthesisResult {
    let nextInvestigation: Investigation = {
      ...investigation,
      hypotheses: [...investigation.hypotheses],
      evidence: [...investigation.evidence],
      conclusions: [...investigation.conclusions],
    };

    for (const assessment of input.assessments || []) {
      const result = this.hypothesisService.applyEvidenceAssessment(nextInvestigation, assessment);
      nextInvestigation = {
        ...nextInvestigation,
        hypotheses: result.hypotheses,
        evidence: result.evidence,
      };
    }

    let conclusion: InvestigationConclusion | undefined;
    if (input.conclusion) {
      const derived = this.conclusionService.deriveFromInvestigation(nextInvestigation, input.conclusion);
      nextInvestigation = {
        ...nextInvestigation,
        conclusions: derived.conclusions,
      };
      conclusion = derived.conclusion;
    }

    return {
      hypotheses: nextInvestigation.hypotheses,
      evidence: nextInvestigation.evidence,
      conclusion,
      snapshot: this.summarize(nextInvestigation),
    };
  }
}

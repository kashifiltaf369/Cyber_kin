import { v4 as uuidv4 } from 'uuid';
import type {
  Investigation,
  InvestigationConclusion,
  InvestigationHypothesis,
} from '../../shared/cyber/investigation-types';

export interface UpsertConclusionInput {
  summary: string;
  confidence?: number;
  rationale?: string;
  derivedFromHypothesisIds?: string[];
  derivedFromEvidenceIds?: string[];
}

export interface DeriveConclusionInput {
  summary?: string;
  rationale?: string;
  hypothesisIds?: string[];
  evidenceIds?: string[];
}

function clampConfidence(value: number | undefined): number {
  if (typeof value !== 'number' || Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function average(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export class ConclusionService {
  upsert(
    existing: InvestigationConclusion[],
    input: UpsertConclusionInput,
    now = Date.now()
  ): { conclusions: InvestigationConclusion[]; conclusion: InvestigationConclusion } {
    const current = existing[0];
    const conclusion: InvestigationConclusion = current
      ? {
          ...current,
          summary: input.summary,
          confidence: clampConfidence(input.confidence),
          rationale: input.rationale,
          derivedFromHypothesisIds: input.derivedFromHypothesisIds || current.derivedFromHypothesisIds || [],
          derivedFromEvidenceIds: input.derivedFromEvidenceIds || current.derivedFromEvidenceIds || [],
          updatedAt: now,
        }
      : {
          id: uuidv4(),
          summary: input.summary,
          confidence: clampConfidence(input.confidence),
          rationale: input.rationale,
          derivedFromHypothesisIds: input.derivedFromHypothesisIds || [],
          derivedFromEvidenceIds: input.derivedFromEvidenceIds || [],
          createdAt: now,
          updatedAt: now,
        };

    return {
      conclusion,
      conclusions: [conclusion, ...existing.slice(1)],
    };
  }

  deriveFromInvestigation(
    investigation: Investigation,
    input: DeriveConclusionInput = {},
    now = Date.now()
  ): { conclusions: InvestigationConclusion[]; conclusion: InvestigationConclusion } {
    const selectedHypotheses = investigation.hypotheses.filter(
      (item) =>
        (input.hypothesisIds?.length ? input.hypothesisIds.includes(item.id) : true) &&
        item.status !== 'REJECTED'
    );
    const supportingHypotheses = selectedHypotheses.filter((item) => item.status === 'SUPPORTED');
    const selectedEvidence = investigation.evidence.filter((item) =>
      input.evidenceIds?.length ? input.evidenceIds.includes(item.id) : supportingHypotheses.some((hypothesis) => item.hypothesisIds.includes(hypothesis.id))
    );

    const derivedHypothesisIds =
      input.hypothesisIds?.length
        ? input.hypothesisIds
        : supportingHypotheses.map((item) => item.id);
    const derivedEvidenceIds =
      input.evidenceIds?.length
        ? input.evidenceIds
        : selectedEvidence.map((item) => item.id);

    const hypothesisConfidence = average(supportingHypotheses.map((item) => item.confidence));
    const evidenceConfidence = average(selectedEvidence.map((item) => item.confidence));
    const confidence = clampConfidence(
      supportingHypotheses.length === 0 && selectedEvidence.length === 0
        ? 0
        : average([hypothesisConfidence, evidenceConfidence].filter((value) => value > 0))
    );

    const summary =
      input.summary ||
      buildDerivedSummary(supportingHypotheses, selectedEvidence, confidence);

    return this.upsert(
      investigation.conclusions,
      {
        summary,
        confidence,
        rationale: input.rationale,
        derivedFromHypothesisIds: derivedHypothesisIds,
        derivedFromEvidenceIds: derivedEvidenceIds,
      },
      now
    );
  }
}

function buildDerivedSummary(
  hypotheses: InvestigationHypothesis[],
  evidence: Investigation['evidence'],
  confidence: number
): string {
  if (hypotheses.length === 0 && evidence.length === 0) {
    return 'Insufficient evidence to derive a conclusion.';
  }
  const topHypothesis = hypotheses
    .slice()
    .sort((a, b) => b.confidence - a.confidence)[0];
  if (topHypothesis) {
    return `Current evidence supports ${topHypothesis.title} with ${Math.round(confidence * 100)}% confidence.`;
  }
  return `Current evidence indicates investigative findings with ${Math.round(confidence * 100)}% confidence.`;
}

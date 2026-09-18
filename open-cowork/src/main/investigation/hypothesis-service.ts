import { v4 as uuidv4 } from 'uuid';
import type {
  HypothesisConfidenceAssessment,
  Investigation,
  InvestigationEvidence,
  InvestigationHypothesis,
} from '../../shared/cyber/investigation-types';

export interface CreateHypothesisInput {
  title: string;
  statement: string;
  confidence?: number;
  assumptions?: string[];
  unresolvedQuestions?: string[];
  createdBy?: InvestigationHypothesis['createdBy'];
}

export interface HypothesisAssessmentInput {
  hypothesisId: string;
  evidenceId: string;
  relationship: 'SUPPORTS' | 'WEAKENS';
  rationale?: string;
  actor?: 'human' | 'agent' | 'system';
}

export interface CompareHypothesesResult {
  ranked: Array<{
    hypothesis: InvestigationHypothesis;
    netSupportScore: number;
    supportCount: number;
    contradictionCount: number;
    unresolvedQuestionCount: number;
    assumptionCount: number;
  }>;
  leadingHypothesisId: string | null;
}

export interface ChallengerAssessment {
  hypothesisId: string;
  contradictoryEvidence: InvestigationEvidence[];
  weakAssumptions: string[];
  alternativeExplanations: string[];
  falsificationQuestions: string[];
  missingEvidence: string[];
  summary: string;
}

function clampConfidence(value: number | undefined): number {
  if (typeof value !== 'number' || Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function toConfidenceAssessment(value: number): HypothesisConfidenceAssessment {
  if (value >= 0.75) return 'HIGH';
  if (value >= 0.4) return 'MEDIUM';
  return 'LOW';
}

function uniqueStrings(values: string[] | undefined): string[] {
  return [...new Set((values || []).map((item) => item.trim()).filter(Boolean))];
}

export class HypothesisService {
  create(input: CreateHypothesisInput, now = Date.now()): InvestigationHypothesis {
    const confidence = clampConfidence(input.confidence);
    return {
      id: uuidv4(),
      title: input.title,
      statement: input.statement,
      status: 'OPEN',
      confidence,
      confidenceAssessment: toConfidenceAssessment(confidence),
      supportingEvidenceIds: [],
      contradictingEvidenceIds: [],
      assumptions: uniqueStrings(input.assumptions),
      unresolvedQuestions: uniqueStrings(input.unresolvedQuestions),
      createdBy: input.createdBy || 'human',
      createdAt: now,
      updatedAt: now,
    };
  }

  normalize(hypothesis: InvestigationHypothesis): InvestigationHypothesis {
    const confidence = clampConfidence(hypothesis.confidence);
    return {
      ...hypothesis,
      status: hypothesis.status || 'OPEN',
      confidence,
      confidenceAssessment: hypothesis.confidenceAssessment || toConfidenceAssessment(confidence),
      supportingEvidenceIds: uniqueStrings(hypothesis.supportingEvidenceIds),
      contradictingEvidenceIds: uniqueStrings(hypothesis.contradictingEvidenceIds),
      assumptions: uniqueStrings(hypothesis.assumptions),
      unresolvedQuestions: uniqueStrings(hypothesis.unresolvedQuestions),
      createdBy: hypothesis.createdBy || 'human',
    };
  }

  update(
    hypotheses: InvestigationHypothesis[],
    hypothesisId: string,
    updates: Partial<
      Pick<
        InvestigationHypothesis,
        'title' | 'statement' | 'status' | 'confidence' | 'assumptions' | 'unresolvedQuestions'
      >
    >,
    now = Date.now()
  ): InvestigationHypothesis[] {
    return hypotheses.map((item) => {
      const normalized = this.normalize(item);
      if (normalized.id !== hypothesisId) return normalized;
      const confidence = updates.confidence !== undefined ? clampConfidence(updates.confidence) : normalized.confidence;
      return {
        ...normalized,
        ...(updates.title !== undefined ? { title: updates.title } : {}),
        ...(updates.statement !== undefined ? { statement: updates.statement } : {}),
        ...(updates.status !== undefined ? { status: updates.status } : {}),
        ...(updates.assumptions !== undefined ? { assumptions: uniqueStrings(updates.assumptions) } : {}),
        ...(updates.unresolvedQuestions !== undefined
          ? { unresolvedQuestions: uniqueStrings(updates.unresolvedQuestions) }
          : {}),
        confidence,
        confidenceAssessment: toConfidenceAssessment(confidence),
        updatedAt: now,
      };
    });
  }

  updateConfidence(
    hypotheses: InvestigationHypothesis[],
    hypothesisId: string,
    confidence: number,
    now = Date.now()
  ): InvestigationHypothesis[] {
    return this.update(hypotheses, hypothesisId, { confidence }, now);
  }

  reject(hypotheses: InvestigationHypothesis[], hypothesisId: string, now = Date.now()): InvestigationHypothesis[] {
    return this.update(hypotheses, hypothesisId, { status: 'REJECTED', confidence: 0.05 }, now);
  }

  promote(hypotheses: InvestigationHypothesis[], hypothesisId: string, now = Date.now()): InvestigationHypothesis[] {
    const current = hypotheses.find((item) => item.id === hypothesisId);
    if (!current) {
      throw new Error(`Hypothesis not found: ${hypothesisId}`);
    }
    return this.update(
      hypotheses,
      hypothesisId,
      { status: 'PROMOTED', confidence: Math.max(current.confidence, 0.75) },
      now
    );
  }

  compare(hypotheses: InvestigationHypothesis[]): CompareHypothesesResult {
    const ranked = hypotheses
      .map((item) => {
        const hypothesis = this.normalize(item);
        const supportCount = hypothesis.supportingEvidenceIds.length;
        const contradictionCount = hypothesis.contradictingEvidenceIds.length;
        const unresolvedQuestionCount = hypothesis.unresolvedQuestions.length;
        const assumptionCount = hypothesis.assumptions.length;
        const netSupportScore =
          hypothesis.confidence + supportCount * 0.1 - contradictionCount * 0.12 - unresolvedQuestionCount * 0.03;
        return {
          hypothesis,
          netSupportScore,
          supportCount,
          contradictionCount,
          unresolvedQuestionCount,
          assumptionCount,
        };
      })
      .sort((a, b) => {
        if (b.netSupportScore !== a.netSupportScore) return b.netSupportScore - a.netSupportScore;
        if (b.supportCount !== a.supportCount) return b.supportCount - a.supportCount;
        return a.hypothesis.id.localeCompare(b.hypothesis.id);
      });

    return {
      ranked,
      leadingHypothesisId: ranked[0]?.hypothesis.id || null,
    };
  }

  challenge(investigation: Investigation, hypothesisId: string): ChallengerAssessment {
    const hypothesis = investigation.hypotheses.find((item) => item.id === hypothesisId);
    if (!hypothesis) {
      throw new Error(`Hypothesis not found: ${hypothesisId}`);
    }
    const normalized = this.normalize(hypothesis);
    const contradictoryEvidence = investigation.evidence.filter((item) =>
      normalized.contradictingEvidenceIds.includes(item.id)
    );
    const weakAssumptions = normalized.assumptions.filter((item) => item.length < 20 || /assum|likely|maybe/i.test(item));
    const alternativeExplanations = [
      ...investigation.humanCapabilityContext.knownLegitimateBehavior.map(
        (item) => `Known legitimate behavior could explain this: ${item.value}`
      ),
      ...(normalized.status === 'SUPPORTED' ? ['Supporting evidence may still fit a benign explanation.'] : []),
    ].slice(0, 5);
    const falsificationQuestions = [
      `What direct evidence would show that "${normalized.statement}" is false?`,
      'Which observation would most strongly contradict the current explanation?',
      'Can the observed behavior be reproduced by a known legitimate workflow?',
    ];
    const missingEvidence = [
      ...(normalized.supportingEvidenceIds.length === 0 ? ['No direct supporting evidence has been linked yet.'] : []),
      ...(normalized.contradictingEvidenceIds.length === 0 ? ['No contradictory evidence has been collected or linked yet.'] : []),
      ...(normalized.unresolvedQuestions.length > 0
        ? normalized.unresolvedQuestions.map((item) => `Unresolved question: ${item}`)
        : ['No explicit falsification-oriented questions have been captured.']),
    ];

    return {
      hypothesisId: normalized.id,
      contradictoryEvidence,
      weakAssumptions,
      alternativeExplanations,
      falsificationQuestions,
      missingEvidence,
      summary:
        `Challenger review for ${normalized.title}: ` +
        `${contradictoryEvidence.length} contradictory evidence item(s), ` +
        `${weakAssumptions.length} weak assumption(s), ` +
        `${missingEvidence.length} missing-evidence signal(s).`,
    };
  }

  applyEvidenceAssessment(
    investigation: Investigation,
    input: HypothesisAssessmentInput,
    now = Date.now()
  ): {
    hypotheses: InvestigationHypothesis[];
    evidence: InvestigationEvidence[];
    hypothesis: InvestigationHypothesis | null;
  } {
    const currentHypothesis = investigation.hypotheses.find((item) => item.id === input.hypothesisId) || null;
    if (!currentHypothesis) {
      throw new Error(`Hypothesis not found: ${input.hypothesisId}`);
    }
    const evidenceExists = investigation.evidence.some((item) => item.id === input.evidenceId);
    if (!evidenceExists) {
      throw new Error(`Evidence not found: ${input.evidenceId}`);
    }

    const normalized = this.normalize(currentHypothesis);
    const nextStatus = input.relationship === 'SUPPORTS'
      ? normalized.status === 'REJECTED' ? 'WEAKENED' : 'SUPPORTED'
      : normalized.status === 'PROMOTED' ? 'WEAKENED' : 'WEAKENED';
    const delta = input.relationship === 'SUPPORTS' ? 0.15 : -0.15;
    const nextConfidence = clampConfidence(normalized.confidence + delta);

    const hypotheses = investigation.hypotheses.map((item) => {
      const hypothesis = this.normalize(item);
      if (hypothesis.id !== input.hypothesisId) return hypothesis;
      return {
        ...hypothesis,
        status: nextStatus,
        confidence: nextConfidence,
        confidenceAssessment: toConfidenceAssessment(nextConfidence),
        supportingEvidenceIds:
          input.relationship === 'SUPPORTS'
            ? uniqueStrings([...hypothesis.supportingEvidenceIds, input.evidenceId])
            : hypothesis.supportingEvidenceIds,
        contradictingEvidenceIds:
          input.relationship === 'WEAKENS'
            ? uniqueStrings([...hypothesis.contradictingEvidenceIds, input.evidenceId])
            : hypothesis.contradictingEvidenceIds,
        updatedAt: now,
      };
    });

    const evidence = investigation.evidence.map((item) =>
      item.id === input.evidenceId
        ? {
            ...item,
            hypothesisIds: item.hypothesisIds.includes(input.hypothesisId)
              ? item.hypothesisIds
              : [...item.hypothesisIds, input.hypothesisId],
            relationships: [
              ...item.relationships,
              {
                id: uuidv4(),
                type: input.relationship,
                targetHypothesisId: input.hypothesisId,
                createdAt: now,
                createdBy: input.actor || 'agent',
                rationale: input.rationale,
              },
            ],
          }
        : item
    );

    return {
      hypotheses,
      evidence,
      hypothesis: hypotheses.find((item) => item.id === input.hypothesisId) || null,
    };
  }
}

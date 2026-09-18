import { ChallengerAgent } from './challenger-agent';
import { HypothesisService, type ChallengerAssessment } from './hypothesis-service';
import type {
  Investigation,
  InvestigationConclusion,
  InvestigationDecision,
  InvestigationEntity,
  InvestigationEvidence,
  InvestigationHypothesis,
  InvestigationTimelineEntry,
} from '../../shared/cyber/investigation-types';

export type ReportOrigin =
  | 'observed_evidence'
  | 'human_decision'
  | 'human_context'
  | 'ai_assessment'
  | 'ai_challenger'
  | 'derived_conclusion';

export interface ReportEvidenceRef {
  evidenceId: string;
  evidenceShortId: string;
  title: string;
  kind: string;
  type: InvestigationEvidence['type'];
  confidence: number;
  origin: ReportOrigin;
  investigator: string;
  collectedAt: number;
  source: string;
  provenance: InvestigationEvidence['provenance'];
  summary: string;
  hypothesisIds: string[];
  tags: string[];
}

export interface ReportHypothesisSection {
  hypothesis: InvestigationHypothesis;
  origin: ReportOrigin;
  supportingEvidence: ReportEvidenceRef[];
  contradictingEvidence: ReportEvidenceRef[];
  unresolvedQuestions: string[];
  assumptions: string[];
  challenger: ChallengerAssessment | null;
}

export interface InvestigationReport {
  investigationId: string;
  title: string;
  objective: string;
  status: Investigation['status'];
  createdAt: number;
  updatedAt: number;
  generatedAt: number;
  executiveSummary: {
    text: string;
    origin: ReportOrigin;
    supportingEvidenceIds: string[];
    supportingHypothesisIds: string[];
    confidence: number;
  };
  humanContext: {
    rawNotes: string;
    priorities: string[];
    constraints: string[];
    suspicions: string[];
    knownLegitimateBehavior: string[];
    knownAbnormalBehavior: string[];
    riskTolerance: string;
    importantEntities: InvestigationEntity[];
    decisions: InvestigationDecision[];
    origin: ReportOrigin;
  };
  timeline: InvestigationTimelineEntry[];
  keyEntities: Array<{
    entity: InvestigationEntity;
    linkedEvidenceCount: number;
    origin: ReportOrigin;
  }>;
  evidence: ReportEvidenceRef[];
  hypotheses: ReportHypothesisSection[];
  finalConclusion: {
    conclusion: InvestigationConclusion | null;
    origin: ReportOrigin;
    supportingEvidenceIds: string[];
    supportingHypothesisIds: string[];
    confidence: number;
  };
  challengerFindings: ChallengerAssessment[];
  unresolvedQuestions: string[];
  actionsTaken: Array<{
    taskId: string;
    title: string;
    description: string;
    status: string;
    type: 'AI' | 'HUMAN';
    origin: ReportOrigin;
    createdAt: number;
    updatedAt: number;
    owner?: string;
    supportingEvidenceIds: string[];
  }>;
  confidenceAssessment: {
    overall: number;
    assessment: 'LOW' | 'MEDIUM' | 'HIGH';
    origin: ReportOrigin;
    supportingEvidenceIds: string[];
    supportingHypothesisIds: string[];
    caveats: string[];
  };
  recommendations: Array<{
    text: string;
    origin: ReportOrigin;
    rationale: string;
    linkedHypothesisIds: string[];
    linkedEvidenceIds: string[];
  }>;
}

function shortId(id: string): string {
  const trimmed = id.replace(/-/g, '');
  return trimmed.slice(0, 8).toUpperCase();
}

function originForEvidence(evidence: InvestigationEvidence): ReportOrigin {
  if (evidence.provenance?.method === 'human_reported') {
    return 'human_decision';
  }
  if (evidence.type === 'CONCLUSION') {
    return 'derived_conclusion';
  }
  return 'observed_evidence';
}

function originForHypothesis(hypothesis: InvestigationHypothesis): ReportOrigin {
  if (hypothesis.createdBy === 'human') {
    return 'human_decision';
  }
  return 'ai_assessment';
}

function confidenceBucket(value: number): 'LOW' | 'MEDIUM' | 'HIGH' {
  if (value >= 0.75) return 'HIGH';
  if (value >= 0.4) return 'MEDIUM';
  return 'LOW';
}

function toEvidenceRef(evidence: InvestigationEvidence): ReportEvidenceRef {
  return {
    evidenceId: evidence.id,
    evidenceShortId: shortId(evidence.id),
    title: evidence.title,
    kind: evidence.kind,
    type: evidence.type,
    confidence: evidence.confidence,
    origin: originForEvidence(evidence),
    investigator: evidence.investigator,
    collectedAt: evidence.collectedAt,
    source: evidence.source,
    provenance: evidence.provenance,
    summary: evidence.summary,
    hypothesisIds: [...evidence.hypothesisIds],
    tags: [...evidence.tags],
  };
}

export class InvestigationReportService {
  constructor(
    private readonly challengerAgent: ChallengerAgent = new ChallengerAgent(new HypothesisService())
  ) {}

  buildReport(investigation: Investigation, now: number = Date.now()): InvestigationReport {
    const evidenceRefs = investigation.evidence.map(toEvidenceRef);
    const evidenceById = new Map(evidenceRefs.map((ref) => [ref.evidenceId, ref]));

    const hypotheses: ReportHypothesisSection[] = investigation.hypotheses.map((hypothesis) => {
      const supporting = hypothesis.supportingEvidenceIds
        .map((id) => evidenceById.get(id))
        .filter((ref): ref is ReportEvidenceRef => Boolean(ref));
      const contradicting = hypothesis.contradictingEvidenceIds
        .map((id) => evidenceById.get(id))
        .filter((ref): ref is ReportEvidenceRef => Boolean(ref));
      return {
        hypothesis,
        origin: originForHypothesis(hypothesis),
        supportingEvidence: supporting,
        contradictingEvidence: contradicting,
        unresolvedQuestions: [...hypothesis.unresolvedQuestions],
        assumptions: [...hypothesis.assumptions],
        challenger: null,
      };
    });

    const challengerResult = this.challengerAgent.reviewInvestigation(investigation);
    const challengerByHypothesis = new Map<string, ChallengerAssessment>();
    for (const review of challengerResult.reviews) {
      challengerByHypothesis.set(review.hypothesisId, review);
    }
    for (const section of hypotheses) {
      section.challenger = challengerByHypothesis.get(section.hypothesis.id) || null;
    }

    const finalConclusion: InvestigationConclusion | null = investigation.conclusions[0] || null;

    const supportingHypothesisIds = hypotheses
      .filter((section) => section.hypothesis.status === 'SUPPORTED' || section.hypothesis.status === 'PROMOTED')
      .map((section) => section.hypothesis.id);
    const supportingEvidenceIds = finalConclusion?.derivedFromEvidenceIds || [];

    const executiveSummary = this.buildExecutiveSummary(
      investigation,
      finalConclusion,
      supportingHypothesisIds,
      evidenceRefs,
      hypotheses
    );

    const actionsTaken = [
      ...investigation.aiTasks.map((task) => ({
        taskId: task.id,
        title: task.title,
        description: task.description,
        status: task.status,
        type: 'AI' as const,
        origin: 'ai_assessment' as ReportOrigin,
        createdAt: task.createdAt,
        updatedAt: task.updatedAt,
        owner: task.owner,
        supportingEvidenceIds: evidenceRefs
          .filter((ref) => {
            const evidence = investigation.evidence.find((item) => item.id === ref.evidenceId);
            return evidence?.supportingTaskId === task.id;
          })
          .map((ref) => ref.evidenceId),
      })),
      ...investigation.humanTasks.map((task) => ({
        taskId: task.id,
        title: task.title,
        description: task.description,
        status: task.status,
        type: 'HUMAN' as const,
        origin: 'human_decision' as ReportOrigin,
        createdAt: task.createdAt,
        updatedAt: task.updatedAt,
        owner: task.owner,
        supportingEvidenceIds: [] as string[],
      })),
    ].sort((a, b) => a.createdAt - b.createdAt);

    const keyEntities: InvestigationReport['keyEntities'] = investigation.entities.map((entity) => {
      const linkedEvidenceCount = evidenceRefs.filter(
        (ref) =>
          investigation.evidence
            .find((item) => item.id === ref.evidenceId)
            ?.relatedEntityIds.includes(entity.id) || false
      ).length;
      return {
        entity,
        linkedEvidenceCount,
        origin: 'observed_evidence' as ReportOrigin,
      };
    });

    const unresolvedQuestions = Array.from(
      new Set([
        ...investigation.openQuestions,
        ...hypotheses.flatMap((section) => section.unresolvedQuestions),
      ])
    );

    const overallConfidence = clampConfidence(finalConclusion?.confidence ?? 0);
    const caveats: string[] = [];
    if (evidenceRefs.length === 0) caveats.push('No observed evidence has been recorded yet.');
    if (hypotheses.length === 0) caveats.push('No hypotheses have been formulated.');
    if (challengerResult.reviews.some((review) => review.contradictoryEvidence.length > 0)) {
      caveats.push('The Challenger identified contradictory evidence on at least one hypothesis.');
    }
    if (finalConclusion && supportingEvidenceIds.length === 0) {
      caveats.push('The current conclusion is not linked to any evidence yet.');
    }

    const recommendations = this.buildRecommendations(investigation, hypotheses, challengerResult.reviews, evidenceRefs);

    return {
      investigationId: investigation.id,
      title: investigation.title,
      objective: investigation.objective,
      status: investigation.status,
      createdAt: investigation.createdAt,
      updatedAt: investigation.updatedAt,
      generatedAt: now,
      executiveSummary,
      humanContext: {
        rawNotes: investigation.humanContext,
        priorities: investigation.humanCapabilityContext.priorities.map((entry) => entry.value),
        constraints: investigation.humanCapabilityContext.constraints.map((entry) => entry.value),
        suspicions: investigation.humanCapabilityContext.suspicions.map((entry) => entry.value),
        knownLegitimateBehavior: investigation.humanCapabilityContext.knownLegitimateBehavior.map((entry) => entry.value),
        knownAbnormalBehavior: investigation.humanCapabilityContext.knownAbnormalBehavior.map((entry) => entry.value),
        riskTolerance: investigation.humanCapabilityContext.riskTolerance,
        importantEntities: investigation.humanCapabilityContext.importantEntities,
        decisions: investigation.decisions,
        origin: 'human_context',
      },
      timeline: investigation.timeline,
      keyEntities,
      evidence: evidenceRefs,
      hypotheses,
      finalConclusion: {
        conclusion: finalConclusion,
        origin: finalConclusion ? 'derived_conclusion' : 'ai_assessment',
        supportingEvidenceIds,
        supportingHypothesisIds,
        confidence: overallConfidence,
      },
      challengerFindings: challengerResult.reviews,
      unresolvedQuestions,
      actionsTaken,
      confidenceAssessment: {
        overall: overallConfidence,
        assessment: confidenceBucket(overallConfidence),
        origin: 'ai_assessment',
        supportingEvidenceIds,
        supportingHypothesisIds,
        caveats,
      },
      recommendations,
    };
  }

  private buildExecutiveSummary(
    investigation: Investigation,
    finalConclusion: InvestigationConclusion | null,
    supportingHypothesisIds: string[],
    evidenceRefs: ReportEvidenceRef[],
    hypotheses: ReportHypothesisSection[]
  ): InvestigationReport['executiveSummary'] {
    const supportingEvidenceIds = finalConclusion?.derivedFromEvidenceIds || [];
    const supportingRefs = supportingEvidenceIds
      .map((id) => evidenceRefs.find((ref) => ref.evidenceId === id))
      .filter((ref): ref is ReportEvidenceRef => Boolean(ref));
    const confidence = clampConfidence(finalConclusion?.confidence ?? 0);
    const assessment: 'OBSERVED' | 'INFERRED' | 'CONCLUDED' | 'PENDING' =
      evidenceRefs.length === 0
        ? 'PENDING'
        : finalConclusion
        ? 'CONCLUDED'
        : hypotheses.length > 0
        ? 'INFERRED'
        : 'OBSERVED';

    const summaryParts: string[] = [];
    summaryParts.push(`Investigation "${investigation.title}" (status: ${investigation.status}).`);
    summaryParts.push(`Objective: ${investigation.objective}`);
    if (finalConclusion) {
      summaryParts.push(`Conclusion: ${finalConclusion.summary}`);
      summaryParts.push(
        `This conclusion is derived from ${supportingHypothesisIds.length} hypothesis(es) and ${supportingRefs.length} evidence item(s) at ${Math.round(confidence * 100)}% confidence.`
      );
    } else if (hypotheses.length > 0) {
      const leading = hypotheses
        .slice()
        .sort((a, b) => b.hypothesis.confidence - a.hypothesis.confidence)[0];
      summaryParts.push(
        `No conclusion has been finalized. Leading hypothesis: "${leading.hypothesis.title}" (${Math.round(
          leading.hypothesis.confidence * 100
        )}% confidence).`
      );
    } else if (evidenceRefs.length > 0) {
      summaryParts.push(
        `${evidenceRefs.length} observed evidence item(s) collected; no hypothesis or conclusion has been formulated yet.`
      );
    } else {
      summaryParts.push('No observed evidence, hypotheses, or conclusions have been recorded.');
    }
    summaryParts.push(`Assessment stage: ${assessment}.`);

    return {
      text: summaryParts.join(' '),
      origin: finalConclusion ? 'derived_conclusion' : 'ai_assessment',
      supportingEvidenceIds,
      supportingHypothesisIds,
      confidence,
    };
  }

  private buildRecommendations(
    investigation: Investigation,
    hypotheses: ReportHypothesisSection[],
    challengerReviews: ChallengerAssessment[],
    evidenceRefs: ReportEvidenceRef[]
  ): InvestigationReport['recommendations'] {
    const recs: InvestigationReport['recommendations'] = [];

    const openHypotheses = hypotheses.filter((section) => section.hypothesis.status === 'OPEN');
    for (const section of openHypotheses) {
      if (section.supportingEvidence.length === 0 && section.contradictingEvidence.length === 0) {
        recs.push({
          text: `Collect direct evidence to support or refute "${section.hypothesis.title}".`,
          origin: 'ai_assessment',
          rationale: 'Hypothesis currently has no linked evidence and cannot be evaluated.',
          linkedHypothesisIds: [section.hypothesis.id],
          linkedEvidenceIds: [],
        });
      }
    }

    const unresolved = new Set(investigation.openQuestions);
    for (const question of unresolved) {
      recs.push({
        text: `Resolve open question: ${question}`,
        origin: 'human_decision',
        rationale: 'Open questions were recorded by the analyst and should be addressed before conclusion.',
        linkedHypothesisIds: [],
        linkedEvidenceIds: [],
      });
    }

    for (const review of challengerReviews) {
      if (review.missingEvidence.length > 0) {
        const hypothesis = hypotheses.find((section) => section.hypothesis.id === review.hypothesisId);
        recs.push({
          text: `Challenger recommends collecting: ${review.missingEvidence[0]}`,
          origin: 'ai_challenger',
          rationale: review.summary,
          linkedHypothesisIds: hypothesis ? [hypothesis.hypothesis.id] : [],
          linkedEvidenceIds: review.contradictoryEvidence.map((evidence) => evidence.id),
        });
      }
      if (review.alternativeExplanations.length > 0) {
        recs.push({
          text: `Investigate alternative explanation: ${review.alternativeExplanations[0]}`,
          origin: 'ai_challenger',
          rationale: review.summary,
          linkedHypothesisIds: [review.hypothesisId],
          linkedEvidenceIds: [],
        });
      }
    }

    if (evidenceRefs.length > 0 && investigation.conclusions.length === 0 && hypotheses.length > 0) {
      const leading = hypotheses
        .slice()
        .sort((a, b) => b.hypothesis.confidence - a.hypothesis.confidence)[0];
      recs.push({
        text: `Promote or reject the leading hypothesis "${leading.hypothesis.title}" once evidence is stable.`,
        origin: 'ai_assessment',
        rationale:
          leading.hypothesis.confidence >= 0.75
            ? 'Leading hypothesis is at HIGH confidence and is a candidate for promotion.'
            : 'Leading hypothesis has not yet reached HIGH confidence; continue gathering evidence.',
        linkedHypothesisIds: [leading.hypothesis.id],
        linkedEvidenceIds: leading.supportingEvidence.map((ref) => ref.evidenceId),
      });
    }

    if (recs.length === 0) {
      recs.push({
        text: 'Continue gathering evidence and Challenger reviews to strengthen the investigation.',
        origin: 'ai_assessment',
        rationale: 'No blocking gaps identified.',
        linkedHypothesisIds: [],
        linkedEvidenceIds: [],
      });
    }

    return recs;
  }
}

function clampConfidence(value: number): number {
  if (Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

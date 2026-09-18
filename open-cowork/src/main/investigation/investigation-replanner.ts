import type { Investigation, InvestigationHypothesis } from '../../shared/cyber/investigation-types';
import {
  AgentCapabilityRegistry,
  InvestigationPlanner,
  type InvestigationAgentRole,
  type InvestigationPlan,
  type PlannedInvestigationTask,
} from './parallel-investigation-engine';
import { HypothesisService } from './hypothesis-service';

export interface UncertaintyAssessment {
  investigationId: string;
  generatedAt: number;
  known: string[];
  uncertain: string[];
  competingHypotheses: Array<{
    hypothesisId: string;
    title: string;
    status: InvestigationHypothesis['status'];
    confidence: number;
    confidenceAssessment: InvestigationHypothesis['confidenceAssessment'];
    supportingEvidenceCount: number;
    contradictingEvidenceCount: number;
    unresolvedQuestionCount: number;
  }>;
  missingEvidence: string[];
  contradictoryEvidence: string[];
  humanPriorities: string[];
  risk: {
    tolerance: Investigation['humanCapabilityContext']['riskTolerance'];
    requiresChallenge: boolean;
  };
  availableCapabilities: InvestigationAgentRole[];
  summary: string;
}

export interface NextBestWorkRecommendation {
  rationale: string;
  uncertaintyReductionGoal: string;
  recommendedTasks: PlannedInvestigationTask[];
}

export class NextBestWorkSelector {
  select(
    _investigation: Investigation,
    assessment: UncertaintyAssessment,
    roles: InvestigationAgentRole[]
  ): NextBestWorkRecommendation {
    const recommendedTasks: PlannedInvestigationTask[] = [];
    const topPriority = assessment.humanPriorities[0];
    const firstCompetingPair = assessment.competingHypotheses.slice(0, 2);
    const hasCompeting = firstCompetingPair.length >= 2;

    if (hasCompeting) {
      const [a, b] = firstCompetingPair;
      const prompt = `Current evidence does not clearly distinguish between hypothesis A (${a.title}) and hypothesis B (${b.title}). Determine the next observation most likely to reduce uncertainty.`;
      if (roles.includes('Historical Investigator')) {
        recommendedTasks.push(createRecommendedTask({
          title: 'Validate normality against historical behavior',
          description:
            `${prompt} Determine whether a similar pattern is normal in historical records. ` +
            `Example target: determine whether a key entity normally authenticates from a given host.`,
          role: 'Historical Investigator',
          kind: 'research',
          mergeStrategy: 'append_notes',
        }));
      } else if (roles.includes('Identity Investigator')) {
        recommendedTasks.push(createRecommendedTask({
          title: 'Distinguish competing identity explanations',
          description:
            `${prompt} Focus on authentication evidence that can separate benign administration from credential misuse.`,
          role: 'Identity Investigator',
          kind: 'investigative',
          mergeStrategy: 'append_evidence',
        }));
      }
    }

    for (const missing of assessment.missingEvidence.slice(0, 2)) {
      if (/authenticat|account|mfa|login|tenant/i.test(missing) && roles.includes('Identity Investigator')) {
        recommendedTasks.push(createRecommendedTask({
          title: 'Resolve identity uncertainty',
          description: `${missing} ${topPriority ? `Prioritize: ${topPriority}.` : ''}`,
          role: 'Identity Investigator',
          kind: 'investigative',
          mergeStrategy: 'append_evidence',
        }));
        continue;
      }
      if (/host|process|powershell|execution|endpoint/i.test(missing) && roles.includes('Endpoint Investigator')) {
        recommendedTasks.push(createRecommendedTask({
          title: 'Resolve endpoint uncertainty',
          description: `${missing} ${topPriority ? `Prioritize: ${topPriority}.` : ''}`,
          role: 'Endpoint Investigator',
          kind: 'investigative',
          mergeStrategy: 'append_evidence',
        }));
        continue;
      }
      if (/network|dns|ip|domain|traffic|lateral/i.test(missing) && roles.includes('Network Investigator')) {
        recommendedTasks.push(createRecommendedTask({
          title: 'Resolve network uncertainty',
          description: `${missing} ${topPriority ? `Prioritize: ${topPriority}.` : ''}`,
          role: 'Network Investigator',
          kind: 'investigative',
          mergeStrategy: 'append_evidence',
        }));
      }
    }

    if (assessment.risk.requiresChallenge && roles.includes('Challenger')) {
      recommendedTasks.push(createRecommendedTask({
        title: 'Challenge unresolved assumptions',
        description:
          'Review contradictory evidence, weak assumptions, and missing falsification evidence before escalating confidence.',
        role: 'Challenger',
        kind: 'challenge',
        canRunConcurrently: false,
        mergeStrategy: 'append_questions',
      }));
    }

    const deduped = dedupeTasks(recommendedTasks);
    return {
      rationale: assessment.summary,
      uncertaintyReductionGoal:
        hasCompeting
          ? `Reduce uncertainty between ${firstCompetingPair[0].title} and ${firstCompetingPair[1].title}.`
          : 'Reduce the highest-value remaining investigative uncertainty.',
      recommendedTasks: deduped,
    };
  }
}

export class InvestigationReplanner {
  constructor(
    private readonly capabilities = new AgentCapabilityRegistry(),
    private readonly planner = new InvestigationPlanner(capabilities),
    private readonly hypothesisService = new HypothesisService(),
    private readonly nextBestWorkSelector = new NextBestWorkSelector()
  ) {}

  assessUncertainty(investigation: Investigation): UncertaintyAssessment {
    const comparison = this.hypothesisService.compare(investigation.hypotheses);
    const roles = this.capabilities.selectRolesForInvestigation(investigation);
    const challengerReviews = investigation.hypotheses.map((item) => this.hypothesisService.challenge(investigation, item.id));

    const known = [
      ...investigation.evidence.slice(0, 5).map((item) => `${item.type}: ${item.summary || item.title}`),
      ...comparison.ranked
        .filter((item) => item.supportCount > 0 || item.contradictionCount > 0)
        .slice(0, 3)
        .map(
          (item) =>
            `Hypothesis ${item.hypothesis.title}: ${item.supportCount} supporting vs ${item.contradictionCount} contradicting evidence item(s)`
        ),
    ];

    const uncertain = [
      ...comparison.ranked
        .filter((item) => item.unresolvedQuestionCount > 0 || Math.abs(item.netSupportScore - (comparison.ranked[0]?.netSupportScore || 0)) < 0.12)
        .map((item) => `Uncertainty remains around hypothesis: ${item.hypothesis.title}`),
      ...investigation.openQuestions.map((item) => `Open question: ${item}`),
    ];

    const missingEvidence = challengerReviews.flatMap((item) => item.missingEvidence);
    const contradictoryEvidence = challengerReviews.flatMap((item) =>
      item.contradictoryEvidence.map((evidence) => `${item.hypothesisId}: ${evidence.title}`)
    );
    const humanPriorities = investigation.humanCapabilityContext.priorities.map((item) => item.value);
    const competingHypotheses = comparison.ranked.map((item) => ({
      hypothesisId: item.hypothesis.id,
      title: item.hypothesis.title,
      status: item.hypothesis.status,
      confidence: item.hypothesis.confidence,
      confidenceAssessment: item.hypothesis.confidenceAssessment,
      supportingEvidenceCount: item.supportCount,
      contradictingEvidenceCount: item.contradictionCount,
      unresolvedQuestionCount: item.unresolvedQuestionCount,
    }));

    return {
      investigationId: investigation.id,
      generatedAt: Date.now(),
      known,
      uncertain,
      competingHypotheses,
      missingEvidence,
      contradictoryEvidence,
      humanPriorities,
      risk: {
        tolerance: investigation.humanCapabilityContext.riskTolerance,
        requiresChallenge:
          investigation.humanCapabilityContext.riskTolerance === 'LOW' || contradictoryEvidence.length > 0,
      },
      availableCapabilities: roles,
      summary: buildAssessmentSummary(competingHypotheses, contradictoryEvidence, missingEvidence),
    };
  }

  createReplan(investigation: Investigation): InvestigationPlan & {
    uncertainty: UncertaintyAssessment;
    nextBestWork: NextBestWorkRecommendation;
  } {
    const basePlan = this.planner.createPlan(investigation);
    const uncertainty = this.assessUncertainty(investigation);
    const nextBestWork = this.nextBestWorkSelector.select(
      investigation,
      uncertainty,
      uncertainty.availableCapabilities
    );

    const combinedTasks = dedupeTasks([...nextBestWork.recommendedTasks, ...basePlan.tasks]);
    return {
      ...basePlan,
      summary: `${basePlan.summary} Replanning focus: ${nextBestWork.uncertaintyReductionGoal}`,
      tasks: combinedTasks,
      uncertainty,
      nextBestWork,
    };
  }
}

function createRecommendedTask(input: {
  title: string;
  description: string;
  role: InvestigationAgentRole;
  kind: PlannedInvestigationTask['kind'];
  dependsOn?: string[];
  canRunConcurrently?: boolean;
  mergeStrategy: PlannedInvestigationTask['mergeStrategy'];
}): PlannedInvestigationTask {
  return {
    id: `replan-${Math.random().toString(36).slice(2, 10)}`,
    title: input.title,
    description: input.description,
    role: input.role,
    kind: input.kind,
    dependsOn: input.dependsOn || [],
    canRunConcurrently: input.canRunConcurrently ?? true,
    mergeStrategy: input.mergeStrategy,
  };
}

function dedupeTasks(tasks: PlannedInvestigationTask[]): PlannedInvestigationTask[] {
  const seen = new Set<string>();
  const result: PlannedInvestigationTask[] = [];
  for (const task of tasks) {
    const key = `${task.role}|${task.title}|${task.description}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(task);
  }
  return result;
}

function buildAssessmentSummary(
  competingHypotheses: UncertaintyAssessment['competingHypotheses'],
  contradictoryEvidence: string[],
  missingEvidence: string[]
): string {
  if (competingHypotheses.length >= 2) {
    return `Current evidence does not fully distinguish between ${competingHypotheses[0].title} and ${competingHypotheses[1].title}. ${contradictoryEvidence.length} contradictory evidence signal(s) and ${missingEvidence.length} missing-evidence signal(s) remain.`;
  }
  return `Investigation uncertainty review found ${contradictoryEvidence.length} contradictory evidence signal(s) and ${missingEvidence.length} missing-evidence signal(s).`;
}

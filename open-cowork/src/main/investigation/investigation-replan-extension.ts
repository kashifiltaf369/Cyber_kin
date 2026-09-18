import { Type } from '@sinclair/typebox';
import type { ExtensionContext } from '@mariozechner/pi-coding-agent';
import type {
  AgentRuntimeCustomTool,
  AgentRuntimeExtension,
  BeforeSessionRunContext,
  BeforeSessionRunResult,
} from '../extensions/agent-runtime-extension';
import type { InvestigationService } from './investigation-service';
import { InvestigationReplanner } from './investigation-replanner';

function toolTextResult(text: string, details?: unknown) {
  return {
    content: [{ type: 'text' as const, text }],
    details,
  };
}

function buildPromptPrefix(): string {
  return [
    '<investigation_replan_guidance>',
    'Use replanning tools to inspect investigation uncertainty and recommended next-best work after evidence changes.',
    'Treat replanning output as advisory within a human-started investigation. Do not assume recommended tasks are already approved or executed.',
    'Prefer the uncertainty assessment when deciding what evidence would best distinguish competing hypotheses.',
    '</investigation_replan_guidance>',
  ].join('\n');
}

function createReplanQueryTool(
  investigationService: InvestigationService,
  sessionLookup: (sessionId: string) => string | null,
  replanner: InvestigationReplanner
): AgentRuntimeCustomTool {
  return {
    name: 'investigation_replan_query',
    label: 'investigation_replan_query',
    description:
      'Inspect the latest dynamic investigation replanning view for the linked investigation. Supports uncertainty assessment, cached recommendations, next-best-work recommendations, and full replan output.',
    parameters: Type.Object({
      queryType: Type.String({
        description: 'Query type: uncertainty, next_best_work, cached_recommendation, or full_replan.',
      }),
    }),
    async execute(_toolCallId: string, params: unknown, _signal: AbortSignal | undefined, _onUpdate: any, ctx: ExtensionContext) {
      const sessionId = ctx.sessionManager.getSessionId();
      if (!sessionId) {
        return toolTextResult('Error: session context unavailable.');
      }
      const investigationId = sessionLookup(sessionId);
      if (!investigationId) {
        return toolTextResult('No investigation is linked to this session.');
      }
      const investigation = investigationService.get(investigationId);
      if (!investigation) {
        return toolTextResult('Linked investigation not found.');
      }
      const { queryType } = (params || {}) as { queryType?: string };
      if (!queryType || typeof queryType !== 'string') {
        return toolTextResult('Error: queryType parameter is required.');
      }

      switch (queryType) {
        case 'uncertainty':
          return toolTextResult(JSON.stringify(replanner.assessUncertainty(investigation), null, 2));
        case 'next_best_work': {
          const assessment = replanner.assessUncertainty(investigation);
          const replan = replanner.createReplan(investigation);
          return toolTextResult(
            JSON.stringify(
              {
                uncertaintySummary: assessment.summary,
                uncertaintyReductionGoal: replan.nextBestWork.uncertaintyReductionGoal,
                recommendedTasks: replan.nextBestWork.recommendedTasks,
                advisoryOnly: true,
                source: 'computed',
              },
              null,
              2
            )
          );
        }
        case 'cached_recommendation': {
          const latestRecommendation = investigationService.getLatestReplanRecommendation(investigationId);
          if (!latestRecommendation) {
            return toolTextResult(
              JSON.stringify(
                {
                  investigationId,
                  advisoryOnly: true,
                  source: 'cached_event',
                  hasRecommendation: false,
                },
                null,
                2
              )
            );
          }
          return toolTextResult(
            JSON.stringify(
              {
                investigationId,
                advisoryOnly: true,
                source: 'cached_event',
                hasRecommendation: true,
                eventId: latestRecommendation.id,
                createdAt: latestRecommendation.createdAt,
                summary: latestRecommendation.summary,
                recommendation: latestRecommendation.data || {},
              },
              null,
              2
            )
          );
        }
        case 'full_replan':
          return toolTextResult(JSON.stringify(replanner.createReplan(investigation), null, 2));
        default:
          return toolTextResult(`Error: unknown queryType "${queryType}".`);
      }
    },
  };
}

export class InvestigationReplanExtension implements AgentRuntimeExtension {
  readonly name = 'investigation-replan';

  constructor(
    private readonly investigationService: InvestigationService,
    private readonly sessionLookup: (sessionId: string) => string | null,
    private readonly replanner = new InvestigationReplanner()
  ) {}

  async beforeSessionRun(context: BeforeSessionRunContext): Promise<BeforeSessionRunResult> {
    const investigationId = this.sessionLookup(context.session.id);
    if (!investigationId) {
      return { customTools: [] };
    }
    return {
      promptPrefix: buildPromptPrefix(),
      customTools: [createReplanQueryTool(this.investigationService, this.sessionLookup, this.replanner)],
    };
  }
}

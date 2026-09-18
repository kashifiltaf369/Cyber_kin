import { Type } from '@sinclair/typebox';
import type { ExtensionContext } from '@mariozechner/pi-coding-agent';
import type {
  AgentRuntimeCustomTool,
  AgentRuntimeExtension,
  BeforeSessionRunContext,
  BeforeSessionRunResult,
} from '../extensions/agent-runtime-extension';
import type { InvestigationService } from './investigation-service';

function toolTextResult(text: string, details?: unknown) {
  return {
    content: [{ type: 'text' as const, text }],
    details,
  };
}

function buildPromptPrefix(): string {
  return [
    '<investigation_hypothesis_guidance>',
    'Treat investigation hypotheses as competing explanations, not facts.',
    'Use structured hypothesis state to inspect support, contradictions, assumptions, unresolved questions, and confidence assessments.',
    'When possible, compare multiple hypotheses and consult challenger output before converging on conclusions.',
    '</investigation_hypothesis_guidance>',
  ].join('\n');
}

function createHypothesisQueryTool(
  investigationService: InvestigationService,
  sessionLookup: (sessionId: string) => string | null
): AgentRuntimeCustomTool {
  return {
    name: 'investigation_hypothesis_query',
    label: 'investigation_hypothesis_query',
    description:
      'Query structured investigation hypotheses linked to the current session. Supports listing hypotheses, reading one hypothesis, comparing competing hypotheses, and challenger review output.',
    parameters: Type.Object({
      queryType: Type.String({
        description: 'Query type: list, get, compare, or challenge.',
      }),
      hypothesisId: Type.Optional(
        Type.String({
          description: 'Hypothesis ID for get or single-hypothesis challenge flows.',
        })
      ),
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
      const { queryType, hypothesisId } = (params || {}) as { queryType?: string; hypothesisId?: string };
      if (!queryType || typeof queryType !== 'string') {
        return toolTextResult('Error: queryType parameter is required.');
      }

      switch (queryType) {
        case 'list':
          return toolTextResult(
            JSON.stringify(
              {
                investigationId,
                hypotheses: investigation.hypotheses,
              },
              null,
              2
            )
          );
        case 'get': {
          if (!hypothesisId) return toolTextResult('Error: hypothesisId is required for get.');
          const hypothesis = investigation.hypotheses.find((item) => item.id === hypothesisId) || null;
          return toolTextResult(JSON.stringify({ investigationId, hypothesis }, null, 2));
        }
        case 'compare':
          return toolTextResult(JSON.stringify(investigationService.compareHypotheses(investigationId), null, 2));
        case 'challenge': {
          const review = investigationService.challengeHypotheses(investigationId);
          const filtered = hypothesisId
            ? {
                ...review,
                reviews: review.reviews.filter((item) => item.hypothesisId === hypothesisId),
              }
            : review;
          return toolTextResult(JSON.stringify(filtered, null, 2));
        }
        default:
          return toolTextResult(`Error: unknown queryType "${queryType}".`);
      }
    },
  };
}

export class InvestigationHypothesisExtension implements AgentRuntimeExtension {
  readonly name = 'investigation-hypothesis';

  constructor(
    private readonly investigationService: InvestigationService,
    private readonly sessionLookup: (sessionId: string) => string | null
  ) {}

  async beforeSessionRun(context: BeforeSessionRunContext): Promise<BeforeSessionRunResult> {
    const investigationId = this.sessionLookup(context.session.id);
    if (!investigationId) {
      return { customTools: [] };
    }
    return {
      promptPrefix: buildPromptPrefix(),
      customTools: [createHypothesisQueryTool(this.investigationService, this.sessionLookup)],
    };
  }
}

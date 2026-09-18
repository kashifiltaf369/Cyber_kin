import { Type } from '@sinclair/typebox';
import type { ExtensionContext } from '@mariozechner/pi-coding-agent';
import type {
  AgentRuntimeCustomTool,
  AgentRuntimeExtension,
  BeforeSessionRunContext,
  BeforeSessionRunResult,
} from '../extensions/agent-runtime-extension';
import type { InvestigationService } from './investigation-service';

function toolTextResult(text: string) {
  return {
    content: [{ type: 'text' as const, text }],
    details: undefined,
  };
}

function buildPlanningPrefix(investigation: ReturnType<InvestigationService['get']>): string | undefined {
  if (!investigation) return undefined;
  const hc = investigation.humanCapabilityContext;
  const lines: string[] = [];
  lines.push('<investigation_context>');
  lines.push(`Investigation: ${investigation.title}`);
  lines.push(`Objective: ${investigation.objective}`);
  lines.push(`Status: ${investigation.status}`);
  if (investigation.humanContext.trim()) {
    lines.push(`Human context summary: ${investigation.humanContext.trim()}`);
  }
  if (hc.priorities.length > 0) {
    lines.push(`Priorities: ${hc.priorities.map((item) => item.value).join(' | ')}`);
  }
  if (hc.constraints.length > 0) {
    lines.push(`Constraints: ${hc.constraints.map((item) => item.value).join(' | ')}`);
  }
  if (hc.suspicions.length > 0) {
    lines.push(`Suspicions: ${hc.suspicions.map((item) => item.value).join(' | ')}`);
  }
  if (hc.knownLegitimateBehavior.length > 0) {
    lines.push(
      `Known legitimate behavior: ${hc.knownLegitimateBehavior.map((item) => item.value).join(' | ')}`
    );
  }
  if (hc.knownAbnormalBehavior.length > 0) {
    lines.push(
      `Known abnormal behavior: ${hc.knownAbnormalBehavior.map((item) => item.value).join(' | ')}`
    );
  }
  if (hc.investigationDirections.length > 0) {
    lines.push(
      `Human investigation direction: ${hc.investigationDirections.map((item) => item.value).join(' | ')}`
    );
  }
  lines.push(`Risk tolerance: ${hc.riskTolerance}`);
  lines.push('Treat human-provided constraints and known-legitimate-behavior as planning guardrails.');
  lines.push('Use this structured context when deciding what to investigate, what to deprioritize, and how to interpret evidence.');
  lines.push('</investigation_context>');
  return lines.join('\n');
}

function createInvestigationContextReadTool(
  investigationService: InvestigationService,
  sessionLookup: (sessionId: string) => string | null
): AgentRuntimeCustomTool {
  return {
    name: 'investigation_context_read',
    label: 'investigation_context_read',
    description:
      'Read structured human investigation context linked to the current session, including priorities, constraints, suspicions, known legitimate behavior, known abnormal behavior, important entities, decisions, and notes.',
    parameters: Type.Object({
      section: Type.Optional(
        Type.String({
          description:
            'Optional section to read: overview, priorities, constraints, suspicions, legitimate, abnormal, entities, directions, decisions, notes, hypotheses.',
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
      const { section } = (params || {}) as { section?: string };
      const hc = investigation.humanCapabilityContext;
      const payload = {
        overview: {
          title: investigation.title,
          objective: investigation.objective,
          status: investigation.status,
          humanContext: investigation.humanContext,
          riskTolerance: hc.riskTolerance,
        },
        priorities: hc.priorities,
        constraints: hc.constraints,
        suspicions: hc.suspicions,
        legitimate: hc.knownLegitimateBehavior,
        abnormal: hc.knownAbnormalBehavior,
        entities: hc.importantEntities,
        directions: hc.investigationDirections,
        decisions: investigation.decisions,
        notes: hc.notes,
        hypotheses: investigation.hypotheses,
      } as const;
      const key = (section || '').trim().toLowerCase();
      if (!key) {
        return toolTextResult(JSON.stringify(payload, null, 2));
      }
      if (!(key in payload)) {
        return toolTextResult(`Error: unknown section "${section}".`);
      }
      return toolTextResult(JSON.stringify(payload[key as keyof typeof payload], null, 2));
    },
  };
}

export class InvestigationContextExtension implements AgentRuntimeExtension {
  readonly name = 'investigation-context';

  constructor(
    private readonly investigationService: InvestigationService,
    private readonly sessionLookup: (sessionId: string) => string | null
  ) {}

  async beforeSessionRun(context: BeforeSessionRunContext): Promise<BeforeSessionRunResult> {
    const investigationId = this.sessionLookup(context.session.id);
    if (!investigationId) {
      return { customTools: [] };
    }
    const investigation = this.investigationService.get(investigationId);
    return {
      promptPrefix: buildPlanningPrefix(investigation),
      customTools: [
        createInvestigationContextReadTool(this.investigationService, this.sessionLookup),
      ],
    };
  }
}

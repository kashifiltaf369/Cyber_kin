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

function buildPromptPrefix(): string {
  return [
    '<investigation_cyber_audit_guidance>',
    'Use cyber audit history to understand which cyber actions were executed, denied, or required explicit approval during this investigation.',
    'Prefer recent denied or high-risk actions when replanning, challenging assumptions, or deciding what requires human involvement.',
    '</investigation_cyber_audit_guidance>',
  ].join('\n');
}

function createCyberAuditQueryTool(
  investigationService: InvestigationService,
  sessionLookup: (sessionId: string) => string | null
): AgentRuntimeCustomTool {
  return {
    name: 'investigation_cyber_audit_query',
    label: 'investigation_cyber_audit_query',
    description:
      'Read cyber action audit events linked to the current investigation, including denied, executed, and approval-requiring actions.',
    parameters: Type.Object({
      mode: Type.Optional(
        Type.String({
          description: 'Optional mode: recent, denied, high_risk, or summary. Default: recent.',
        })
      ),
      limit: Type.Optional(
        Type.Number({
          minimum: 1,
          maximum: 100,
          description: 'Maximum number of audit events to return. Default: 10.',
        })
      ),
    }),
    async execute(_toolCallId: string, params: unknown, _signal: AbortSignal | undefined, _onUpdate: unknown, ctx: ExtensionContext) {
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

      const { mode, limit } = (params || {}) as { mode?: string; limit?: number };
      const normalizedMode = (mode || 'recent').trim().toLowerCase();
      const maxItems = Math.max(1, Math.min(limit || 10, 100));

      if (normalizedMode === 'summary') {
        return toolTextResult(JSON.stringify(investigationService.summarizeCyberAuditEvents(investigationId, maxItems), null, 2));
      }

      const events = investigationService.getCyberAuditEvents(investigationId, {
        mode:
          normalizedMode === 'denied'
            ? 'denied'
            : normalizedMode === 'high_risk'
              ? 'high_risk'
              : 'recent',
        limit: maxItems,
      });

      return toolTextResult(
        JSON.stringify(
          {
            investigationId,
            mode: normalizedMode,
            count: events.length,
            events,
          },
          null,
          2
        )
      );
    },
  };
}

export class InvestigationCyberAuditExtension implements AgentRuntimeExtension {
  readonly name = 'investigation-cyber-audit';

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
      customTools: [createCyberAuditQueryTool(this.investigationService, this.sessionLookup)],
    };
  }
}

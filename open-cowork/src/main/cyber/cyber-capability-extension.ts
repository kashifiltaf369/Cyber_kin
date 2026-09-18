import { Type } from '@sinclair/typebox';
import type {
  AgentRuntimeCustomTool,
  AgentRuntimeExtension,
  BeforeSessionRunContext,
  BeforeSessionRunResult,
} from '../extensions/agent-runtime-extension';
import type {
  CyberCapabilityDefinition,
  CyberCapabilityExecutionContext,
  CyberCapabilityName,
  CyberCapabilityRegistry,
  CyberCapabilityRiskLevel,
} from './cyber-capability-registry';
import {
  CyberActionAuditTrail,
  CyberPermissionPolicy,
  classifyCapabilityRisk,
  type CyberCapabilityAuditContext,
} from './cyber-permission-policy';

export interface CyberCapabilityExtensionOptions {
  sessionLookup?: (sessionId: string) => string | null;
  resolveExecutionContext?: (args: {
    sessionId: string;
    capabilityName: CyberCapabilityName;
    adapterPreference?: string;
  }) => CyberCapabilityExecutionContext | undefined;
  allowedRiskLevels?: CyberCapabilityRiskLevel[];
  permissionResolver?: (
    capability: CyberCapabilityDefinition,
    input: unknown,
    context: { sessionId: string }
  ) => Promise<'allow' | 'deny'> | 'allow' | 'deny';
  auditTrail?: CyberActionAuditTrail;
  permissionPolicy?: CyberPermissionPolicy;
  onAuditRecord?: (record: import('./cyber-permission-policy').CyberActionAuditRecord) => void;
}

function toolTextResult(text: string, details?: unknown) {
  return {
    content: [{ type: 'text' as const, text }],
    details,
  };
}

function formatCapabilitySummary(capability: CyberCapabilityDefinition): Record<string, unknown> {
  return {
    name: capability.name,
    description: capability.description,
    riskLevel: capability.riskLevel,
    actionCategory: capability.actionCategory || classifyCapabilityRisk(capability),
    permissionsRequired: capability.permissionsRequired,
    timeoutMs: capability.timeoutMs,
    cost: capability.cost,
    supportedAdapters: capability.supportedAdapters,
    tags: capability.tags,
    canAnswer: capability.canAnswer,
    inputSchema: capability.inputSchema,
    outputSchema: capability.outputSchema,
  };
}

function buildPromptPrefix(): string {
  return [
    '<cyber_capability_guidance>',
    'When doing cybersecurity investigation work, prefer the cyber capability tools over vendor-specific assumptions.',
    'First ask which capability can answer the investigative question, then execute the selected capability with structured input.',
    'Use capability discovery to choose between evidence sources such as logs, processes, network, DNS, identity activity, file inspection, hashes, historical activity, browser data, safe analysis, and PCAP-derived data.',
    'Respect capability risk levels and human investigation constraints.',
    '</cyber_capability_guidance>',
  ].join('\n');
}

function createDiscoverTool(
  registry: CyberCapabilityRegistry,
  options: CyberCapabilityExtensionOptions
): AgentRuntimeCustomTool {
  return {
    name: 'cyber_capability_discover',
    label: 'cyber_capability_discover',
    description:
      'Discover vendor-neutral cybersecurity capabilities that can answer an investigative question. Use this before executing a capability when deciding how to gather evidence.',
    parameters: Type.Object({
      question: Type.String({
        description:
          'The investigative question to answer, e.g. "How can I search DNS activity for suspicious lookups?"',
      }),
      limit: Type.Optional(
        Type.Number({
          minimum: 1,
          maximum: 20,
          description: 'Maximum number of candidate capabilities to return. Default: 5.',
        })
      ),
    }),
    async execute(_toolCallId: string, params: unknown) {
      const { question, limit } = (params || {}) as { question?: string; limit?: number };
      if (!question || typeof question !== 'string' || question.trim().length === 0) {
        return toolTextResult('Error: question parameter is required.');
      }
      const allowedRiskLevels = new Set(options.allowedRiskLevels || ['LOW', 'MEDIUM']);
      const matches = registry
        .discover(question)
        .filter((item) => allowedRiskLevels.has(item.capability.riskLevel))
        .slice(0, Math.max(1, Math.min(limit || 5, 20)))
        .map((item) => ({
          score: item.score,
          reasons: item.reasons,
          capability: formatCapabilitySummary(item.capability),
        }));
      return toolTextResult(JSON.stringify({ question, matches }, null, 2));
    },
  };
}

function createExecuteTool(
  registry: CyberCapabilityRegistry,
  options: CyberCapabilityExtensionOptions
): AgentRuntimeCustomTool {
  return {
    name: 'cyber_capability_execute',
    label: 'cyber_capability_execute',
    description:
      'Execute a vendor-neutral cybersecurity capability with structured input. This performs controlled evidence gathering or safe analysis using the capability registry.',
    parameters: Type.Object({
      name: Type.String({
        description: 'Capability name to execute, e.g. search_dns or calculate_hash.',
      }),
      input: Type.Optional(
        Type.Any({
          description: 'Structured input for the capability matching the capability input schema.',
        })
      ),
      adapterPreference: Type.Optional(
        Type.String({
          description: 'Optional adapter preference when more than one adapter supports the capability.',
        })
      ),
    }),
    async execute(
      _toolCallId: string,
      params: unknown,
      _signal,
      _onUpdate,
      ctx
    ) {
      const { name, input, adapterPreference } = (params || {}) as {
        name?: string;
        input?: unknown;
        adapterPreference?: string;
      };
      if (!name || typeof name !== 'string') {
        return toolTextResult('Error: name parameter is required.');
      }
      const capability = registry.get(name as CyberCapabilityName);
      if (!capability) {
        return toolTextResult(`Error: unknown capability "${name}".`);
      }
      const allowedRiskLevels = new Set(options.allowedRiskLevels || ['LOW', 'MEDIUM']);
      if (!allowedRiskLevels.has(capability.riskLevel)) {
        return toolTextResult(
          `Error: capability "${capability.name}" has disallowed risk level ${capability.riskLevel}.`
        );
      }
      const sessionId = (ctx as { sessionId?: string } | undefined)?.sessionId;
      if (!sessionId) {
        return toolTextResult('Error: session context unavailable.');
      }
      if (options.sessionLookup && !options.sessionLookup(sessionId)) {
        return toolTextResult(
          'Error: this session is not linked to an investigation and cannot use cyber capabilities.'
        );
      }
      if (options.permissionResolver) {
        const decision = await options.permissionResolver(capability, input, { sessionId });
        if (decision === 'deny') {
          return toolTextResult(`Error: permission denied for capability "${capability.name}".`);
        }
      }
      const investigationId = options.sessionLookup?.(sessionId) || null;
      const permissionPolicy = options.permissionPolicy || new CyberPermissionPolicy();
      const auditTrail = options.auditTrail;
      const executionContext = (options.resolveExecutionContext?.({
        sessionId,
        capabilityName: capability.name,
        adapterPreference,
      }) || { adapterPreference }) as CyberCapabilityAuditContext;

      const decision = permissionPolicy.decide(capability, input, executionContext.explicitHumanApproval === true);
      if (!decision.allowed) {
        const deniedRecord = auditTrail?.append({
          actor: 'agent',
          agent: sessionId,
          timestamp: Date.now(),
          investigationId,
          capabilityName: capability.name,
          actionCategory: classifyCapabilityRisk(capability),
          target: 'unknown',
          parameters: (input && typeof input === 'object' ? (input as Record<string, unknown>) : {}) || {},
          result: { status: 'denied', summary: decision.reason },
          approvalState: decision.approvalState,
        });
        if (deniedRecord) {
          options.onAuditRecord?.(deniedRecord);
        }
        return toolTextResult(`Error: ${decision.reason}`);
      }

      const result = await registry.execute(capability.name, input, executionContext);
      if (auditTrail) {
        const record = permissionPolicy.audit(
          auditTrail,
          capability,
          input,
          { sessionId, investigationId, actor: 'agent', agent: sessionId },
          decision,
          { status: 'executed', summary: `Executed capability ${capability.name}` }
        );
        options.onAuditRecord?.(record);
      }
      return toolTextResult(JSON.stringify(result, null, 2), {
        capability: formatCapabilitySummary(capability),
        approvalState: decision.approvalState,
      });
    },
  };
}

export class CyberCapabilityExtension implements AgentRuntimeExtension {
  readonly name = 'cyber-capability';

  constructor(
    private readonly registry: CyberCapabilityRegistry,
    private readonly options: CyberCapabilityExtensionOptions = {}
  ) {}

  async beforeSessionRun(_context: BeforeSessionRunContext): Promise<BeforeSessionRunResult> {
    return {
      promptPrefix: buildPromptPrefix(),
      customTools: [createDiscoverTool(this.registry, this.options), createExecuteTool(this.registry, this.options)],
    };
  }
}

import { describe, expect, it } from 'vitest';
import type { InvestigationStatus, InvestigationEventType } from '../src/shared/cyber/investigation-types';

describe('Investigation type contracts', () => {
  it('supports the expected lifecycle states', () => {
    const states: InvestigationStatus[] = [
      'CREATED',
      'PLANNING',
      'INVESTIGATING',
      'WAITING_FOR_HUMAN',
      'REPLANNING',
      'CONCLUDED',
      'ARCHIVED',
    ];
    expect(states).toHaveLength(7);
  });

  it('supports the required important event types', () => {
    const required: InvestigationEventType[] = [
      'INVESTIGATION_CREATED',
      'PLAN_CREATED',
      'TASK_CREATED',
      'TASK_STARTED',
      'TASK_COMPLETED',
      'EVIDENCE_ADDED',
      'EVIDENCE_LINKED',
      'EVIDENCE_ANNOTATED',
      'HYPOTHESIS_CREATED',
      'HYPOTHESIS_UPDATED',
      'HUMAN_INPUT_ADDED',
      'AGENT_REDIRECTED',
      'CONCLUSION_UPDATED',
    ];
    expect(required).toContain('AGENT_REDIRECTED');
  });
});

import { describe, expect, it } from 'vitest';
import type { ClientEvent, ServerEvent } from '../src/renderer/types';

describe('investigation IPC types', () => {
  it('supports investigation orchestration client events', () => {
    const planEvent: ClientEvent = {
      type: 'investigation.plan',
      payload: { investigationId: 'inv-1' },
    };
    const replanEvent: ClientEvent = {
      type: 'investigation.replan',
      payload: { investigationId: 'inv-1' },
    };
    const latestRecommendationEvent: ClientEvent = {
      type: 'investigation.getLatestReplanRecommendation',
      payload: { investigationId: 'inv-1' },
    };
    const executeEvent: ClientEvent = {
      type: 'investigation.execute',
      payload: { investigationId: 'inv-1' },
    };
    const pauseEvent: ClientEvent = {
      type: 'investigation.pauseTask',
      payload: { plannedTaskId: 'task-1', reason: 'Pause for review' },
    };
    const resumeEvent: ClientEvent = {
      type: 'investigation.resumeTask',
      payload: { plannedTaskId: 'task-1' },
    };
    const reprioritizeEvent: ClientEvent = {
      type: 'investigation.reprioritizeTask',
      payload: { plannedTaskId: 'task-1', priority: 10, rationale: 'Human priority changed' },
    };
    const createTaskEvent: ClientEvent = {
      type: 'investigation.createTask',
      payload: {
        investigationId: 'inv-1',
        task: {
          id: 'task-2',
          title: 'Investigate lateral movement',
          description: 'Review remote access paths',
          role: 'Network Investigator',
          kind: 'investigative',
          dependsOn: [],
          canRunConcurrently: true,
          mergeStrategy: 'append_evidence',
        },
      },
    };
    const interruptionEvent: ClientEvent = {
      type: 'investigation.applyHumanInterruption',
      payload: {
        investigationId: 'inv-1',
        instruction: 'Stop focusing on the vendor domain and investigate lateral movement.',
        addPriority: 'Investigate lateral movement first',
        cancelTaskIds: ['task-1'],
      },
    };
    const cancelEvent: ClientEvent = {
      type: 'investigation.cancelTask',
      payload: { plannedTaskId: 'task-1', reason: 'Human cancelled' },
    };
    const redirectEvent: ClientEvent = {
      type: 'investigation.redirectTask',
      payload: {
        plannedTaskId: 'task-1',
        description: 'Refocus on identity evidence',
        role: 'Identity Investigator',
      },
    };

    expect(planEvent.type).toBe('investigation.plan');
    expect(replanEvent.type).toBe('investigation.replan');
    expect(latestRecommendationEvent.type).toBe('investigation.getLatestReplanRecommendation');
    expect(executeEvent.type).toBe('investigation.execute');
    expect(pauseEvent.type).toBe('investigation.pauseTask');
    expect(resumeEvent.type).toBe('investigation.resumeTask');
    expect(reprioritizeEvent.type).toBe('investigation.reprioritizeTask');
    expect(createTaskEvent.type).toBe('investigation.createTask');
    expect(interruptionEvent.type).toBe('investigation.applyHumanInterruption');
    expect(cancelEvent.type).toBe('investigation.cancelTask');
    expect(redirectEvent.type).toBe('investigation.redirectTask');
  });

  it('supports investigation plan server events', () => {
    const event: ServerEvent = {
      type: 'investigation.plan',
      payload: {
        investigationId: 'inv-1',
        plan: {
          objective: 'Investigate suspicious sign-ins',
          summary: 'Generated plan',
          createdAt: Date.now(),
          tasks: [
            {
              id: 'task-1',
              title: 'Analyze identity activity',
              description: 'Check sign-ins',
              role: 'Identity Investigator',
              kind: 'investigative',
              dependsOn: [],
              canRunConcurrently: true,
              mergeStrategy: 'append_evidence',
            },
          ],
        },
      },
    };

    expect(event.type).toBe('investigation.plan');
    if (event.type === 'investigation.plan') {
      expect(event.payload.plan.tasks[0]?.role).toBe('Identity Investigator');
    }

    const replanServerEvent: ServerEvent = {
      type: 'investigation.replan',
      payload: {
        investigationId: 'inv-1',
        plan: {
          objective: 'Investigate suspicious sign-ins',
          summary: 'Replanned investigation work',
          createdAt: Date.now(),
          tasks: [
            {
              id: 'task-r1',
              title: 'Validate historical authentication pattern',
              description: 'Determine whether service account X normally authenticates from host Y.',
              role: 'Historical Investigator',
              kind: 'research',
              dependsOn: [],
              canRunConcurrently: true,
              mergeStrategy: 'append_notes',
            },
          ],
        },
      },
    };
    const latestRecommendationServerEvent: ServerEvent = {
      type: 'investigation.replanRecommendation',
      payload: {
        investigationId: 'inv-1',
        recommendation: {
          id: 'evt-1',
          investigationId: 'inv-1',
          type: 'REPLAN_RECOMMENDED',
          createdAt: Date.now(),
          actor: 'system',
          summary: 'Replan recommended after evidence merge',
          data: {
            uncertaintySummary: 'Current evidence does not distinguish between competing hypotheses.',
            autoExecuted: false,
          },
        },
      },
    };

    expect(replanServerEvent.type).toBe('investigation.replan');
    if (replanServerEvent.type === 'investigation.replan') {
      expect(replanServerEvent.payload.plan.tasks[0]?.role).toBe('Historical Investigator');
    }

    expect(latestRecommendationServerEvent.type).toBe('investigation.replanRecommendation');
    if (latestRecommendationServerEvent.type === 'investigation.replanRecommendation') {
      expect(latestRecommendationServerEvent.payload.recommendation?.type).toBe('REPLAN_RECOMMENDED');
      expect(latestRecommendationServerEvent.payload.recommendation?.data).toMatchObject({ autoExecuted: false });
    }
  });
});

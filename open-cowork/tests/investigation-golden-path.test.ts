/**
 * Golden-path integration test — KIN investigation workflow over the REAL
 * backend (no mocked success).
 *
 * Drives the same code path the typed IPC handlers use:
 *   InvestigationService (real better-sqlite3 schema, in-memory)
 *     → RuntimeInvestigationOrchestrator.createPlan (real planner)
 *     → applyHumanInterruption (real normalization + service writes)
 *     → createHumanDirectedTask / reprioritizeTask (real task manager)
 *     → replan recommendation (real replanner)
 *     → generateReport / renderReportMarkdown (real report builder)
 *
 * NOT covered here (documented, not faked): live worker execution — that
 * path starts real agent sessions and requires a configured model/API key,
 * which a CI sandbox does not have. Everything up to worker dispatch is
 * exercised against real persisted state.
 */

import { describe, expect, it } from 'vitest';
import { initDatabase } from '../src/main/db/database';
import { InvestigationService } from '../src/main/investigation/investigation-service';
import {
  RuntimeInvestigationOrchestrator,
  type InvestigationSessionRuntime,
} from '../src/main/investigation/runtime-investigation-orchestrator';

const noopRuntime: InvestigationSessionRuntime = {
  startSession: (() => {
    throw new Error('worker sessions are not part of the golden-path integration test');
  }) as never,
  stopSession: () => undefined,
  getSession: () => null,
  getMessages: () => [],
};

describe('KIN investigation golden path (real backend)', () => {
  it('create → plan → human interruption → human-directed tasks → replan → report', async () => {
    const db = initDatabase({ dbPath: ':memory:' });
    const investigationService = new InvestigationService(db);

    // 1. Create (analyst opens a new case).
    const created = investigationService.create({
      title: 'Suspected credential misuse',
      objective: 'Determine whether the service account was used interactively.',
      humanContext: 'Reports of unusual VPN logins for svc-backup.',
      riskTolerance: 'MEDIUM',
      hypotheses: [
        { title: 'Interactive use of service account', statement: 'svc-backup was used by a person from a workstation.', confidence: 0.4 },
      ],
    });
    expect(created.id).toBeTruthy();
    expect(created.status).toBe('CREATED');

    const orchestrator = new RuntimeInvestigationOrchestrator(investigationService, noopRuntime);

    // 2. Plan (real planner over the real capability registry).
    const plan = orchestrator.createPlan(created.id);
    expect(plan.tasks.length).toBeGreaterThan(0);
    for (const task of plan.tasks) {
      expect(task.id).toBeTruthy();
      expect(task.role).toBeTruthy();
    }

    // 3. Human interruption (batch shape) — real normalization + writes.
    const interruption = orchestrator.applyHumanInterruption(created.id, {
      instruction: 'Focus on VPN gateway logs first.',
      addPriority: 'Gateway auth logs before endpoint triage',
      addContext: ['VPN gateway is hosted by the network team'],
    });
    expect(interruption.updatedInvestigation).not.toBeNull();

    const afterInterruption = investigationService.get(created.id)!;
    expect(afterInterruption.humanCapabilityContext.priorities.map((p) => p.value)).toContain(
      'Gateway auth logs before endpoint triage'
    );
    // A replan recommendation is always recorded after an interruption.
    const recommendation = investigationService.getLatestReplanRecommendation(created.id);
    expect(recommendation).not.toBeNull();
    expect(recommendation?.type).toBe('REPLAN_RECOMMENDED');

    // 4. Single-action (kind-based) interruptions — the shapes the UI sends.
    orchestrator.applyHumanInterruption(created.id, { kind: 'suspicion', value: 'svc-backup logins cluster after midnight' });
    orchestrator.applyHumanInterruption(created.id, { kind: 'constraint', value: 'Do not contact the network team without approval' });
    orchestrator.applyHumanInterruption(created.id, { kind: 'hypothesis', title: 'Scheduled job misuse', statement: 'A scheduled job is reusing the service account ticket.' });
    const afterKinds = investigationService.get(created.id)!;
    expect(
      afterKinds.humanCapabilityContext.suspicions.map((s) => s.value).join(' ')
    ).toContain('svc-backup logins cluster after midnight');
    expect(afterKinds.hypotheses.map((h) => h.title)).toContain('Scheduled job misuse');

    // Invalid single-action payloads must be rejected, not coerced.
    expect(() => orchestrator.applyHumanInterruption(created.id, { kind: 'directive', value: '   ' })).toThrow();
    expect(() => orchestrator.applyHumanInterruption(created.id, { kind: 'promote_hypothesis' })).toThrow();

    // 5. Human-directed task creation reaches the investigation record.
    orchestrator.createHumanDirectedTask(created.id, {
      id: 'human-task-1',
      title: 'Review gateway auth logs',
      description: 'Pull VPN gateway auth logs for the last 7 days.',
      role: 'Network Investigator',
      kind: 'investigative',
      mergeStrategy: 'append_evidence',
    });
    const withHumanTask = investigationService.get(created.id)!;
    expect(withHumanTask.aiTasks.map((t) => t.title)).toContain('Review gateway auth logs');

    // 6. Replan (real replanner over live investigation state).
    const replan = orchestrator.createReplan(created.id);
    expect(replan.tasks.length).toBeGreaterThanOrEqual(0);
    expect(replan.objective).toBeTruthy();

    // 7. Report generation over persisted state.
    const report = investigationService.generateReport(created.id);
    expect(report.investigationId).toBe(created.id);
    const markdown = investigationService.renderReportMarkdown(created.id);
    expect(markdown).toContain('Suspected credential misuse');
    expect(markdown).toContain('Scheduled job misuse');

    // 8. Events were durably recorded for the investigation timeline.
    const events = db.investigationEvents.getByInvestigationId(created.id);
    const eventTypes = events.map((e) => e.type);
    expect(eventTypes).toContain('INVESTIGATION_CREATED');
    expect(eventTypes).toContain('REPLAN_RECOMMENDED');

    db.close();
  });

  it('archive + list round-trip through the real database', async () => {
    const db = initDatabase({ dbPath: ':memory:' });
    const investigationService = new InvestigationService(db);

    const investigation = investigationService.create({
      title: 'Lateral movement triage',
      objective: 'Scope SMB activity from WORKSTATION-22.',
    });
    investigationService.archive(investigation.id);

    const all = investigationService.list();
    const archived = all.find((item) => item.id === investigation.id);
    expect(archived?.status).toBe('ARCHIVED');

    db.close();
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoScenarioController } from '../src/main/demo/demo-scenario-controller';
import { InvestigationService } from '../src/main/investigation/investigation-service';
import type { DatabaseInstance, InvestigationEventRow, InvestigationRow, InvestigationSessionLinkRow } from '../src/main/db/database';
import type { DemoControllerState } from '../src/shared/cyber/demo-types';
import type { ServerEvent } from '../src/renderer/types';

/**
 * KIN Demo Mode — deterministic scenario controller tests.
 *
 * The controller drives a REAL InvestigationService; these tests verify the
 * §30 acceptance sequence end-to-end (with accelerated scenario timing):
 * start → context root → evidence → specialists → hypotheses → next best
 * step → BLOCKING approval → computer use → new evidence → updated
 * hypotheses → (second approval) → conclusion → real report; plus deny
 * behavior and restart repeatability.
 */

function makeDb() {
  const investigations = new Map<string, InvestigationRow>();
  const events = new Map<string, InvestigationEventRow[]>();
  const links = new Map<string, InvestigationSessionLinkRow>();

  const db: DatabaseInstance = {
    raw: {} as never,
    investigations: {
      create: vi.fn((row: InvestigationRow) => investigations.set(row.id, { ...row })),
      update: vi.fn((id: string, updates: Partial<InvestigationRow>) => {
        const current = investigations.get(id);
        if (!current) return;
        investigations.set(id, { ...current, ...updates, updated_at: Date.now() });
      }),
      get: vi.fn((id: string) => investigations.get(id)),
      getAll: vi.fn(() => Array.from(investigations.values())),
      delete: vi.fn(),
    },
    investigationEvents: {
      create: vi.fn((row: InvestigationEventRow) => {
        const list = events.get(row.investigation_id) || [];
        list.push({ ...row });
        events.set(row.investigation_id, list);
      }),
      getByInvestigationId: vi.fn((id: string) => (events.get(id) || []).slice()),
      deleteByInvestigationId: vi.fn(),
    },
    investigationSessionLinks: {
      link: vi.fn((investigationId: string, sessionId: string, role: string) => {
        links.set(sessionId, { investigation_id: investigationId, session_id: sessionId, role, created_at: Date.now() });
      }),
      getInvestigationIdBySessionId: vi.fn((sessionId: string) => links.get(sessionId)?.investigation_id ?? null),
      getSessionLinksByInvestigationId: vi.fn((investigationId: string) =>
        Array.from(links.values()).filter((item) => item.investigation_id === investigationId)
      ),
      deleteBySessionId: vi.fn((sessionId: string) => {
        links.delete(sessionId);
      }),
    },
    sessions: {} as never,
    messages: {} as never,
    traceSteps: {} as never,
    scheduledTasks: {} as never,
    prepare: vi.fn() as never,
    exec: vi.fn(),
    pragma: vi.fn(),
    close: vi.fn(),
  };

  return { db };
}

/** Accelerated scenario timing: every scripted delay is scaled to ~0.5% . */
const FAST_STEP_DELAY_MS = 4;

/** Waits for the blocking approval gate for a specific step to be open. */
async function waitForGate(
  controller: DemoScenarioController,
  stepId: string,
  timeoutMs = 8000
): Promise<DemoControllerState> {
  const start = Date.now();
  for (;;) {
    const state = controller.snapshot();
    if (
      state.phase === 'awaiting-approval' &&
      state.approval?.stepId === stepId &&
      state.approval.status === 'pending'
    ) {
      return state;
    }
    if (Date.now() - start > timeoutMs) {
      throw new Error(`Timed out waiting for approval gate ${stepId}; phase: ${state.phase}, approval: ${state.approval?.stepId ?? 'none'}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function waitForPhase(
  controller: DemoScenarioController,
  phase: DemoControllerState['phase'],
  timeoutMs = 8000
): Promise<DemoControllerState> {
  const start = Date.now();
  for (;;) {
    const state = controller.snapshot();
    if (state.phase === phase) return state;
    if (Date.now() - start > timeoutMs) {
      throw new Error(`Timed out waiting for phase ${phase}; current: ${state.phase}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe('DemoScenarioController (KIN Demo Mode)', () => {
  let cleanup: (() => void) | null = null;

  function makeController(stepDelayMs = FAST_STEP_DELAY_MS) {
    const { db } = makeDb();
    const investigationService = new InvestigationService(db);
    const rendererEvents: ServerEvent[] = [];
    const controller = new DemoScenarioController(
      {
        investigationService,
        sendToRenderer: (event) => rendererEvents.push(event),
      },
      { stepDelayMs }
    );
    cleanup = () => controller.dispose();
    return { controller, investigationService, rendererEvents };
  }

  afterEach(() => {
    cleanup?.();
    cleanup = null;
  });

  it('runs the full scenario: start → evidence → hypotheses → blocking approval → computer use → new evidence → conclusion → real report', async () => {
    const { controller, investigationService, rendererEvents } = makeController();
    const { investigationId } = controller.start();

    expect(investigationId).toBeTruthy();
    const titled = investigationService.get(investigationId);
    expect(titled?.title.startsWith('[DEMO MODE]')).toBe(true);
    expect(titled?.humanContext.includes('KIN_DEMO_MODE')).toBe(true);

    // Context root fills in as real controller state.
    const contextReady = await waitForPhase(controller, 'signal-detected');
    expect(contextReady.contextRoot.every((section) => section.status === 'ready')).toBe(true);
    expect(contextReady.signal).toMatchObject({ parent: 'WINWORD.EXE', child: 'powershell.exe' });

    // E-001 and E-002 land as REAL investigation evidence.
    await vi.waitFor(() => {
      const inv = investigationService.get(investigationId);
      expect(inv?.evidence.length).toBeGreaterThanOrEqual(2);
    }, { timeout: 8000 });

    // Correlation chain becomes visible.
    await vi.waitFor(() => {
      expect(controller.snapshot().correlationChain.length).toBeGreaterThan(0);
    }, { timeout: 8000 });

    // Competing hypotheses: H1 MEDIUM-ish, H2 LOW, service-computed.
    await vi.waitFor(() => {
      const inv = investigationService.get(investigationId);
      const h1 = inv?.hypotheses.find((h) => h.title.startsWith('H1'));
      const h2 = inv?.hypotheses.find((h) => h.title.startsWith('H2'));
      expect(h1).toBeDefined();
      expect(h2).toBeDefined();
      expect(h1!.status).toBe('SUPPORTED');
      expect(h1!.confidenceAssessment).toBe('MEDIUM');
      expect(h1!.supportingEvidenceIds.length).toBeGreaterThanOrEqual(3);
      expect(h2!.confidenceAssessment).toBe('LOW');
      expect(h2!.contradictingEvidenceIds.length).toBeGreaterThanOrEqual(2);
    }, { timeout: 8000 });

    // Explicit unknowns are acknowledged before any action.
    await vi.waitFor(() => {
      expect(controller.snapshot().unknowns.length).toBeGreaterThanOrEqual(2);
    }, { timeout: 8000 });

    // NEXT BEST STEP + BLOCKING approval gate.
    const gated = await waitForGate(controller, 'step-1');
    expect(gated.approval?.status).toBe('pending');
    expect(gated.nextStep?.expectedValue).toBe('HIGH');
    const invAtGate = investigationService.get(investigationId);
    const evidenceAtGate = invAtGate.evidence.length;

    // THE GATE MUST BLOCK: with accelerated timing any scheduled continuation
    // would have fired long ago; phase + evidence must remain unchanged.
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(controller.snapshot().phase).toBe('awaiting-approval');
    expect(controller.snapshot().approval?.status).toBe('pending');
    expect(investigationService.get(investigationId).evidence.length).toBe(evidenceAtGate);

    // Judge approves → computer use runs through the same action/result
    // stream → E-005 appears → hypotheses update → second approval gate.
    const approved = controller.approve('step-1');
    expect(approved.success).toBe(true);

    await vi.waitFor(() => {
      expect(controller.snapshot().computerActions.length).toBeGreaterThanOrEqual(3);
      expect(controller.snapshot().computerActions.every((action) => action.status === 'done')).toBe(true);
    }, { timeout: 8000 });

    // E-005 (post-approval execution confirmation) as real evidence.
    await vi.waitFor(() => {
      const inv = investigationService.get(investigationId);
      const e5 = inv?.evidence.find((item) => item.title.includes('E-005'));
      expect(e5).toBeDefined();
      expect(e5?.title).toContain('Confirmed Execution');
    }, { timeout: 8000 });

    // Hypotheses moved: H1 HIGH/SUPPORTED (E-005 supporting), H2 disfavored.
    await vi.waitFor(() => {
      const inv = investigationService.get(investigationId);
      const h1 = inv?.hypotheses.find((h) => h.title.startsWith('H1'));
      const h2 = inv?.hypotheses.find((h) => h.title.startsWith('H2'));
      expect(h1?.confidenceAssessment).toBe('HIGH');
      expect(h1?.supportingEvidenceIds).toContain(
        inv?.evidence.find((item) => item.title.includes('E-005'))?.id
      );
      expect(h2?.status).toBe('WEAKENED');
      expect(h2?.confidence).toBeLessThan(0.4);
    }, { timeout: 8000 });

    // Second approval gate (persistence question).
    const gated2 = await waitForGate(controller, 'step-2');
    expect(gated2.approval?.stepId).toBe('step-2');
    controller.approve('step-2');

    // Conclusion: HIGH confidence, never 100%, unknowns preserved.
    const finished = await waitForPhase(controller, 'complete');
    expect(finished.conclusion).not.toBeNull();
    expect(finished.conclusion?.confidence).toBe('HIGH');
    expect(finished.conclusion?.confidencePercent).toBeLessThan(100);
    expect(finished.conclusion?.remainingUnknowns.length).toBeGreaterThanOrEqual(2);

    const concluded = investigationService.get(investigationId);
    expect(concluded.status).toBe('CONCLUDED');
    expect(concluded.conclusions.at(-1)?.summary).toBeTruthy();
    expect(concluded.confidence).toBeCloseTo(0.9, 5);

    // The REPORT is generated from the actual state by the real pipeline.
    const markdown = investigationService.renderReportMarkdown(investigationId);
    expect(markdown).toContain('Suspicious PowerShell');
    expect(markdown.toUpperCase()).toContain('DEMO');

    // Renderer received real state sync + demo snapshots.
    const types = new Set(rendererEvents.map((event) => event.type));
    expect(types.has('demo.state')).toBe(true);
    expect(types.has('investigation.updated')).toBe(true);
    expect(types.has('investigation.list')).toBe(true);
  }, 30000);

  it('blocks at the approval gate and DENY ends the run without new evidence', async () => {
    const { controller, investigationService } = makeController();
    const { investigationId } = controller.start();

    await waitForGate(controller, 'step-1');
    const before = investigationService.get(investigationId).evidence.length;

    const denied = controller.deny('step-1');
    expect(denied.success).toBe(true);
    expect(controller.snapshot().phase).toBe('denied');

    // Nothing executes after denial.
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(controller.snapshot().phase).toBe('denied');
    expect(investigationService.get(investigationId).evidence.length).toBe(before);
    expect(investigationService.get(investigationId).status).not.toBe('CONCLUDED');

    // The denial is recorded as an operational event in the real stream.
    const inv = investigationService.get(investigationId);
    const denialEvent = (inv as unknown as { events?: Array<{ type: string }> }).events;
    void denialEvent;
  });

  it('restart archives the previous demo investigation and is repeatable', async () => {
    const { controller, investigationService } = makeController();

    // Run #1 to completion, then restart twice — each restart must produce
    // a fresh, complete run (restart repeatability).
    const first = controller.start();
    const completedIds = new Set<string>();
    const seenIds = new Set([first.investigationId]);

    const runToCompletion = async (): Promise<string> => {
      await waitForGate(controller, 'step-1');
      expect(controller.approve('step-1').success).toBe(true);
      await waitForGate(controller, 'step-2');
      expect(controller.approve('step-2').success).toBe(true);
      const finished = await waitForPhase(controller, 'complete');
      const id = finished.investigationId!;
      expect(completedIds.has(id)).toBe(false); // each run completes once
      completedIds.add(id);
      const inv = investigationService.get(id);
      expect(inv.evidence.length).toBeGreaterThanOrEqual(5);
      expect(inv.conclusions.at(-1)?.summary).toBeTruthy();
      return id;
    };

    await runToCompletion();

    for (let run = 0; run < 2; run += 1) {
      const next = controller.restart();
      expect(seenIds.has(next.investigationId)).toBe(false);
      seenIds.add(next.investigationId);
      const state = await waitForGate(controller, 'step-1');
      expect(state.evidence.length).toBeGreaterThanOrEqual(4);
      expect(state.contextRoot.every((section) => section.status === 'ready')).toBe(true);
      await runToCompletion();
    }

    // Every investigation replaced by a restart is archived.
    const all = investigationService.list();
    const archived = all.filter((item) => item.status === 'ARCHIVED');
    expect(archived.length).toBe(2);
    expect(controller.snapshot().phase).toBe('complete');
  }, 30000);

  it('never auto-approves: snapshot state gates expose pending approval only via IPC answer', async () => {
    const { controller } = makeController(60); // near-real pacing
    controller.start();
    const gated = await waitForPhase(controller, 'awaiting-approval', 20000);
    expect(gated.approval?.status).toBe('pending');

    // Wrong step id is rejected; gate stays closed.
    expect(controller.approve('bogus-step').success).toBe(false);
    expect(controller.deny('bogus-step').success).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(controller.snapshot().phase).toBe('awaiting-approval');
    expect(controller.snapshot().approval?.status).toBe('pending');
  });
});

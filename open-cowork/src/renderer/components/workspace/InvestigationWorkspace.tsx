import { useCallback, useEffect, useMemo, useState } from 'react';
import { ChevronLeft } from 'lucide-react';
import type {
  Investigation,
  InvestigationEvent,
  InvestigationTask,
} from '../../../shared/cyber/investigation-types';
import type { InvestigationPlan, PlannedInvestigationTask } from '../../../main/investigation/parallel-investigation-engine';
import { useAppStore } from '../../store';
import { useIPC } from '../../hooks/useIPC';
import {
  useActiveInvestigation,
  useActiveInvestigationId,
  useActiveInvestigationPlan,
  useActiveInvestigationRecommendation,
} from '../../store/selectors';
import { InvestigationsList } from './InvestigationsList';
import { InvestigationHeader } from './InvestigationHeader';
import { AITeamPanel } from './AITeamPanel';
import { HumanContextPanel } from './HumanContextPanel';
import { TaskBoard } from './TaskBoard';
import { EvidenceFeed } from './EvidenceFeed';
import { Timeline } from './Timeline';
import { HypothesesPanel } from './HypothesesPanel';
import { EvidenceGraph } from './EvidenceGraph';
import { OpenQuestionsPanel } from './OpenQuestionsPanel';
import { AISynthesisPanel } from './AISynthesisPanel';
import { ChallengerFindingsPanel } from './ChallengerFindingsPanel';
import { InvestigationReportPanel } from './InvestigationReportPanel';
import { HumanCommandBar, type CommandKind } from './HumanCommandBar';
import { WorkerInspector } from './WorkerInspector';

export function InvestigationWorkspace() {
  const investigation = useActiveInvestigation();
  const plan = useActiveInvestigationPlan();
  const recommendation = useActiveInvestigationRecommendation();
  const activeInvestigationId = useActiveInvestigationId();
  const setActiveInvestigation = useAppStore((s) => s.setActiveInvestigation);
  const { send, invoke } = useIPC();

  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [inspector, setInspector] = useState<{
    planned: PlannedInvestigationTask | null;
    runtime: InvestigationTask | undefined;
  } | null>(null);

  const tasksById = useMemo(() => {
    const m = new Map<string, InvestigationTask>();
    for (const t of investigation?.aiTasks ?? []) {
      const pid = (t as InvestigationTask & { plannedTaskId?: string }).plannedTaskId;
      if (pid) m.set(pid, t);
      m.set(t.id, t);
    }
    return m;
  }, [investigation?.aiTasks]);

  useEffect(() => {
    setInspector(null);
    setSelectedEvidenceId(null);
  }, [activeInvestigationId]);

  // Load the execution plan + pending replan recommendation for the active
  // investigation so header stats and the approve/reject controls are live.
  useEffect(() => {
    if (!activeInvestigationId) return;
    let cancelled = false;
    (async () => {
      try {
        const planResult = await invoke<InvestigationPlan | null>({
          type: 'investigation.plan',
          payload: { investigationId: activeInvestigationId },
        });
        if (!cancelled && planResult) {
          useAppStore.getState().setActiveInvestigationPlan(planResult);
        }
        const recommendation = await invoke<InvestigationEvent | null>({
          type: 'investigation.getLatestReplanRecommendation',
          payload: { investigationId: activeInvestigationId },
        });
        if (!cancelled) {
          useAppStore.getState().setActiveInvestigationRecommendation(recommendation ?? null);
        }
      } catch {
        // Plan/recommendation endpoints are best-effort; the workspace still
        // renders from the investigation record itself.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeInvestigationId, invoke]);

  const openInvestigation = useCallback(
    (id: string) => {
      void (async () => {
        try {
          const opened = await invoke<Investigation | null>({
            type: 'investigation.open',
            payload: { investigationId: id },
          });
          if (opened) {
            useAppStore.getState().upsertInvestigation(opened);
          }
        } finally {
          setActiveInvestigation(id);
        }
      })();
    },
    [invoke, setActiveInvestigation]
  );

  const onSendCommand = useCallback(
    (kind: CommandKind, payload: string) => {
      if (!investigation) return;
      switch (kind) {
        case 'pause_all':
          send({ type: 'session.stop', payload: { sessionId: '' } });
          for (const t of investigation.aiTasks) {
            if (t.status === 'STARTED') {
              invoke<{ success: boolean }>({
                type: 'investigation.pauseTask',
                payload: { plannedTaskId: (t as InvestigationTask & { plannedTaskId?: string }).plannedTaskId ?? t.id },
              });
            }
          }
          break;
        case 'resume_all':
          for (const t of investigation.aiTasks) {
            if (t.status === 'PAUSED') {
              invoke<{ success: boolean }>({
                type: 'investigation.resumeTask',
                payload: { plannedTaskId: (t as InvestigationTask & { plannedTaskId?: string }).plannedTaskId ?? t.id },
              });
            }
          }
          break;
        case 'replan':
          invoke({
            type: 'investigation.replan',
            payload: { investigationId: investigation.id },
          });
          break;
        case 'add_hypothesis':
          invoke({
            type: 'investigation.applyHumanInterruption',
            payload: {
              investigationId: investigation.id,
              kind: 'hypothesis',
              title: payload,
              statement: payload,
            },
          });
          break;
        case 'add_suspicion':
          invoke({
            type: 'investigation.applyHumanInterruption',
            payload: {
              investigationId: investigation.id,
              kind: 'suspicion',
              value: payload,
            },
          });
          break;
        case 'add_constraint':
          invoke({
            type: 'investigation.applyHumanInterruption',
            payload: {
              investigationId: investigation.id,
              kind: 'constraint',
              value: payload,
            },
          });
          break;
        case 'note':
          invoke({
            type: 'investigation.applyHumanInterruption',
            payload: {
              investigationId: investigation.id,
              kind: 'note',
              value: payload,
            },
          });
          break;
        case 'message':
          invoke({
            type: 'investigation.applyHumanInterruption',
            payload: {
              investigationId: investigation.id,
              kind: 'directive',
              value: payload,
            },
          });
          break;
      }
    },
    [investigation, invoke, send]
  );

  // All hooks have run — the list view is rendered when no investigation is
  // active. (Early returns must come after every hook call.)
  if (!investigation) {
    return (
      <div
        className="flex-1 min-h-0 flex flex-col"
        style={{ background: 'var(--soc-bg-canvas)' }}
      >
        <InvestigationsList onSelect={openInvestigation} />
      </div>
    );
  }

  const onPauseTask = (taskId: string) =>
    invoke<{ success: boolean }>({
      type: 'investigation.pauseTask',
      payload: { plannedTaskId: taskId },
    });
  const onResumeTask = (taskId: string) =>
    invoke<{ success: boolean }>({
      type: 'investigation.resumeTask',
      payload: { plannedTaskId: taskId },
    });
  const onCancelTask = (taskId: string) =>
    invoke<{ success: boolean }>({
      type: 'investigation.cancelTask',
      payload: { plannedTaskId: taskId, reason: 'Cancelled by human' },
    });
  const onReprioritizeTask = (taskId: string, priority: number) =>
    invoke<{ success: boolean }>({
      type: 'investigation.reprioritizeTask',
      payload: { plannedTaskId: taskId, priority, rationale: 'Adjusted from workspace' },
    });
  const onRedirectTask = (taskId: string) =>
    invoke<{ success: boolean }>({
      type: 'investigation.redirectTask',
      payload: { plannedTaskId: taskId },
    });
  const onAddHypothesis = (title: string, statement: string) =>
    invoke({
      type: 'investigation.applyHumanInterruption',
      payload: { investigationId: investigation.id, kind: 'hypothesis', title, statement },
    });
  const onPromoteHypothesis = (id: string) =>
    invoke({
      type: 'investigation.applyHumanInterruption',
      payload: { investigationId: investigation.id, kind: 'promote_hypothesis', hypothesisId: id },
    });
  const onRejectHypothesis = (id: string) =>
    invoke({
      type: 'investigation.applyHumanInterruption',
      payload: { investigationId: investigation.id, kind: 'reject_hypothesis', hypothesisId: id },
    });
  const onSetRiskTolerance = (level: 'LOW' | 'MEDIUM' | 'HIGH') =>
    invoke({
      type: 'investigation.applyHumanInterruption',
      payload: { investigationId: investigation.id, kind: 'risk_tolerance', value: level },
    });
  const onAddContext = (kind: 'note' | 'suspicion' | 'direction' | 'constraint', value: string) =>
    invoke({
      type: 'investigation.applyHumanInterruption',
      payload: { investigationId: investigation.id, kind, value },
    });
  const onExecute = () =>
    invoke({
      type: 'investigation.execute',
      payload: { investigationId: investigation.id },
    });
  const onReplan = () =>
    invoke({
      type: 'investigation.replan',
      payload: { investigationId: investigation.id },
    });
  const onArchive = () =>
    invoke({
      type: 'investigation.archive',
      payload: { investigationId: investigation.id },
    });

  return (
    <div
      className="flex-1 min-h-0 flex flex-col overflow-hidden"
      style={{ background: 'var(--soc-bg-canvas)' }}
    >
      <div
        className="flex items-center gap-2 px-5 py-2 border-b"
        style={{
          background: 'var(--soc-bg-primary)',
          borderColor: 'var(--soc-border-subtle)',
        }}
      >
        <button
          onClick={() => setActiveInvestigation(null)}
          className="inline-flex items-center gap-1 text-[11.5px] font-semibold"
          style={{ color: 'var(--soc-text-muted)' }}
        >
          <ChevronLeft className="w-3.5 h-3.5" /> Investigations
        </button>
        <span style={{ color: 'var(--soc-text-disabled)' }}>/</span>
        <span
          className="text-[11.5px] truncate"
          style={{ color: 'var(--soc-text-secondary)' }}
        >
          {investigation.title}
        </span>
      </div>

      <InvestigationHeader
        investigation={investigation}
        onPauseAll={() => onSendCommand('pause_all', '')}
        onResumeAll={() => onSendCommand('resume_all', '')}
        onReplan={onReplan}
        onArchive={onArchive}
        onExecute={onExecute}
      />

      <div
        className="flex-1 min-h-0 grid relative"
        style={{
          gridTemplateColumns: '320px 1fr 360px',
          gridTemplateRows: 'minmax(0, 1fr) auto',
        }}
      >
        <div
          className="row-span-1 border-r overflow-hidden"
          style={{ borderColor: 'var(--soc-border-subtle)' }}
        >
          <div className="h-full p-3 grid gap-3" style={{ gridTemplateRows: 'auto minmax(0, 1fr)' }}>
            <HumanContextPanel
              investigation={investigation}
              onAddNote={(v) => onAddContext('note', v)}
              onAddSuspicion={(v) => onAddContext('suspicion', v)}
              onAddDirection={(v) => onAddContext('direction', v)}
              onAddConstraint={(v) => onAddContext('constraint', v)}
              onSetRiskTolerance={onSetRiskTolerance}
            />
            <div className="min-h-0 grid gap-3" style={{ gridTemplateRows: 'minmax(0, 1.2fr) minmax(0, 1fr) minmax(0, 1fr)' }}>
            <AITeamPanel
              investigation={investigation}
              plan={plan}
              onInspectTask={(planned, runtime) => setInspector({ planned, runtime })}
            />
              <ChallengerFindingsPanel investigation={investigation} />
              <OpenQuestionsPanel investigation={investigation} />
            </div>
          </div>
        </div>

        <div className="row-span-1 overflow-hidden">
          <div className="h-full p-3 grid gap-3" style={{ gridTemplateRows: 'minmax(0, 1.4fr) minmax(0, 1fr)' }}>
            <TaskBoard
              investigation={investigation}
              plan={plan}
              tasksById={tasksById}
              onPauseTask={onPauseTask}
              onResumeTask={onResumeTask}
              onCancelTask={onCancelTask}
              onReprioritizeTask={onReprioritizeTask}
              onRedirectTask={onRedirectTask}
            />
            <div className="min-h-0 grid gap-3" style={{ gridTemplateColumns: '1.4fr 1fr' }}>
              <EvidenceFeed
                investigation={investigation}
                onSelectEvidence={(ev) => setSelectedEvidenceId(ev.id)}
                selectedEvidenceId={selectedEvidenceId}
              />
              <div className="min-h-0 grid gap-3" style={{ gridTemplateRows: 'minmax(0, 1fr) minmax(0, 1fr)' }}>
                <EvidenceGraph investigation={investigation} />
                <AISynthesisPanel investigation={investigation} />
              </div>            </div>
          </div>
        </div>

        <div
          className="row-span-1 border-l overflow-hidden"
          style={{ borderColor: 'var(--soc-border-subtle)' }}
        >
          <div className="h-full p-3 grid gap-3" style={{ gridTemplateRows: 'minmax(0, 1.4fr) minmax(0, 1fr)' }}>
            <HypothesesPanel
              investigation={investigation}
              onAddHypothesis={onAddHypothesis}
              onPromote={onPromoteHypothesis}
              onReject={onRejectHypothesis}
            />
            <Timeline investigation={investigation} />
          </div>
        </div>

        <div className="col-span-3 row-start-2">
          <div className="grid gap-3 p-3" style={{ gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)' }}>
            <HumanCommandBar
              investigation={investigation}
              onSendCommand={onSendCommand}
              onApproveReplan={
                recommendation
                  ? () => invoke({ type: 'investigation.replan', payload: { investigationId: investigation.id } })
                  : undefined
              }
              onRejectReplan={
                recommendation
                  ? () =>
                      invoke({
                        type: 'investigation.applyHumanInterruption',
                        payload: { investigationId: investigation.id, kind: 'reject_replan' },
                      })
                  : undefined
              }
            />
            <InvestigationReportPanel investigationId={investigation.id} />
          </div>
        </div>

        {inspector && (
          <WorkerInspector
            investigation={investigation}
            planned={inspector.planned}
            runtime={inspector.runtime}
            onClose={() => setInspector(null)}
            onPause={onPauseTask}
            onResume={onResumeTask}
            onCancel={onCancelTask}
            onRedirect={onRedirectTask}
            onReprioritize={onReprioritizeTask}
          />
        )}
      </div>
    </div>
  );
}

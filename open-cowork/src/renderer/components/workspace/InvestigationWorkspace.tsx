import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ChevronLeft,
} from 'lucide-react';
import type {
  InvestigationTask,
} from '../../../shared/cyber/investigation-types';
import type { PlannedInvestigationTask } from '../../../main/investigation/parallel-investigation-engine';
import { useAppStore } from '../../store';
import { useIPC } from '../../hooks/useIPC';
import {
  useActiveInvestigation,
  useActiveInvestigationId,
  useActiveInvestigationPlan,
  useActiveInvestigationRecommendation,
} from '../../store/selectors';
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

  if (!investigation) {
    return (
      <div
        className="flex-1 min-h-0 flex items-center justify-center"
        style={{ background: 'var(--soc-bg-canvas)', color: 'var(--soc-text-muted)' }}
      >
        <div className="flex flex-col items-center gap-2 text-center px-6">
          <Activity className="w-6 h-6" />
          <div className="text-[13px]">No investigation selected</div>
          <button
            onClick={() => setActiveInvestigation(null)}
            className="text-[12px] underline"
            style={{ color: 'var(--soc-text-secondary)' }}
          >
            Back
          </button>
        </div>
      </div>
    );
  }

  const onSendCommand = useCallback(
    (kind: CommandKind, payload: string) => {
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
            } as any,
          });
          break;
        case 'add_suspicion':
          invoke({
            type: 'investigation.applyHumanInterruption',
            payload: {
              investigationId: investigation.id,
              kind: 'suspicion',
              value: payload,
            } as any,
          });
          break;
        case 'add_constraint':
          invoke({
            type: 'investigation.applyHumanInterruption',
            payload: {
              investigationId: investigation.id,
              kind: 'constraint',
              value: payload,
            } as any,
          });
          break;
        case 'note':
          invoke({
            type: 'investigation.applyHumanInterruption',
            payload: {
              investigationId: investigation.id,
              kind: 'note',
              value: payload,
            } as any,
          });
          break;
        case 'message':
          invoke({
            type: 'investigation.applyHumanInterruption',
            payload: {
              investigationId: investigation.id,
              kind: 'directive',
              value: payload,
            } as any,
          });
          break;
      }
    },
    [investigation, invoke, send]
  );

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
      payload: { investigationId: investigation.id, kind: 'hypothesis', title, statement } as any,
    });
  const onPromoteHypothesis = (id: string) =>
    invoke({
      type: 'investigation.applyHumanInterruption',
      payload: { investigationId: investigation.id, kind: 'promote_hypothesis', hypothesisId: id } as any,
    });
  const onRejectHypothesis = (id: string) =>
    invoke({
      type: 'investigation.applyHumanInterruption',
      payload: { investigationId: investigation.id, kind: 'reject_hypothesis', hypothesisId: id } as any,
    });
  const onSetRiskTolerance = (level: 'LOW' | 'MEDIUM' | 'HIGH') =>
    invoke({
      type: 'investigation.applyHumanInterruption',
      payload: { investigationId: investigation.id, kind: 'risk_tolerance', value: level } as any,
    });
  const onAddContext = (kind: 'note' | 'suspicion' | 'direction' | 'constraint', value: string) =>
    invoke({
      type: 'investigation.applyHumanInterruption',
      payload: { investigationId: investigation.id, kind, value } as any,
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
                        payload: { investigationId: investigation.id, kind: 'reject_replan' } as any,
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

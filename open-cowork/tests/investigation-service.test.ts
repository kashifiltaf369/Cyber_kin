import { describe, expect, it, vi } from 'vitest';
import type { DatabaseInstance } from '../src/main/db/database';
import { InvestigationService } from '../src/main/investigation/investigation-service';
import type { InvestigationEventRow, InvestigationRow } from '../src/main/db/database';
import type { ServerEvent } from '../src/renderer/types';

function makeDb() {
  const investigations = new Map<string, InvestigationRow>();
  const events = new Map<string, InvestigationEventRow[]>();

  const db: DatabaseInstance = {
    raw: {} as never,
    investigations: {
      create: vi.fn((row: InvestigationRow) => {
        investigations.set(row.id, { ...row });
      }),
      update: vi.fn((id: string, updates: Partial<InvestigationRow>) => {
        const current = investigations.get(id);
        if (!current) return;
        investigations.set(id, { ...current, ...updates, updated_at: Date.now() });
      }),
      get: vi.fn((id: string) => investigations.get(id)),
      getAll: vi.fn(() => Array.from(investigations.values()).sort((a, b) => b.updated_at - a.updated_at)),
      delete: vi.fn((id: string) => {
        investigations.delete(id);
        events.delete(id);
      }),
    },
    investigationEvents: {
      create: vi.fn((row: InvestigationEventRow) => {
        const list = events.get(row.investigation_id) || [];
        list.push({ ...row });
        events.set(row.investigation_id, list);
      }),
      getByInvestigationId: vi.fn((id: string) => (events.get(id) || []).slice().sort((a, b) => a.created_at - b.created_at)),
      deleteByInvestigationId: vi.fn((id: string) => {
        events.delete(id);
      }),
    },
    investigationSessionLinks: {
      link: vi.fn(),
      getInvestigationIdBySessionId: vi.fn(() => null),
      getSessionLinksByInvestigationId: vi.fn(() => []),
      deleteBySessionId: vi.fn(),
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

  return { db, investigations, events };
}

describe('InvestigationService', () => {
  it('creates an investigation and emits lifecycle events', () => {
    const { db } = makeDb();
    const sent: ServerEvent[] = [];
    const service = new InvestigationService(db, (event) => sent.push(event));

    const investigation = service.create({
      title: 'Investigate suspicious login',
      objective: 'Determine if login was malicious',
      humanContext: 'VPN logs available',
      riskTolerance: 'MEDIUM',
      hypotheses: [{ title: 'Credential theft', statement: 'The login used stolen creds', confidence: 0.6 }],
      openQuestions: ['Was MFA bypassed?'],
    });

    expect(investigation.title).toBe('Investigate suspicious login');
    expect(investigation.status).toBe('CREATED');
    expect(investigation.hypotheses).toHaveLength(1);
    expect(investigation.openQuestions).toEqual(['Was MFA bypassed?']);
    expect(investigation.humanCapabilityContext.riskTolerance).toBe('MEDIUM');
    expect(investigation.activity.map((item) => item.type)).toContain('INVESTIGATION_CREATED');
    expect(investigation.activity.map((item) => item.type)).toContain('HYPOTHESIS_CREATED');
    expect(investigation.activity.map((item) => item.type)).toContain('OPEN_QUESTION_ADDED');
    expect(sent.some((event) => event.type === 'investigation.event')).toBe(true);
  });

  it('supports open, resume, and archive lifecycle operations', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Obj' });

    const opened = service.open(created.id);
    expect(opened.activity.at(-1)?.type).toBe('INVESTIGATION_OPENED');

    const resumed = service.resume(created.id);
    expect(resumed.status).toBe('INVESTIGATING');
    expect(resumed.activity.map((item) => item.type)).toContain('INVESTIGATION_RESUMED');
    expect(resumed.activity.map((item) => item.type)).toContain('INVESTIGATION_STATUS_CHANGED');

    const archived = service.archive(created.id);
    expect(archived.status).toBe('ARCHIVED');
    expect(archived.activity.at(-1)?.type).toBe('INVESTIGATION_ARCHIVED');
  });

  it('records evidence, hypotheses, tasks, decisions, conclusions, and entities as events', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Obj' });

    service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'Auth log excerpt',
      source: 'idp-signin.log',
      timestamp: Date.now() - 1_000,
      investigator: 'Identity Investigator',
      relatedEntityIds: [],
      content: 'Login from unusual IP',
      confidence: 0.7,
      provenance: {
        method: 'tool_output',
        sourceType: 'log',
        sourceLabel: 'Identity provider sign-in log',
        collectedBy: 'Identity Investigator',
        capability: 'search_identity_activity',
      },
      kind: 'log_excerpt',
      summary: 'Login from unusual IP',
      hypothesisIds: [],
      tags: ['auth'],
    });
    const withHypothesis = service.addHypothesis(created.id, {
      title: 'Password spray',
      statement: 'Could be password spray',
      confidence: 0.4,
    });
    const hypothesisId = withHypothesis.hypotheses.at(-1)?.id as string;
    service.updateHypothesis(created.id, hypothesisId, { status: 'SUPPORTED', confidence: 0.7 });
    const withTask = service.addTask(created.id, {
      title: 'Check IdP logs',
      description: 'Review sign-in events',
      type: 'AI',
      owner: 'worker-1',
      status: 'STARTED',
    });
    const taskId = withTask.aiTasks[0].id;
    service.updateTask(created.id, taskId, { status: 'COMPLETED' });
    service.addDecision(created.id, { summary: 'Limit scope to tenant A' });
    service.upsertConclusion(created.id, {
      summary: 'Likely compromised account',
      confidence: 0.8,
      derivedFromHypothesisIds: [hypothesisId],
      derivedFromEvidenceIds: [service.get(created.id)?.evidence[0]?.id as string],
    });
    const finalState = service.addEntity(created.id, { name: '203.0.113.7', type: 'ip', summary: 'Suspect IP' });

    expect(finalState.evidence).toHaveLength(1);
    expect(finalState.evidence[0]?.type).toBe('OBSERVATION');
    expect(finalState.evidence[0]?.provenance.capability).toBe('search_identity_activity');
    expect(finalState.hypotheses).toHaveLength(1);
    expect(finalState.aiTasks).toHaveLength(1);
    expect(finalState.decisions).toHaveLength(1);
    expect(finalState.conclusions).toHaveLength(1);
    expect(finalState.conclusions[0]?.derivedFromHypothesisIds).toEqual([hypothesisId]);
    expect(finalState.entities).toHaveLength(1);
    expect(finalState.activity.map((item) => item.type)).toContain('EVIDENCE_ADDED');
    expect(finalState.activity.map((item) => item.type)).toContain('HYPOTHESIS_UPDATED');
    expect(finalState.activity.map((item) => item.type)).toContain('TASK_CREATED');
    expect(finalState.activity.map((item) => item.type)).toContain('TASK_STARTED');
    expect(finalState.activity.map((item) => item.type)).toContain('TASK_COMPLETED');
    expect(finalState.activity.map((item) => item.type)).toContain('DECISION_ADDED');
    expect(finalState.activity.map((item) => item.type)).toContain('CONCLUSION_UPDATED');
    expect(finalState.activity.map((item) => item.type)).toContain('ENTITY_ADDED');
  });

  it('stores structured human capability context and emits events', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Obj' });

    service.addHumanContext(created.id, {
      environmentalKnowledge: ['This organization uses PowerShell heavily.'],
      suspicions: ['Possible credential theft'],
      knownLegitimateBehavior: ['Routine admin PowerShell remoting'],
      knownAbnormalBehavior: ['Unexpected overnight interactive logons'],
      notes: ['Treat admin jump host as high-value context'],
      riskTolerance: 'LOW',
      importantEntities: [{ name: 'Admin-Jump-01', type: 'host', summary: 'Tier-0 jump host' }],
    });
    service.addConstraint(created.id, 'Do not treat PowerShell alone as malicious.');
    service.addPriority(created.id, 'Investigate lateral movement.');
    service.addDecision(created.id, {
      summary: 'Focus on authentication and admin activity first',
      rationale: 'Most likely initial attack path',
    });
    service.addNote(created.id, 'Human analyst suspects staging via VPN access.');
    const redirected = service.redirectInvestigation(created.id, 'Pivot toward identity compromise analysis.');

    expect(redirected.status).toBe('REPLANNING');
    expect(redirected.humanCapabilityContext.environmentalKnowledge).toContain(
      'This organization uses PowerShell heavily.'
    );
    expect(redirected.humanCapabilityContext.constraints[0].value).toBe(
      'Do not treat PowerShell alone as malicious.'
    );
    expect(redirected.humanCapabilityContext.priorities[0].value).toBe(
      'Investigate lateral movement.'
    );
    expect(redirected.humanCapabilityContext.suspicions[0].value).toBe('Possible credential theft');
    expect(redirected.humanCapabilityContext.knownLegitimateBehavior[0].value).toBe(
      'Routine admin PowerShell remoting'
    );
    expect(redirected.humanCapabilityContext.knownAbnormalBehavior[0].value).toBe(
      'Unexpected overnight interactive logons'
    );
    expect(redirected.humanCapabilityContext.riskTolerance).toBe('LOW');
    expect(redirected.humanCapabilityContext.importantEntities[0].name).toBe('Admin-Jump-01');
    expect(redirected.humanCapabilityContext.investigationDirections[0].value).toBe(
      'Pivot toward identity compromise analysis.'
    );
    expect(redirected.humanCapabilityContext.notes.map((item) => item.value)).toContain(
      'Treat admin jump host as high-value context'
    );
    expect(redirected.humanCapabilityContext.notes.map((item) => item.value)).toContain(
      'Human analyst suspects staging via VPN access.'
    );
    expect(service.getHumanContext(created.id).riskTolerance).toBe('LOW');
    expect(redirected.activity.map((item) => item.type)).toContain('HUMAN_CONTEXT_ADDED');
    expect(redirected.activity.map((item) => item.type)).toContain('CONSTRAINT_ADDED');
    expect(redirected.activity.map((item) => item.type)).toContain('PRIORITY_ADDED');
    expect(redirected.activity.map((item) => item.type)).toContain('DECISION_ADDED');
    expect(redirected.activity.map((item) => item.type)).toContain('NOTE_ADDED');
    expect(redirected.activity.map((item) => item.type)).toContain('AGENT_REDIRECTED');
  });

  it('supports structured evidence relationships, provenance, annotations, and retrieval', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Obj' });

    const withEntity = service.addEntity(created.id, {
      name: 'WINWORD.EXE',
      type: 'process',
      summary: 'Office parent process',
    });
    const entityId = withEntity.entities[0].id;

    const withHypothesis = service.addHypothesis(created.id, {
      title: 'Malicious document execution',
      statement: 'A document triggered malicious PowerShell execution',
      confidence: 0.65,
    });
    const hypothesisId = withHypothesis.hypotheses[0].id;

    const withTask = service.addTask(created.id, {
      title: 'Review process tree',
      description: 'Check parent-child execution chain',
      type: 'AI',
      owner: 'endpoint-worker',
      status: 'STARTED',
    });
    const taskId = withTask.aiTasks[0].id;

    let state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'PowerShell spawned by WINWORD.EXE',
      source: 'process-tree.json',
      timestamp: 1_700_000_000_000,
      collectedAt: 1_700_000_000_100,
      investigator: 'Endpoint Investigator',
      relatedEntityIds: [entityId],
      content: 'PowerShell was launched as a child process of WINWORD.EXE.',
      confidence: 0.92,
      provenance: {
        method: 'tool_output',
        sourceType: 'file',
        sourceId: 'artifact-1',
        sourceLabel: 'Process tree export',
        collectedBy: 'Endpoint Investigator',
        capability: 'search_processes',
      },
      supportingTaskId: taskId,
      hypothesisIds: [hypothesisId],
      kind: 'structured_record',
      summary: 'Word spawned PowerShell',
      tags: ['process-tree', 'powershell', 'office'],
    });
    const observationId = state.evidence[0].id;

    state = service.addEvidence(created.id, {
      type: 'INFERENCE',
      title: 'Execution chain is unusual',
      source: 'analysis',
      timestamp: 1_700_000_000_200,
      collectedAt: 1_700_000_000_250,
      investigator: 'Evidence Analyst',
      relatedEntityIds: [entityId],
      content: 'WINWORD.EXE spawning PowerShell is unusual in this context.',
      confidence: 0.78,
      provenance: {
        method: 'derived_analysis',
        sourceType: 'task_result',
        sourceLabel: 'Process chain assessment',
        collectedBy: 'Evidence Analyst',
      },
      supportingTaskId: taskId,
      hypothesisIds: [hypothesisId],
      kind: 'note',
      summary: 'Unusual execution chain',
      tags: ['inference'],
    });
    const inferenceId = state.evidence.find((item) => item.title === 'Execution chain is unusual')?.id as string;

    state = service.linkEvidence(created.id, inferenceId, {
      type: 'DERIVED_FROM',
      targetEvidenceId: observationId,
      supportingTaskId: taskId,
      rationale: 'Inference derives from observed process ancestry',
      createdBy: 'agent',
    });
    state = service.linkEvidence(created.id, observationId, {
      type: 'ABOUT_ENTITY',
      targetEntityId: entityId,
      rationale: 'Observation concerns WINWORD.EXE execution chain',
      createdBy: 'agent',
    });
    state = service.linkEvidence(created.id, inferenceId, {
      type: 'ABOUT_HYPOTHESIS',
      targetHypothesisId: hypothesisId,
      rationale: 'Inference informs malicious document hypothesis',
      createdBy: 'agent',
    });
    state = service.annotateEvidence(created.id, observationId, {
      note: 'Human notes that this org rarely launches PowerShell from Office.',
      author: 'human',
    });

    state = service.applyEvidenceToHypothesis(created.id, {
      hypothesisId,
      evidenceId: observationId,
      relationship: 'SUPPORTS',
      rationale: 'Observed process ancestry supports the hypothesis',
      actor: 'agent',
    });

    const entityEvidence = service.getEvidenceForEntity(created.id, entityId);
    const hypothesisEvidence = service.getEvidenceForHypothesis(created.id, hypothesisId);
    const timeline = service.getEvidenceTimeline(created.id);

    expect(state.evidence).toHaveLength(2);
    expect(state.evidence.find((item) => item.id === observationId)?.analystAnnotations).toHaveLength(1);
    expect(
      state.evidence.find((item) => item.id === inferenceId)?.relationships.some(
        (relationship) => relationship.type === 'DERIVED_FROM' && relationship.targetEvidenceId === observationId
      )
    ).toBe(true);
    expect(entityEvidence).toHaveLength(2);
    expect(hypothesisEvidence).toHaveLength(2);
    expect(timeline.map((item) => item.id)).toEqual([observationId, inferenceId]);
    expect(state.hypotheses.find((item) => item.id === hypothesisId)?.status).toBe('SUPPORTED');
    expect(state.hypotheses.find((item) => item.id === hypothesisId)?.confidence).toBe(0.8);
    expect(state.evidence.find((item) => item.id === observationId)?.relationships.some((item) => item.type === 'SUPPORTS')).toBe(true);
    expect(state.activity.map((item) => item.type)).toContain('EVIDENCE_LINKED');
    expect(state.activity.map((item) => item.type)).toContain('EVIDENCE_ANNOTATED');
    expect(state.activity.filter((item) => item.type === 'HYPOTHESIS_UPDATED').length).toBeGreaterThan(0);
  });

  it('derives conclusions from investigation state through explicit domain logic', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Obj' });
    const withHypothesis = service.addHypothesis(created.id, {
      title: 'Malicious document execution',
      statement: 'A document triggered suspicious execution',
      confidence: 0.7,
    });
    const hypothesisId = withHypothesis.hypotheses[0].id;
    let state = service.updateHypothesis(created.id, hypothesisId, {
      status: 'SUPPORTED',
      confidence: 0.8,
    });
    state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'PowerShell spawned by WINWORD.EXE',
      source: 'process-tree.json',
      timestamp: 100,
      investigator: 'Endpoint Investigator',
      relatedEntityIds: [],
      content: 'PowerShell child process of Word',
      confidence: 0.9,
      provenance: { method: 'tool_output', sourceType: 'file' },
      kind: 'structured_record',
      summary: 'Observed suspicious process ancestry',
      hypothesisIds: [hypothesisId],
      tags: [],
    });
    const evidenceId = state.evidence[0].id;
    state = service.deriveConclusionFromState(created.id, {
      hypothesisIds: [hypothesisId],
      evidenceIds: [evidenceId],
      rationale: 'Supported hypothesis and direct endpoint observation',
    });

    expect(state.conclusions).toHaveLength(1);
    expect(state.conclusions[0]?.derivedFromHypothesisIds).toEqual([hypothesisId]);
    expect(state.conclusions[0]?.derivedFromEvidenceIds).toEqual([evidenceId]);
    expect(state.conclusions[0]?.summary).toContain('Malicious document execution');
    expect(state.activity.map((item) => item.type)).toContain('CONCLUSION_UPDATED');
  });

  it('synthesizes reasoning across evidence, hypotheses, and conclusions', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Obj' });
    let state = service.addHypothesis(created.id, {
      title: 'Malicious document execution',
      statement: 'Office triggered malicious execution',
      confidence: 0.5,
    });
    const hypothesisId = state.hypotheses[0].id;
    state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'PowerShell spawned by WINWORD.EXE',
      source: 'process-tree.json',
      timestamp: 100,
      investigator: 'Endpoint Investigator',
      relatedEntityIds: [],
      content: 'Word spawned PowerShell',
      confidence: 0.9,
      provenance: { method: 'tool_output', sourceType: 'file' },
      kind: 'structured_record',
      summary: 'Observed suspicious parent-child chain',
      hypothesisIds: [],
      tags: [],
    });
    const evidenceId = state.evidence[0].id;

    state = service.synthesizeReasoning(created.id, {
      assessments: [
        {
          hypothesisId,
          evidenceId,
          relationship: 'SUPPORTS',
          rationale: 'Observed ancestry supports likely malicious execution',
          actor: 'agent',
        },
      ],
      conclusion: {
        hypothesisIds: [hypothesisId],
        evidenceIds: [evidenceId],
      },
    });

    expect(state.hypotheses[0]?.status).toBe('SUPPORTED');
    expect(state.conclusions[0]?.derivedFromHypothesisIds).toEqual([hypothesisId]);
    expect(state.conclusions[0]?.derivedFromEvidenceIds).toEqual([evidenceId]);
    expect(state.activity.filter((item) => item.type === 'HYPOTHESIS_UPDATED').length).toBeGreaterThan(0);
    expect(state.activity.filter((item) => item.type === 'CONCLUSION_UPDATED').length).toBeGreaterThan(0);
  });

  it('lists and fetches persisted investigations', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const first = service.create({ title: 'First', objective: 'One' });
    const second = service.create({ title: 'Second', objective: 'Two' });

    const list = service.list();
    expect(list).toHaveLength(2);
    expect(list.map((item) => item.id)).toEqual(expect.arrayContaining([first.id, second.id]));
    expect(service.get(first.id)?.title).toBe('First');
    expect(service.get('missing')).toBeNull();
  });

  it('stores a queryable evidence graph with evidence-backed relationships', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Obj' });

    let state = service.addEntity(created.id, {
      name: 'powershell.exe',
      type: 'process',
      summary: 'Suspicious PowerShell process',
    });
    state = service.addEntity(created.id, {
      name: 'Workstation-22',
      type: 'host',
      summary: 'Endpoint host',
    });
    state = service.addEntity(created.id, {
      name: '203.0.113.50',
      type: 'ip',
      summary: 'Remote IP',
    });
    state = service.addEntity(created.id, {
      name: 'svc-backup',
      type: 'account',
      summary: 'Service account',
    });
    state = service.addEntity(created.id, {
      name: 'Server-03',
      type: 'host',
      summary: 'Authenticated target',
    });

    const processId = state.entities.find((item) => item.name === 'powershell.exe')?.id as string;
    const workstationId = state.entities.find((item) => item.name === 'Workstation-22')?.id as string;
    const remoteIpId = state.entities.find((item) => item.name === '203.0.113.50')?.id as string;
    const accountId = state.entities.find((item) => item.name === 'svc-backup')?.id as string;
    const serverId = state.entities.find((item) => item.name === 'Server-03')?.id as string;

    state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'Process observed on workstation',
      source: 'process telemetry',
      timestamp: 1_000,
      investigator: 'Endpoint Investigator',
      relatedEntityIds: [processId, workstationId],
      content: 'powershell.exe executed on Workstation-22',
      confidence: 0.93,
      provenance: {
        method: 'tool_output',
        sourceType: 'log',
      },
      hypothesisIds: [],
      kind: 'structured_record',
      summary: 'Execution observed',
      tags: ['process'],
    });
    state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'Remote connection observed',
      source: 'netflow',
      timestamp: 1_005,
      investigator: 'Network Investigator',
      relatedEntityIds: [processId, remoteIpId],
      content: 'powershell.exe connected to 203.0.113.50',
      confidence: 0.89,
      provenance: {
        method: 'tool_output',
        sourceType: 'log',
      },
      hypothesisIds: [],
      kind: 'structured_record',
      summary: 'Network connection observed',
      tags: ['network'],
    });
    state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'Account logged into host',
      source: 'auth log',
      timestamp: 2_000,
      investigator: 'Identity Investigator',
      relatedEntityIds: [accountId, serverId],
      content: 'svc-backup authenticated to Server-03',
      confidence: 0.86,
      provenance: {
        method: 'tool_output',
        sourceType: 'log',
      },
      hypothesisIds: [],
      kind: 'structured_record',
      summary: 'Authentication observed',
      tags: ['identity'],
    });

    const execEvidenceId = state.evidence.find((item) => item.title === 'Process observed on workstation')?.id as string;
    const netEvidenceId = state.evidence.find((item) => item.title === 'Remote connection observed')?.id as string;
    const authEvidenceId = state.evidence.find((item) => item.title === 'Account logged into host')?.id as string;

    state = service.addGraphRelationship(created.id, {
      type: 'EXECUTED',
      sourceEntityId: processId,
      targetEntityId: workstationId,
      source: 'process telemetry',
      timestamp: 1_000,
      confidence: 0.93,
      evidenceIds: [execEvidenceId],
      investigator: 'Endpoint Investigator',
    });
    state = service.addGraphRelationship(created.id, {
      type: 'CONNECTED_TO',
      sourceEntityId: processId,
      targetEntityId: remoteIpId,
      source: 'netflow',
      timestamp: 1_005,
      confidence: 0.89,
      evidenceIds: [netEvidenceId],
      investigator: 'Network Investigator',
    });
    state = service.addGraphRelationship(created.id, {
      type: 'AUTHENTICATED_TO',
      sourceEntityId: accountId,
      targetEntityId: serverId,
      source: 'auth log',
      timestamp: 2_000,
      confidence: 0.86,
      evidenceIds: [authEvidenceId],
      investigator: 'Identity Investigator',
    });

    const graph = service.getGraph(created.id);
    const processNeighbors = service.findConnectedEntities(created.id, {
      entityId: processId,
      direction: 'outbound',
    });
    const nearProcess = service.findEntitiesConnectedWithinTimeWindow(created.id, {
      entityId: processId,
      withinMs: 10,
      direction: 'both',
    });
    const accountRelationships = service.getGraphRelationshipsForEntity(created.id, {
      entityId: accountId,
      direction: 'outbound',
      relationshipTypes: ['AUTHENTICATED_TO'],
    });
    const supportingEvidence = service.getEvidenceForGraphRelationship(created.id, accountRelationships[0].id);

    expect(graph.relationships).toHaveLength(3);
    expect(processNeighbors.map((item) => item.entity.name).sort()).toEqual(['203.0.113.50', 'Workstation-22']);
    expect(nearProcess.map((item) => item.entity.name).sort()).toEqual(['203.0.113.50', 'Workstation-22']);
    expect(accountRelationships).toHaveLength(1);
    expect(accountRelationships[0].targetEntityId).toBe(serverId);
    expect(supportingEvidence.map((item) => item.id)).toEqual([authEvidenceId]);
    expect(state.activity.map((item) => item.type)).toContain('GRAPH_RELATIONSHIP_ADDED');
  });

  it('supports competing hypotheses, challenger review, and explicit confidence assessment', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Obj' });

    let state = service.addHypothesis(created.id, {
      title: 'Credential theft',
      statement: 'Stolen credentials were used for the login activity',
      confidence: 0.55,
      assumptions: ['Assume impossible travel indicates compromise'],
      unresolvedQuestions: ['Was MFA challenged?'],
      createdBy: 'human',
    });
    state = service.addHypothesis(created.id, {
      title: 'Administrative maintenance',
      statement: 'Observed activity is part of routine administrator maintenance',
      confidence: 0.45,
      assumptions: ['Known admin scripts may explain the behavior'],
      unresolvedQuestions: ['Was there a scheduled maintenance window?'],
      createdBy: 'human',
    });

    const theftHypothesis = state.hypotheses.find((item) => item.title === 'Credential theft');
    const maintenanceHypothesis = state.hypotheses.find((item) => item.title === 'Administrative maintenance');
    const theftId = theftHypothesis?.id as string;
    const maintenanceId = maintenanceHypothesis?.id as string;

    state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'Successful login from unusual geography',
      source: 'signin.log',
      timestamp: 100,
      investigator: 'Identity Investigator',
      relatedEntityIds: [],
      content: 'A successful login occurred from an unusual country.',
      confidence: 0.88,
      provenance: { method: 'tool_output', sourceType: 'log' },
      hypothesisIds: [],
      kind: 'log_excerpt',
      summary: 'Unusual geography login',
      tags: ['identity'],
    });
    state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'Approved maintenance window recorded',
      source: 'change-record',
      timestamp: 120,
      investigator: 'Historical Investigator',
      relatedEntityIds: [],
      content: 'A documented admin maintenance window overlaps observed activity.',
      confidence: 0.81,
      provenance: { method: 'imported', sourceType: 'file' },
      hypothesisIds: [],
      kind: 'note',
      summary: 'Maintenance window overlaps activity',
      tags: ['history'],
    });

    const unusualLoginEvidenceId = state.evidence.find((item) => item.title === 'Successful login from unusual geography')?.id as string;
    const maintenanceEvidenceId = state.evidence.find((item) => item.title === 'Approved maintenance window recorded')?.id as string;

    state = service.addSupportingEvidence(
      created.id,
      theftId,
      unusualLoginEvidenceId,
      'Unusual geography supports credential theft',
      'agent'
    );
    state = service.addContradictingEvidence(
      created.id,
      theftId,
      maintenanceEvidenceId,
      'Maintenance context weakens direct compromise attribution',
      'agent'
    );
    state = service.addSupportingEvidence(
      created.id,
      maintenanceId,
      maintenanceEvidenceId,
      'Scheduled maintenance supports benign explanation',
      'agent'
    );
    state = service.promoteHypothesis(created.id, maintenanceId);
    state = service.updateHypothesisConfidence(created.id, theftId, 0.42);

    const comparison = service.compareHypotheses(created.id);
    const challenge = service.challengeHypotheses(created.id);

    expect(state.hypotheses).toHaveLength(2);
    expect(state.hypotheses.find((item) => item.id === theftId)?.supportingEvidenceIds).toContain(unusualLoginEvidenceId);
    expect(state.hypotheses.find((item) => item.id === theftId)?.contradictingEvidenceIds).toContain(maintenanceEvidenceId);
    expect(state.hypotheses.find((item) => item.id === theftId)?.confidenceAssessment).toBe('MEDIUM');
    expect(state.hypotheses.find((item) => item.id === maintenanceId)?.status).toBe('PROMOTED');
    expect(comparison.ranked).toHaveLength(2);
    expect(comparison.leadingHypothesisId).toBeTruthy();
    expect(challenge.reviews).toHaveLength(2);
    expect(challenge.reviews.some((item) => item.hypothesisId === theftId && item.contradictoryEvidence.length > 0)).toBe(true);
    expect(state.activity.filter((item) => item.type === 'HYPOTHESIS_UPDATED').length).toBeGreaterThan(0);
  });
});

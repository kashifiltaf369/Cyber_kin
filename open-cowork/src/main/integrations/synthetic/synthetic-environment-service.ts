/**
 * @module main/integrations/synthetic/synthetic-environment-service
 *
 * High-level façade over the synthetic environment. Owns the dataset
 * store, the scenario registry, and the IntegrationRegistry that hosts
 * the synthetic factories. Exposes programmatic operations (load, reset,
 * list, seed-investigation) so both the IPC layer and the headless CLI
 * can drive the environment identically.
 *
 * Hard guardrails (CYBER_BUILD_RULES rule 23 — never fabricate evidence):
 *  - Every synthetic observation carries a `synthetic: true` watermark and a
 *    unique `adapterId: synthetic-*` provenance.
 *  - Every seed-investigation records an explicit notice event so the
 *    investigation timeline is permanently labelled SYNTHETIC.
 *  - Scenario titles are prefixed `[SYNTHETIC DEMO]` so they cannot be
 *    mistaken for a real investigation.
 */

import type { InvestigationService } from '../../investigation/investigation-service';
import type { CreateInvestigationInput, Investigation } from '../../../shared/cyber/investigation-types';
import { IntegrationRegistry } from '../integration-registry';
import { SyntheticDatasetStore } from './synthetic-dataset';
import { buildSyntheticFactories, isSyntheticEnvironmentEnabled } from './synthetic-factories';
import {
  buildSyntheticScenario,
  listSyntheticScenarios,
} from './scenarios';
import {
  SYNTHETIC_WATERMARK,
  type ScenarioId,
  type SyntheticDataset,
  type SyntheticEnvironmentStatus,
  type SyntheticScenario,
} from './scenario-types';

export interface SyntheticEnvironmentServiceOptions {
  /**
   * If false (default), loading scenarios is blocked. This is a safety
   * switch the Electron main process wires to the CYBER_SYNTHETIC_ENABLED
   * env var.
   */
  enabled?: boolean;
  registry?: IntegrationRegistry;
}

export class SyntheticEnvironmentService {
  readonly store: SyntheticDatasetStore;
  readonly registry: IntegrationRegistry;
  private readonly enabled: boolean;

  constructor(
    private readonly investigationService?: InvestigationService,
    options: SyntheticEnvironmentServiceOptions = {},
  ) {
    this.enabled = options.enabled ?? isSyntheticEnvironmentEnabled();
    this.store = new SyntheticDatasetStore();
    this.registry =
      options.registry ??
      new IntegrationRegistry({
        preference: {
          siem: 'synthetic',
          edr: 'synthetic',
          network: 'synthetic',
          identity: 'synthetic',
          'threat-intel': 'synthetic',
          'file-analysis': 'synthetic',
        },
      });
    this.registry.registerAll(buildSyntheticFactories(this.store));
  }

  isAvailable(): boolean {
    return this.enabled;
  }

  listScenarios(): SyntheticScenario[] {
    return listSyntheticScenarios();
  }

  status(): SyntheticEnvironmentStatus {
    return this.store.status();
  }

  load(scenarioId: ScenarioId): SyntheticDataset {
    this.requireEnabled();
    const scenario = buildSyntheticScenario(scenarioId);
    const dataset = scenario.build();
    this.store.load(dataset);
    return dataset;
  }

  reset(): void {
    this.store.reset();
  }

  /**
   * Build a fully-formed Investigation in the InvestigationService that
   * targets this scenario. Records a synthetic-data-notice event so the
   * investigation timeline is permanently labelled.
   */
  seedInvestigation(scenarioId: ScenarioId, actor: 'human' | 'agent' | 'system' = 'system'): Investigation {
    this.requireEnabled();
    const dataset = this.load(scenarioId);
    if (!this.investigationService) {
      throw new Error(
        `[${SYNTHETIC_WATERMARK}] SyntheticEnvironmentService was constructed without an InvestigationService — cannot seed investigation.`,
      );
    }
    const input: CreateInvestigationInput = {
      title: dataset.objective.title,
      objective: dataset.objective.initialPrompt,
      riskTolerance: 'MEDIUM',
      humanContext: [
        `[${SYNTHETIC_WATERMARK}] This investigation is a DEMO. All telemetry is synthetic.`,
        `Scenario: ${scenarioId} — ${dataset.objective.summary}`,
        'Do not act on this evidence against any real system.',
      ].join('\n\n'),
      hypotheses: [],
      openQuestions: [
        `Confirm synthetic dataset is loaded for scenario ${scenarioId}.`,
        ...dataset.suspicion.expectedHypotheses.map((h) => `Evaluate hypothesis: ${h}`),
      ],
    };
    const investigation = this.investigationService.create(input);
    this.investigationService.recordEvent(
      investigation.id,
      'OPERATIONAL_UPDATE',
      actor,
      `[${SYNTHETIC_WATERMARK}] Synthetic dataset loaded for scenario ${scenarioId}.`,
      {
        scenarioId,
        recordCounts: this.store.status().recordCounts,
        watermark: SYNTHETIC_WATERMARK,
        safety: 'demo-only-not-real-telemetry',
      },
    );
    this.investigationService.addNote(investigation.id, `[${SYNTHETIC_WATERMARK}] Do not run any real-world remediation on this investigation.`);
    this.investigationService.addConstraint(investigation.id, 'All evidence is synthetic; do not trigger real-world response.');
    return investigation;
  }

  requireEnabled(): void {
    if (!this.enabled) {
      throw new Error(
        `[${SYNTHETIC_WATERMARK}] Synthetic environment is disabled. Set CYBER_SYNTHETIC_ENABLED=1 to enable.`,
      );
    }
    if (!this.store.isLoaded()) {
      throw new Error(
        `[${SYNTHETIC_WATERMARK}] No synthetic scenario loaded. Call load() first.`,
      );
    }
  }
}

export { isSyntheticEnvironmentEnabled };
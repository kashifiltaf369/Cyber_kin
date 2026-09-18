/**
 * @module main/integrations/synthetic/synthetic-adapter-base
 *
 * Shared helpers for the synthetic adapters. Every observation returned by a
 * synthetic adapter MUST carry provenance identifying the adapter as
 * synthetic and tagging the record with the SYNTHETIC_DEMO_DATA watermark.
 */

import {
  type EventSearchQuery,
  type IntegrationObservation,
  type IntegrationProvenance,
} from '../integration-types';
import { SYNTHETIC_WATERMARK, type SyntheticDataset } from './scenario-types';

export function syntheticProvenance(
  domain: IntegrationProvenance['domain'],
  capability: string,
  scenarioId: string,
): IntegrationProvenance {
  return {
    domain,
    adapterId: `synthetic-${domain}`,
    vendor: 'synthetic',
    capability,
    method: 'file_import',
    collectedAt: Date.now(),
    sourceLabel: `synthetic-scenario:${scenarioId}`,
    sourceId: scenarioId,
  };
}

export function tagRecord<T extends object>(
  observation: T,
  watermark: string = SYNTHETIC_WATERMARK,
): T {
  const tagField = ((observation as Record<string, unknown>).raw as Record<string, unknown> | undefined) ?? {};
  return {
    ...observation,
    raw: {
      ...tagField,
      synthetic: true,
      watermark,
    },
  } as T;
}

export function ensureSyntheticQuery(query: EventSearchQuery): EventSearchQuery {
  return { ...query };
}

export function makeSyntheticObservation<T>(
  value: T,
  domain: IntegrationProvenance['domain'],
  capability: string,
  scenarioId: string,
): IntegrationObservation<T> {
  return {
    value,
    provenance: syntheticProvenance(domain, capability, scenarioId),
  };
}

/**
 * Helper that asserts a dataset is loaded and tags each record with the
 * synthetic watermark before returning.
 */
export function observeSynthetic<T extends object>(
  dataset: SyntheticDataset,
  domain: IntegrationProvenance['domain'],
  capability: string,
  records: T[],
): IntegrationObservation<T[]> {
  return {
    value: records.map((record) => tagRecord(record)),
    provenance: syntheticProvenance(domain, capability, dataset.scenarioId),
  };
}
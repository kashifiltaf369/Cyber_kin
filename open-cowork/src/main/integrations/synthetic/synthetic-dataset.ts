/**
 * @module main/integrations/synthetic/synthetic-dataset
 *
 * In-memory holder for an active synthetic dataset. Adapters read from this
 * holder so all domains (SIEM, EDR, network, identity, threat intel, file
 * analysis) return consistent evidence for a single scenario.
 *
 * The holder is intentionally NOT process-global: tests instantiate their own
 * SyntheticDatasetStore to keep scenarios isolated.
 */

import type {
  DnsRecord,
  EventRecord,
  FileAnalysisReport,
  IdentityActivityRecord,
  IndicatorLookupResult,
  NetworkConnectionRecord,
  ProcessRecord,
} from '../integration-types';
import {
  SYNTHETIC_WATERMARK,
  type ScenarioId,
  type SyntheticDataset,
  type SyntheticEnvironmentStatus,
} from './scenario-types';

export class SyntheticDatasetStore {
  private dataset: SyntheticDataset | null = null;
  private loadedAt: number | null = null;

  load(dataset: SyntheticDataset): void {
    this.dataset = dataset;
    this.loadedAt = Date.now();
  }

  reset(): void {
    this.dataset = null;
    this.loadedAt = null;
  }

  isLoaded(): boolean {
    return this.dataset !== null;
  }

  requireDataset(): SyntheticDataset {
    if (!this.dataset) {
      throw new Error(
        `[${SYNTHETIC_WATERMARK}] No synthetic scenario loaded. Call load() before querying.`,
      );
    }
    return this.dataset;
  }

  currentScenarioId(): ScenarioId | null {
    return this.dataset?.scenarioId ?? null;
  }

  status(): SyntheticEnvironmentStatus {
    if (!this.dataset) {
      return {
        loaded: false,
        scenarioId: null,
        loadedAt: null,
        recordCounts: {
          events: 0,
          processes: 0,
          networkConnections: 0,
          dnsQueries: 0,
          identityActivity: 0,
          fileAnalysisReports: 0,
          indicatorLookups: 0,
        },
      };
    }
    return {
      loaded: true,
      scenarioId: this.dataset.scenarioId,
      loadedAt: this.loadedAt,
      recordCounts: {
        events: this.dataset.events.length,
        processes: this.dataset.processes.length,
        networkConnections: this.dataset.networkConnections.length,
        dnsQueries: this.dataset.dnsQueries.length,
        identityActivity: this.dataset.identityActivity.length,
        fileAnalysisReports: this.dataset.fileAnalysisReports.length,
        indicatorLookups: this.dataset.indicatorLookups.length,
      },
    };
  }

  // ---- typed accessors with simple filtering ----

  searchEvents(query: {
    query?: string;
    startTime?: number;
    endTime?: number;
    limit?: number;
    filters?: Record<string, string | number | boolean>;
  }): EventRecord[] {
    const dataset = this.requireDataset();
    return applyFilters(dataset.events, query.query, query.startTime, query.endTime, query.filters).slice(
      0,
      query.limit ?? 100,
    );
  }

  searchProcesses(query: {
    query?: string;
    startTime?: number;
    endTime?: number;
    limit?: number;
    host?: string;
    name?: string;
  }): ProcessRecord[] {
    const dataset = this.requireDataset();
    let results = dataset.processes;
    if (query.host) results = results.filter((record) => record.host === query.host);
    if (query.name) results = results.filter((record) => record.name === query.name);
    return applyFilters(results, query.query, query.startTime, query.endTime, undefined).slice(
      0,
      query.limit ?? 100,
    );
  }

  searchNetworkConnections(query: {
    query?: string;
    startTime?: number;
    endTime?: number;
    limit?: number;
    host?: string;
    remoteAddress?: string;
  }): NetworkConnectionRecord[] {
    const dataset = this.requireDataset();
    let results = dataset.networkConnections;
    if (query.host) results = results.filter((record) => record.host === query.host);
    if (query.remoteAddress) results = results.filter((record) => record.remoteAddress === query.remoteAddress);
    return applyFilters(results, query.query, query.startTime, query.endTime, undefined).slice(
      0,
      query.limit ?? 100,
    );
  }

  searchDns(query: {
    query?: string;
    startTime?: number;
    endTime?: number;
    limit?: number;
    host?: string;
    name?: string;
  }): DnsRecord[] {
    const dataset = this.requireDataset();
    let results = dataset.dnsQueries;
    if (query.host) results = results.filter((record) => record.host === query.host);
    if (query.name) results = results.filter((record) => record.query === query.name);
    return applyFilters(results, query.query, query.startTime, query.endTime, undefined).slice(
      0,
      query.limit ?? 100,
    );
  }

  searchIdentityActivity(query: {
    query?: string;
    startTime?: number;
    endTime?: number;
    limit?: number;
    actor?: string;
    action?: string;
  }): IdentityActivityRecord[] {
    const dataset = this.requireDataset();
    let results = dataset.identityActivity;
    if (query.actor) results = results.filter((record) => record.actor === query.actor);
    if (query.action) results = results.filter((record) => record.action === query.action);
    return applyFilters(results, query.query, query.startTime, query.endTime, undefined).slice(
      0,
      query.limit ?? 100,
    );
  }

  lookupIndicator(indicator: string): IndicatorLookupResult | null {
    const dataset = this.requireDataset();
    return dataset.indicatorLookups.find((record) => record.indicator === indicator) ?? null;
  }

  fetchFileReport(submissionId: string): FileAnalysisReport | null {
    const dataset = this.requireDataset();
    return dataset.fileAnalysisReports.find((record) => record.submissionId === submissionId) ?? null;
  }
}

function applyFilters<T extends { timestamp?: number; source?: string; message?: string; name?: string; query?: string; actor?: string; remoteAddress?: string; indicator?: string }>(
  records: T[],
  textQuery: string | undefined,
  startTime: number | undefined,
  endTime: number | undefined,
  filters: Record<string, string | number | boolean> | undefined,
): T[] {
  let results = records;
  if (textQuery && textQuery.trim().length > 0) {
    const needle = textQuery.toLowerCase();
    results = results.filter((record) =>
      JSON.stringify(record).toLowerCase().includes(needle),
    );
  }
  if (typeof startTime === 'number') {
    results = results.filter((record) => typeof record.timestamp !== 'number' || record.timestamp >= startTime);
  }
  if (typeof endTime === 'number') {
    results = results.filter((record) => typeof record.timestamp !== 'number' || record.timestamp <= endTime);
  }
  if (filters) {
    for (const [key, value] of Object.entries(filters)) {
      results = results.filter((record) => {
        const candidate = (record as unknown as Record<string, unknown>)[key];
        return candidate === value;
      });
    }
  }
  return results;
}
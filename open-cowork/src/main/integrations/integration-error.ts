/**
 * @module main/integrations/integration-error
 *
 * Stable error shape for adapter failures. The investigation engine must
 * always be able to distinguish a missing/unconfigured integration from a
 * runtime failure so the UI can mark the integration as "unavailable"
 * instead of crashing the worker (CYBER_BUILD_RULES: graceful degradation).
 */

import type { IntegrationDomain } from './integration-types';

export class IntegrationUnavailableError extends Error {
  readonly domain: IntegrationDomain;
  readonly vendor: string;
  readonly reason: string;
  readonly missingRequirements: string[];

  constructor(params: {
    domain: IntegrationDomain;
    vendor: string;
    reason: string;
    missingRequirements?: string[];
  }) {
    super(`Integration unavailable: ${params.domain}/${params.vendor} - ${params.reason}`);
    this.name = 'IntegrationUnavailableError';
    this.domain = params.domain;
    this.vendor = params.vendor;
    this.reason = params.reason;
    this.missingRequirements = params.missingRequirements ? [...params.missingRequirements] : [];
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      domain: this.domain,
      vendor: this.vendor,
      reason: this.reason,
      missingRequirements: this.missingRequirements,
    };
  }
}

export class IntegrationTimeoutError extends Error {
  readonly domain: IntegrationDomain;
  readonly vendor: string;
  readonly capability: string;

  constructor(params: { domain: IntegrationDomain; vendor: string; capability: string; timeoutMs: number }) {
    super(`Integration call timed out after ${params.timeoutMs}ms: ${params.domain}/${params.vendor}/${params.capability}`);
    this.name = 'IntegrationTimeoutError';
    this.domain = params.domain;
    this.vendor = params.vendor;
    this.capability = params.capability;
  }
}

export function isIntegrationUnavailable(value: unknown): value is IntegrationUnavailableError {
  return value instanceof IntegrationUnavailableError;
}

export function describeIntegrationError(error: unknown): string {
  if (isIntegrationUnavailable(error)) {
    return `${error.domain}/${error.vendor} unavailable: ${error.reason}`;
  }
  if (error instanceof IntegrationTimeoutError) {
    return `${error.domain}/${error.vendor}/${error.capability} timed out`;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'Unknown integration error';
}

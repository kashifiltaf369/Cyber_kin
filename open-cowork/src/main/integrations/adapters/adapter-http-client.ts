/**
 * @module main/integrations/adapters/adapter-http-client
 *
 * Tiny dependency-free HTTP client used by adapters.
 *
 * Kept in-tree to avoid adding vendor SDKs that would couple the investigation
 * engine to a specific transport. Uses the Node 22 built-in `fetch`.
 * Timeouts are enforced via AbortController and errors are redacted through
 * the credential module so secrets never leak into logs.
 */

import { redactCredential } from '../integration-credentials';

export interface AdapterHttpRequest {
  url: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  headers?: Record<string, string>;
  body?: string | Record<string, unknown>;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface AdapterHttpResponse<T = unknown> {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  data: T;
  text: string;
}

export class AdapterHttpError extends Error {
  readonly status: number;
  readonly body: string;
  readonly redactedBody: string;

  constructor(status: number, body: string) {
    super(`Adapter HTTP ${status}: ${redactCredential(body)}`);
    this.name = 'AdapterHttpError';
    this.status = status;
    this.body = body;
    this.redactedBody = String(redactCredential(body));
  }
}

export async function adapterFetch<T = unknown>(request: AdapterHttpRequest): Promise<AdapterHttpResponse<T>> {
  const timeoutMs = request.timeoutMs ?? 10_000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const signals: AbortSignal[] = [controller.signal];
  if (request.signal) signals.push(request.signal);
  const combined = AbortSignal.any(signals);
  const init: RequestInit = {
    method: request.method || 'GET',
    headers: { Accept: 'application/json', ...(request.headers || {}) },
    signal: combined,
  };
  if (request.body !== undefined) {
    init.body = typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
    (init.headers as Record<string, string>)['Content-Type'] = (init.headers as Record<string, string>)['Content-Type'] || 'application/json';
  }
  try {
    const response = await fetch(request.url, init);
    const text = await response.text();
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    let data: T;
    try {
      data = text.length === 0 ? (undefined as unknown as T) : (JSON.parse(text) as T);
    } catch {
      data = text as unknown as T;
    }
    if (!response.ok) {
      throw new AdapterHttpError(response.status, text);
    }
    return { status: response.status, ok: true, headers, data, text };
  } finally {
    clearTimeout(timeout);
  }
}

export function encodePath(value: string): string {
  return encodeURIComponent(value);
}

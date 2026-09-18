import { describe, expect, it } from 'vitest';
import {
  IntegrationCredentialResolver,
  redactCredential,
  REDACTED_VALUE,
} from '../src/main/integrations/integration-credentials';

describe('IntegrationCredentialResolver', () => {
  it('resolves credentials from env first', () => {
    const resolver = new IntegrationCredentialResolver({
      env: { SPLUNK_TOKEN: 'from-env' },
    });
    const resolved = resolver.resolve('siem', 'splunk', 'SPLUNK_TOKEN', 'token');
    expect(resolved?.value).toBe('from-env');
    expect(resolved?.source).toBe('env');
  });

  it('falls back to configStore when env is missing', () => {
    const resolver = new IntegrationCredentialResolver({
      configStore: {
        getCredential: (_domain, _vendor, key) => (key === 'token' ? 'from-config' : undefined),
      },
    });
    const resolved = resolver.resolve('siem', 'splunk', 'SPLUNK_TOKEN', 'token');
    expect(resolved?.value).toBe('from-config');
    expect(resolved?.source).toBe('config');
  });

  it('uses override map with highest precedence', () => {
    const resolver = new IntegrationCredentialResolver({
      env: { SPLUNK_TOKEN: 'from-env' },
      overrides: { 'siem.splunk.SPLUNK_TOKEN': 'from-override' },
    });
    const resolved = resolver.resolve('siem', 'splunk', 'SPLUNK_TOKEN', 'token');
    expect(resolved?.source).toBe('override');
    expect(resolved?.value).toBe('from-override');
  });

  it('returns null when no source provides the credential', () => {
    const resolver = new IntegrationCredentialResolver();
    expect(resolver.resolve('siem', 'splunk', 'MISSING')).toBeNull();
  });

  it('aggregates missing requirements for many credentials', () => {
    const resolver = new IntegrationCredentialResolver({ env: { A: '1' } });
    const missing = resolver.missingRequirements('siem', 'splunk', [
      { envVar: 'A' },
      { envVar: 'B' },
      { envVar: 'C' },
    ]);
    expect(missing).toEqual(['B', 'C']);
  });
});

describe('redactCredential', () => {
  it('redacts bearer tokens in strings', () => {
    const redacted = redactCredential('Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345') as string;
    expect(redacted).toContain(REDACTED_VALUE);
    expect(redacted).not.toContain('abcdefghijklmnopqrstuvwxyz012345');
  });

  it('redacts long base64-looking secret blobs', () => {
    const secret = 'A'.repeat(48);
    const redacted = redactCredential(`token=${secret}`) as string;
    expect(redacted).toContain(REDACTED_VALUE);
  });

  it('redacts nested object key fields', () => {
    const redacted = redactCredential({
      status: 401,
      headers: { authorization: 'Bearer xyz1234567890abcdefghijklmnop' },
      details: { apiKey: 'secret-value-1234' },
    }) as Record<string, unknown>;
    expect((redacted.headers as Record<string, string>).authorization).toContain(REDACTED_VALUE);
    expect((redacted.details as Record<string, string>).apiKey).toBe(REDACTED_VALUE);
  });
});

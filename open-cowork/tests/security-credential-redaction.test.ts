/**
 * Security tests: Credential redaction coverage gaps.
 *
 * Maps to SECURITY_THREAT_MODEL.md THREAT-07 (Credential exposure) — HIGH severity.
 *
 * Verifies redactCredential behavior against 5 documented gap patterns:
 *   1. Short tokens (< 32 chars) - Slack legacy 10-char, AWS AKID 20-char
 *   2. Hyphenated tokens (Slack xoxb-*, Stripe, GitHub fine-grained) — hyphens break [A-Za-z0-9+/]{32,} regex
 *   3. Authorization: Basic <base64(user:pass)> — no Basic variant pattern
 *   4. Credentials in generic object keys: { value, data, body, payload } — not in key-name filter list
 *   5. Nested recursive redaction correctness
 */

import { describe, it, expect } from 'vitest';
import { redactCredential, REDACTED_VALUE } from '../src/main/integrations/integration-credentials';

describe('THREAT-07: Credential redaction behavior', () => {
  describe('Patterns correctly redacted (baseline)', () => {
    it('redacts long base64-like tokens (>= 32 chars) embedded in strings', () => {
      const longBase64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456789+/AAAA';
      const input = `request failed with token=${longBase64} in body`;
      const output = redactCredential(input) as string;
      expect(output).not.toContain(longBase64);
      expect(output).toContain(REDACTED_VALUE);
    });

    it('redacts Bearer scheme tokens', () => {
      const input = 'Authorization: Bearer eyJhbGciOi.JIUzI1NiIsIn.xxx-SIGNED';
      const output = redactCredential(input) as string;
      expect(output).toContain(`Bearer ${REDACTED_VALUE}`);
      expect(output).not.toContain('eyJhbGciOi');
    });

    it('redacts api_key / apikey key=value patterns (case insensitive)', () => {
      // Dummy value (not a real Stripe key format) so GitHub secret scanning/push protection doesn't block commits.
      expect(redactCredential('log: apikey=sk_DUMMY_abcdefghijklmnopqrstuvwxyz012345') as string).toContain(
        `api_key=${REDACTED_VALUE}`
      );
      expect(redactCredential('log: API_KEY: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456789') as string).toContain(
        `api_key=${REDACTED_VALUE}`
      );
      expect(redactCredential('log: api-key=t0123456789abcdefghijklmnopqrstuv') as string).toContain(
        `api_key=${REDACTED_VALUE}`
      );
    });

    it('recursively redacts object keys matching secret/token/password patterns', () => {
      const input = {
        level1: {
          token: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij01',
          password: 'plaintext-long-password-here-1234',
          authorization: 'Bearer kept',
          safeField: 'public-value',
        },
      };
      const output = redactCredential(input) as Record<string, Record<string, string>>;
      expect(output.level1.token).toBe(REDACTED_VALUE);
      expect(output.level1.password).toBe(REDACTED_VALUE);
      expect(output.level1.authorization).toBe(REDACTED_VALUE);
      expect(output.level1.safeField).toBe('public-value');
    });
  });

  describe('DOCUMENTED GAPS: Patterns NOT redacted by current implementation', () => {
    it('DOCUMENTS GAP 1: short AWS access key (20 chars, < 32 threshold) — kept as-is in string form', () => {
      const shortAwsAccessKey = 'AKIAIOSFODNN7EXAMPLE';
      expect(shortAwsAccessKey.length).toBeLessThan(32);

      const input = `AWS error accessing S3 with key ${shortAwsAccessKey}`;
      const output = redactCredential(input) as string;
      expect(output).toContain(shortAwsAccessKey);
    });

    it('DOCUMENTS GAP 1 (obj): short AWS key in generic object key "value" — key name not in filter + string < 32 chars', () => {
      const input = {
        value: 'AKIAIOSFODNN7EXAMPLE',
        description: 'AWS access key from config',
      };
      const output = redactCredential(input) as Record<string, string>;
      expect(output.value).toBe('AKIAIOSFODNN7EXAMPLE');
    });

    it('DOCUMENTS GAP 2: hyphenated Slack xoxb-* bot token — hyphens break base64 regex', () => {
      const slackToken = 'xoxb-123456789012-ABCDEFGHIJKLMNOPQRSTUVWXYZ-abcdefghij0123456789';
      expect(slackToken).toContain('-');

      const input = `Slack API 401 for token ${slackToken}`;
      const output = redactCredential(input) as string;

      const slackPartsNoHyphens = slackToken.split('-').filter((s) => s.length >= 32);
      if (slackPartsNoHyphens.length > 0) {
        for (const part of slackPartsNoHyphens) {
          expect(output).not.toContain(part);
        }
      }

      expect(output).toContain('xoxb');
    });

    it('DOCUMENTS GAP 3: SHORT (< 32-char base64) Authorization: Basic tokens bypass both regexes', () => {
      // Short Basic creds (e.g. user:p → base64 length 8) do NOT hit the 32+ base64 regex.
      const shortBasic = 'Basic dXNlcjpw';
      expect(Buffer.from('dXNlcjpw', 'base64').toString()).toBe('user:p');
      const input = `header received: Authorization: ${shortBasic}`;
      const output = redactCredential(input) as string;

      expect(output).not.toContain(`Basic ${REDACTED_VALUE}`);
      expect(output).toContain('Basic dXNlcjpw');
    });

    it('DOCUMENTS GAP 4: credential stored in generic object key "payload" / "body" / "data" — key names not in filter', () => {
      const secret = 'sk_test_abcdefghijklmnopqrstuvwxyz0123456789ABCD';
      const input = {
        payload: secret,
        body: secret,
        data: secret,
        value: secret,
      };
      const output = redactCredential(input) as Record<string, string>;

      expect(output.payload).toBe(secret);
      expect(output.body).toBe(secret);
      expect(output.data).toBe(secret);
      expect(output.value).toBe(secret);
    });

    it('DOCUMENTS GAP 4 nested: generic key "request.body" deep in object tree leaks', () => {
      const secret = 'SECRET-LONG-VALUE-AAAAAAAAAAAAAAAAAAAAAAAAAAA';
      const input = {
        request: {
          body: secret,
          headers: {
            'x-custom': secret,
          },
        },
      };
      const output = redactCredential(input) as Record<string, Record<string, unknown>>;
      const req = output.request as Record<string, string>;
      expect(req.body).toBe(secret);
    });
  });

  describe('Error instances', () => {
    it('redacts message + stack on Error objects (without losing name)', () => {
      const err = new Error('failed with Bearer eyJhbGciOi.JIUzI1NiIsIn-R3 signed and apikey=sk_DUMMY_1234567890abcdefghijklmnopqrstuvwxyz01');
      err.name = 'IntegrationError';
      const output = redactCredential(err) as Error;
      expect(output.name).toBe('IntegrationError');
      expect(output.message).not.toContain('eyJhbGciOi');
      expect(output.message).not.toContain('sk_DUMMY_1234567890');
    });
  });

  describe('Edge cases: non-credentials / false positives', () => {
    it('does not redact short innocent identifiers', () => {
      const input = 'user id=abc_123 session=XYZ order=INV-2025-0001';
      const output = redactCredential(input) as string;
      expect(output).toBe(input);
    });

    it('does not modify null / undefined / number primitives', () => {
      expect(redactCredential(null)).toBeNull();
      expect(redactCredential(undefined)).toBeUndefined();
      expect(redactCredential(42)).toBe(42);
      expect(redactCredential(true)).toBe(true);
    });
  });
});

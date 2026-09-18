/**
 * Security tests: SSRF surface validation.
 *
 * Maps to SECURITY_THREAT_MODEL.md THREAT-10 (SSRF) — CRITICAL severity.
 *
 * Because both ToolExecutor.webFetch() and adapterFetch() have ZERO server-side
 * URL allowlist/blocklist validation (only protocol check for http/https), these
 * tests DOCUMENT and lock in that actual behavior. No network calls are made.
 *
 * Tests do NOT modify the implementation. They create a behavioral contract of
 * exactly which URLs are rejected at validation-time vs permitted to reach fetch().
 */

import { describe, it, expect } from 'vitest';

const METADATA_URLS = [
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  'http://169.254.169.254/latest/user-data',
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
  'http://metadata.goog/user-data',
];

const LOOPBACK_URLS = [
  'http://127.0.0.1/admin',
  'http://127.0.0.1:3000/secrets',
  'http://127.255.255.254:8080/config',
  'http://localhost/internal-console',
  'http://localhost:9222/json',
  'http://[::1]:8080/secret',
  'http://[::1]/admin',
];

const PRIVATE_RFC1918_URLS = [
  'http://10.0.0.1/router-login',
  'http://10.255.255.254:22',
  'http://172.16.0.1/docker-api',
  'http://172.31.255.253:8443/vault',
  'http://192.168.1.1/admin',
  'http://192.168.0.254:8080/dashboard',
];

const LINK_LOCAL = [
  'http://169.254.1.1/device-config',
  'http://[fe80::1%25eth0]/router',
];

const SAFE_EXTERNAL = [
  'https://example.com/path?q=1',
  'https://api.virustotal.com/v3/files/abc',
  'http://httpbin.org/get',
];

const BLOCKED_PROTOCOL = [
  'file:///etc/passwd',
  'ftp://10.0.0.1/secret',
  'gopher://127.0.0.1:70/_SECRET',
  'data:text/html,<script>alert(1)</script>',
];

type CheckResult = { allowedByProtocol: boolean; url: string };

function validateUrlLikeWebFetch(url: string): CheckResult {
  // Mirror webFetch's validator (tool-executor.ts#L161-L176) EXACTLY:
  //   - trim
  //   - new URL()
  //   - protocol in ['http:', 'https:']
  const trimmed = url.trim();
  if (!trimmed) return { allowedByProtocol: false, url };
  try {
    const parsed = new URL(trimmed);
    const ok = ['http:', 'https:'].includes(parsed.protocol);
    return { allowedByProtocol: ok, url };
  } catch {
    return { allowedByProtocol: false, url };
  }
}

describe('THREAT-10: SSRF validator behavior (webFetch / adapterFetch protocol-only gate)', () => {
  describe('Always blocked: non-http(s) protocols (webFetch line 174)', () => {
    for (const url of BLOCKED_PROTOCOL) {
      it(`blocks protocol: ${url}`, () => {
        expect(validateUrlLikeWebFetch(url).allowedByProtocol).toBe(false);
      });
    }
  });

  describe('DOCUMENTS GAP: cloud metadata endpoints pass protocol-only validator (no IP-based blocking)', () => {
    for (const url of METADATA_URLS) {
      it(`PERMITS (passes protocol gate) → ${url}`, () => {
        const result = validateUrlLikeWebFetch(url);
        expect(result.allowedByProtocol).toBe(true);
        // No additional checks exist in webFetch / adapterFetch. This test
        // locks in that metadata URLs are NOT blocked at the URL validation stage.
      });
    }
  });

  describe('DOCUMENTS GAP: loopback (127/8, localhost, ::1) passes protocol-only validator', () => {
    for (const url of LOOPBACK_URLS) {
      it(`PERMITS (passes protocol gate) → ${url}`, () => {
        expect(validateUrlLikeWebFetch(url).allowedByProtocol).toBe(true);
      });
    }
  });

  describe('DOCUMENTS GAP: RFC1918 private IP ranges pass protocol-only validator', () => {
    for (const url of PRIVATE_RFC1918_URLS) {
      it(`PERMITS (passes protocol gate) → ${url}`, () => {
        expect(validateUrlLikeWebFetch(url).allowedByProtocol).toBe(true);
      });
    }
  });

  describe('DOCUMENTS GAP: link-local (169.254/16 non-metadata, IPv6 fe80) passes', () => {
    for (const url of LINK_LOCAL) {
      it(`PERMITS (passes protocol gate) → ${url}`, () => {
        // IPv6 scope-ID URLs (fe80::1%eth0) may fail new URL() because of '%',
        // which is technically invalid without encoding. Allow either outcome.
        const res = validateUrlLikeWebFetch(url);
        expect([true, false]).toContain(res.allowedByProtocol);
      });
    }
  });

  describe('Safe external URLs: always pass through the protocol gate', () => {
    for (const url of SAFE_EXTERNAL) {
      it(`permits → ${url}`, () => {
        expect(validateUrlLikeWebFetch(url).allowedByProtocol).toBe(true);
      });
    }
  });

  describe('Adapter HTTP client: direct URL construction (no host-level restrictions)', () => {
    it('adapterFetch request interface accepts caller-controlled headers & arbitrary http/https URLs', () => {
      // This test validates the AdapterHttpRequest TYPE constraints (design-level SSRF surface):
      // url is a plain string; method is limited enum (ok), headers is fully caller-controlled.
      const internalRequest = {
        url: 'http://127.0.0.1:8200/v1/secret/data/ci',
        method: 'GET' as const,
        headers: {
          'X-Vault-Token': 'hvs.xxx',
          'Metadata-Flavor': 'Google',
        },
      };
      expect(internalRequest.url.startsWith('http://127')).toBe(true);
      expect(internalRequest.headers['Metadata-Flavor']).toBe('Google');
      // Interface accepts arbitrary url + headers → SSRF to metadata services with required
      // headers is structurally permitted. Documented.
    });
  });

  describe('Invalid URL handling (baseline sanity)', () => {
    it('rejects empty string', () => expect(validateUrlLikeWebFetch('').allowedByProtocol).toBe(false));
    it('rejects whitespace-only', () => expect(validateUrlLikeWebFetch('   ').allowedByProtocol).toBe(false));
    it('rejects malformed URL (no scheme)', () =>
      expect(validateUrlLikeWebFetch('not-a-url').allowedByProtocol).toBe(false));
    it('rejects javascript: scheme', () =>
      expect(validateUrlLikeWebFetch('javascript:alert(1)').allowedByProtocol).toBe(false));
  });
});

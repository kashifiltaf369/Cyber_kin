/**
 * Security tests: Path traversal edge cases against path-containment.ts.
 *
 * Maps to SECURITY_THREAT_MODEL.md THREAT-09 (Path traversal) — CRITICAL severity.
 *
 * Focuses on EDGE CASES NOT already covered by existing path-containment.test.ts:
 *   - Null-byte variants (encoded)
 *   - Double URL-encoded dots (%2e%2e)
 *   - Mixed-case and case-sensitivity flag behavior
 *   - `..` with brace/non-separator prefixes (command-injection style)
 *   - UNC path edge cases
 *   - Whitespace and control-character variants
 *
 * Does NOT modify any security controls. Pure black-box behavioral tests.
 */

import { describe, it, expect } from 'vitest';
import {
  normalizePathForContainment,
  isPathWithinRoot,
} from '../src/main/tools/path-containment';

const POSIX_ROOT = '/sandbox/workspace/sess-123';
const WIN_ROOT = 'C:/workspace';
const UNC_ROOT = '//server/share/workspace';

describe('THREAT-09: Path containment encoding & obfuscation edge cases', () => {
  describe('Null bytes & control characters (THREAT-09.1 / encoding gaps)', () => {
    it('rejects paths containing literal null bytes (\x00) — already covered; extended variants', () => {
      // Middle of string
      expect(isPathWithinRoot('/workspace/file\x00.txt', '/workspace')).toBe(false);
      // Trailing null (classic truncation against C-style APIs downstream)
      expect(isPathWithinRoot('/workspace/../../../etc/passwd\x00', '/workspace')).toBe(false);
      // Null ONLY (silly but safe)
      expect(isPathWithinRoot('\x00', '/workspace')).toBe(false);
    });

    it('DOCUMENTS GAP: URL-encoded null bytes (%00) are NOT decoded before containment check — lexical path passes if URL-decoded downstream', () => {
      const encodedNullInput = '/sandbox/workspace/sess-123/secret%00.txt';
      // The containment layer sees literal '%00' (3 chars), not 0x00.
      const result = isPathWithinRoot(encodedNullInput, POSIX_ROOT);
      expect(result).toBe(true);
      // If any downstream consumer calls decodeURIComponent() on the path,
      // the null byte re-emerges → C-API truncation risk. Documented, not patched.
    });

    it('DOCUMENTS GAP: double-encoded dot segments (%252e%252e) are NOT decoded and are treated as literal filenames', () => {
      const doubleEncoded = '/sandbox/workspace/sess-123/%252e%252e/outside';
      const contained = isPathWithinRoot(doubleEncoded, POSIX_ROOT);
      // Canonicalize sees '%252e%252e' as a directory name, not '..' → stays inside.
      // IF downstream double-decodes (%25 → %, then %2e → .), escape occurs. Documented.
      expect(contained).toBe(true);
    });

    it('DOCUMENTS GAP: URL-encoded ../ (%2e%2e%2f) is treated as literal dir name; passes lexical containment', () => {
      const urlEncodedTraversal = '/sandbox/workspace/sess-123/%2e%2e/%2e%2e/etc/passwd';
      const contained = isPathWithinRoot(urlEncodedTraversal, POSIX_ROOT);
      // %2e%2e → literal string (not resolved as ..) → passes
      expect(contained).toBe(true);
    });
  });

  describe('Brace / non-separator prefix around .. (THREAT-08 "close-brace" vector applied to paths)', () => {
    it('still resolves .. correctly when it follows a closing brace in the segment pipeline', () => {
      // Real POSIX filesystem does not treat "}.." specially — still parent dir.
      // Lexical segment-resolution: path is split on / and \, so:
      //   /root/abc}../x → segments = ['root', 'abc}..', 'x'] → 'abc}..' not matched as '..'
      // But in bash, "$HOME}/.." is shell-expanded differently.
      const candidate = `${POSIX_ROOT}/project-dir}../outside-root`;
      const result = isPathWithinRoot(candidate, POSIX_ROOT);
      // Segments: [..., 'project-dir}..', 'outside-root'] → 'project-dir}..' treated as a literal dir name
      expect(result).toBe(true);
    });

    it('still catches standard .. segments with standard separators', () => {
      expect(isPathWithinRoot(`${POSIX_ROOT}/src/../../../etc/passwd`, POSIX_ROOT)).toBe(false);
      // 4 levels of .. after sess-123/a/b/c: c,b,a pop, then one more pops sess-123 → escapes root → reject
      expect(isPathWithinRoot(`${POSIX_ROOT}/a/b/c/../../../../outside-root`, POSIX_ROOT)).toBe(false);
    });
  });

  describe('Case sensitivity behavior on Windows paths', () => {
    it('case-insensitive flag: Windows drive letters and path components normalize correctly', () => {
      expect(isPathWithinRoot('C:\\WorkSpace\\Project\\file.TXT', 'c:\\workspace', true)).toBe(true);
      expect(isPathWithinRoot('C:/Workspace/Project/../OTHER/file.dat', 'c:/workspace', true)).toBe(true);
    });

    it('DOCUMENTS GAP: forgetting caseInsensitive=true on Windows filesystem produces false rejects (informational)', () => {
      // Case-sensitive compare on Windows (case-insensitive FS) can leak:
      // Root registered as "C:/workspace" but user passes "c:/Workspace/secret" →
      // caseSensitive mode → kind=windows, root="C:" vs "c:" → line 107 root mismatch → false.
      const mismatch = isPathWithinRoot('c:/Workspace/secret.txt', 'C:/workspace', false);
      expect(mismatch).toBe(false);
    });

    it('case-insensitive mode correctly blocks Windows traversal escapes', () => {
      expect(
        isPathWithinRoot('C:/Workspace/A/../../SecretData/passwords.txt', 'c:/workspace', true)
      ).toBe(false);
    });
  });

  describe('UNC path edge cases', () => {
    it('allows valid UNC descendants with case insensitive flag', () => {
      expect(
        isPathWithinRoot('//SERVER/SHARE/Workspace/Evidence/file.pcap', '//server/share/workspace', true)
      ).toBe(true);
    });

    it('blocks UNC share escape via traversal (host matches, share mismatched after resolve)', () => {
      const escaped = `${UNC_ROOT}/nested/../../OtherShare/private.txt`;
      expect(isPathWithinRoot(escaped, UNC_ROOT, true)).toBe(false);
    });

    it('blocks cross-share same-prefix UNC paths', () => {
      expect(
        isPathWithinRoot('//server/share-evil/x.txt', UNC_ROOT, true)
      ).toBe(false);
    });

    it('blocks cross-host UNC (host name differs even if share matches)', () => {
      expect(
        isPathWithinRoot('//OTHERserver/share/workspace/a.txt', UNC_ROOT, true)
      ).toBe(false);
    });
  });

  describe('Whitespace / control chars around paths', () => {
    it('tabs in directory names do not confuse segment resolution — traversal still escapes, containment still blocks', () => {
      // `src\t` is treated as a single segment (literal tab is part of name, not a split char).
      // Then /../../ pops both `src\t` AND sess-123 → path escapes root. Containment correctly returns false.
      const withTab = `${POSIX_ROOT}/src\t/../../etc/passwd`;
      const contained = isPathWithinRoot(withTab, POSIX_ROOT);
      expect(contained).toBe(false);
    });

    it('normalizePathForContainment only touches slash directions & trailing slashes; preserves whitespace', () => {
      const raw = '  /home/user dir  \t/file name  ';
      const normalized = normalizePathForContainment(raw);
      expect(normalized).toBe(raw.replace(/\\/g, '/').replace(/\/+$/, ''));
      expect(normalized).toContain(' ');
      expect(normalized).toContain('\t');
    });
  });

  describe('Backstop: existing positive test cases still pass (no regressions)', () => {
    it('POSIX child within root', () => {
      expect(isPathWithinRoot(`${POSIX_ROOT}/pkg/index.ts`, POSIX_ROOT)).toBe(true);
    });
    it('POSIX escape', () => {
      expect(isPathWithinRoot(`${POSIX_ROOT}/../other/key`, POSIX_ROOT)).toBe(false);
    });
    it('relative inputs always rejected', () => {
      expect(isPathWithinRoot('pkg/index.ts', POSIX_ROOT)).toBe(false);
    });
  });
});

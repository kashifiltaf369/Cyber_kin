import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const viteConfig = readFileSync(path.resolve(process.cwd(), 'vite.config.ts'), 'utf8');
const builderConfig = readFileSync(path.resolve(process.cwd(), 'electron-builder.yml'), 'utf8');

describe('Gemini Electron runtime packaging', () => {
  it('keeps @google/genai external to the main-process bundle', () => {
    expect(viteConfig).toContain(
      "const googleGenAiExternals = ['@google/genai', /^@google\\/genai\\//]"
    );
    expect(viteConfig).toContain('...googleGenAiExternals');
  });

  it('ships the externalized SDK in packaged applications', () => {
    expect(builderConfig).toContain('- node_modules/@google/genai/**/*');
  });
});

import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { listRecentWorkspaceFiles } from '../src/main/utils/recent-workspace-files';

describe('listRecentWorkspaceFiles', () => {
  let rootDir: string;

  beforeEach(async () => {
    rootDir = await fs.mkdtemp(path.join(os.tmpdir(), 'open-cowork-recent-files-'));
  });

  afterEach(async () => {
    await fs.rm(rootDir, { recursive: true, force: true });
  });

  it('returns files created after the given timestamp', async () => {
    const before = Date.now();

    const filePath = path.join(rootDir, 'deck.pptx');
    await fs.writeFile(filePath, 'ppt');
    // Deterministic timestamp well clear of `before` (wall-clock jitter on
    // virtualized filesystems made raw write-order mtimes flaky).
    await fs.utimes(filePath, new Date(before + 50), new Date(before + 50));

    const files = await listRecentWorkspaceFiles(rootDir, before);

    expect(files.map((item) => path.basename(item.path))).toContain('deck.pptx');
  });

  it('ignores files inside excluded directories', async () => {
    const before = Date.now();
    await new Promise((resolve) => setTimeout(resolve, 5));

    await fs.mkdir(path.join(rootDir, 'node_modules'), { recursive: true });
    await fs.writeFile(path.join(rootDir, 'node_modules', 'ignored.txt'), 'ignore');
    const reportPath = path.join(rootDir, 'report.html');
    await fs.writeFile(reportPath, 'ok');
    await fs.utimes(reportPath, new Date(before + 50), new Date(before + 50));

    const files = await listRecentWorkspaceFiles(rootDir, before);

    expect(files.map((item) => path.basename(item.path))).toContain('report.html');
    expect(files.map((item) => path.basename(item.path))).not.toContain('ignored.txt');
  });

  it('ignores system metadata files like .DS_Store', async () => {
    const before = Date.now();
    await new Promise((resolve) => setTimeout(resolve, 5));

    await fs.writeFile(path.join(rootDir, '.DS_Store'), 'noise');
    await fs.writeFile(path.join(rootDir, 'slides.pptx'), 'ppt');

    const files = await listRecentWorkspaceFiles(rootDir, before);

    expect(files.map((item) => path.basename(item.path))).toContain('slides.pptx');
    expect(files.map((item) => path.basename(item.path))).not.toContain('.DS_Store');
  });

  it('ignores common temp, lock, and backup file patterns', async () => {
    const before = Date.now();
    await new Promise((resolve) => setTimeout(resolve, 5));

    const noiseFiles = [
      '._slides.pptx',
      '~$deck.pptx',
      '.~lock.deck.pptx#',
      'draft.md~',
      'report.tmp',
      'download.crdownload',
    ];

    for (const name of noiseFiles) {
      await fs.writeFile(path.join(rootDir, name), 'noise');
    }
    await fs.writeFile(path.join(rootDir, 'real-output.pdf'), 'pdf');

    const files = await listRecentWorkspaceFiles(rootDir, before);
    const names = files.map((item) => path.basename(item.path));

    expect(names).toContain('real-output.pdf');
    for (const name of noiseFiles) {
      expect(names).not.toContain(name);
    }
  });

  it('ignores cache directories like __pycache__', async () => {
    const before = Date.now();
    await new Promise((resolve) => setTimeout(resolve, 5));

    await fs.mkdir(path.join(rootDir, '__pycache__'), { recursive: true });
    await fs.writeFile(path.join(rootDir, '__pycache__', 'script.cpython-311.pyc'), 'pyc');
    await fs.writeFile(path.join(rootDir, 'presentation.pptx'), 'ppt');

    const files = await listRecentWorkspaceFiles(rootDir, before);
    const names = files.map((item) => path.basename(item.path));

    expect(names).toContain('presentation.pptx');
    expect(names).not.toContain('script.cpython-311.pyc');
  });

  it('orders results by most recent change first', async () => {
    const before = Date.now();

    const older = path.join(rootDir, 'older.txt');
    const newer = path.join(rootDir, 'newer.txt');
    await fs.writeFile(older, '1');
    await fs.writeFile(newer, '2');
    // Explicit mtimes: the implementation sorts by max(mtime, birthtime), so
    // stamping both files deterministically (older < newer, both > before)
    // removes the wall-clock jitter of relying on raw write order.
    await fs.utimes(older, new Date(before + 1000), new Date(before + 1000));
    await fs.utimes(newer, new Date(before + 2000), new Date(before + 2000));

    const files = await listRecentWorkspaceFiles(rootDir, before);

    expect(files[0]?.path).toBe(newer);
    expect(files[1]?.path).toBe(older);
  });
});

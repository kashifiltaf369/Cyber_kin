import { describe, expect, it } from 'vitest';
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { CyberCapabilityRegistry } from '../src/main/cyber/cyber-capability-registry';

describe('CyberCapabilityRegistry', () => {
  it('discovers relevant capabilities from analyst questions', () => {
    const registry = new CyberCapabilityRegistry();
    const results = registry.discover('What capability can search DNS queries and suspicious domain lookups?');

    expect(results.length).toBeGreaterThan(0);
    expect(results[0]?.capability.name).toBe('search_dns');
  });

  it('executes file inspection and hashing against local data', async () => {
    const root = path.join(process.cwd(), 'tmp-cyber-capability-test');
    rmSync(root, { recursive: true, force: true });
    mkdirSync(root, { recursive: true });
    const filePath = path.join(root, 'artifact.txt');
    writeFileSync(filePath, 'suspicious artifact content\nsecond line', 'utf8');

    const registry = new CyberCapabilityRegistry();
    const inspect = (await registry.execute('inspect_file', { filePath }, { workspacePath: root })) as {
      exists: boolean;
      preview: string;
    };
    const hash = (await registry.execute('calculate_hash', {
      filePath,
      algorithm: 'sha256',
    }, { workspacePath: root })) as { algorithm: string; hash: string };

    expect(inspect.exists).toBe(true);
    expect(inspect.preview).toContain('suspicious artifact content');
    expect(hash.algorithm).toBe('sha256');
    expect(hash.hash).toHaveLength(64);

    rmSync(root, { recursive: true, force: true });
  });

  it('queries local logs and structured process/network snapshots', async () => {
    const root = path.join(process.cwd(), 'tmp-cyber-capability-logs');
    rmSync(root, { recursive: true, force: true });
    mkdirSync(root, { recursive: true });

    const dnsLog = path.join(root, 'dns.log');
    const processes = path.join(root, 'processes.json');
    const connections = path.join(root, 'connections.json');

    writeFileSync(dnsLog, 'query for evil.example\nquery for benign.local\n', 'utf8');
    writeFileSync(
      processes,
      JSON.stringify([
        { pid: 1, name: 'explorer.exe', commandLine: 'explorer.exe' },
        { pid: 2, name: 'powershell.exe', commandLine: 'powershell.exe -enc abc' },
      ]),
      'utf8'
    );
    writeFileSync(
      connections,
      JSON.stringify([
        { localAddress: '10.0.0.5', remoteAddress: '203.0.113.10', port: 443 },
        { localAddress: '10.0.0.5', remoteAddress: '198.51.100.1', port: 445 },
      ]),
      'utf8'
    );

    const registry = new CyberCapabilityRegistry();
    const workspace = { workspacePath: root };
    const dns = (await registry.execute('search_dns', {
      sourcePath: dnsLog,
      query: 'evil.example',
    }, workspace)) as { records: Array<{ line: string }> };
    const processResult = (await registry.execute('search_processes', {
      sourcePath: processes,
      query: 'powershell',
    }, workspace)) as { processes: Array<Record<string, unknown>> };
    const networkResult = (await registry.execute('search_network_connections', {
      sourcePath: connections,
      query: '445',
    }, workspace)) as { connections: Array<Record<string, unknown>> };
    const logQuery = (await registry.execute('query_local_logs', {
      directoryPath: root,
      query: 'evil.example',
      extensions: ['.log'],
    }, workspace)) as { files: Array<{ path: string; matches: Array<{ line: string }> }> };

    expect(dns.records[0]?.line).toContain('evil.example');
    expect(processResult.processes).toHaveLength(1);
    expect(String(processResult.processes[0]?.name)).toContain('powershell');
    expect(networkResult.connections).toHaveLength(1);
    expect(String(networkResult.connections[0]?.remoteAddress)).toContain('198.51.100.1');
    expect(logQuery.files[0]?.matches[0]?.line).toContain('evil.example');

    rmSync(root, { recursive: true, force: true });
  });

  it('classifies indicators without vendor coupling', async () => {
    const registry = new CyberCapabilityRegistry();
    const result = (await registry.execute('lookup_indicator', {
      indicator: 'evil.example',
    })) as { indicatorType: string; safeToEnrich: boolean; summary: string };

    expect(result.indicatorType).toBe('domain');
    expect(result.safeToEnrich).toBe(true);
    expect(result.summary).toContain('No vendor enrichment performed');
  });

  it('refuses filesystem capabilities with paths outside the session workspace', async () => {
    const registry = new CyberCapabilityRegistry();
    await expect(
      registry.execute('inspect_file', { filePath: '/etc/passwd' }, { workspacePath: '/sandbox/workspace/sess-1' })
    ).rejects.toThrow(/outside the session workspace/);

    await expect(
      registry.execute('calculate_hash', { filePath: '../../etc/passwd' }, { workspacePath: '/sandbox/workspace/sess-1' })
    ).rejects.toThrow(/outside the session workspace/);
  });

  it('refuses filesystem capabilities when no workspace path is available (fail closed)', async () => {
    const registry = new CyberCapabilityRegistry();
    await expect(
      registry.execute('inspect_file', { filePath: '/tmp/anything.txt' })
    ).rejects.toThrow(/no workspace path is available/);
  });

  it('refuses paths that resolve through symlinks outside the session workspace', async () => {
    const base = path.join(process.cwd(), 'tmp-cyber-symlink-test');
    rmSync(base, { recursive: true, force: true });
    const root = path.join(base, 'workspace');
    const outside = path.join(base, 'outside');
    mkdirSync(root, { recursive: true });
    mkdirSync(outside, { recursive: true });
    const secret = path.join(outside, 'secret.txt');
    writeFileSync(secret, 'top secret', 'utf8');

    const registry = new CyberCapabilityRegistry();

    // 1. Existing symlinked FILE pointing outside the workspace.
    const fileLink = path.join(root, 'innocent.txt');
    symlinkSync(secret, fileLink);
    await expect(
      registry.execute('inspect_file', { filePath: fileLink }, { workspacePath: root })
    ).rejects.toThrow(/outside the session workspace/);

    // 2. Non-existent path under a symlinked DIRECTORY component.
    const dirLink = path.join(root, 'docs');
    symlinkSync(outside, dirLink);
    await expect(
      registry.execute('calculate_hash', { filePath: path.join(dirLink, 'new.txt') }, { workspacePath: root })
    ).rejects.toThrow(/outside the session workspace/);

    // 3. A genuinely local file still passes the real-path check.
    const local = path.join(root, 'local.txt');
    writeFileSync(local, 'inside', 'utf8');
    const inspect = (await registry.execute('inspect_file', { filePath: local }, { workspacePath: root })) as {
      exists: boolean;
    };
    expect(inspect.exists).toBe(true);

    rmSync(base, { recursive: true, force: true });
  });
});

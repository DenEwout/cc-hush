import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { startDaemon } from '../daemon/server.ts';
import { regexDetect } from '../daemon/detect.ts';

const HOOK = path.resolve('plugin/hooks/hook.ts');
const ENSURE = path.resolve('plugin/hooks/ensure-daemon.ts');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hush-hooks-'));
let daemon: http.Server;
let port = 0;
let closedPort = 0;

type Run = { status: number | null; stdout: string; stderr: string };
// The daemon under test lives in this process, so the hook child must be awaited asynchronously: a blocking
// spawnSync would freeze the event loop and the child could never be answered.
const run = (script: string, env: Record<string, string>, input = '') => new Promise<Run>((resolve) => {
  const child = spawn(process.execPath, [script], { env: { ...process.env, HUSH_PORT: String(port), HUSH_DATA: tmp, ...env } });
  let stdout = '', stderr = '';
  child.stdout.on('data', (d) => (stdout += d));
  child.stderr.on('data', (d) => (stderr += d));
  child.on('close', (status) => resolve({ status, stdout, stderr }));
  child.stdin.end(input);
});
const context = (result: Run) => JSON.parse(result.stdout).hookSpecificOutput.additionalContext as string;

before(async () => {
  mock.method(console, 'log', () => {});
  daemon = startDaemon({ port: 0, data: tmp, upstream: 'http://127.0.0.1:9', exit: () => {}, detector: { ready: () => true, load: async () => {}, detect: async (text) => regexDetect(text) } });
  await once(daemon, 'listening');
  port = (daemon.address() as { port: number }).port;
  const probe = http.createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  closedPort = (probe.address() as { port: number }).port;
  probe.close();
  await once(probe, 'close');
});

after(() => { daemon.closeAllConnections(); daemon.close(); });

test('hook.ts: forwards the event and prints the daemon decision', async () => {
  const result = await run(HOOK, {}, JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git push --force origin main' }, cwd: tmp, session_id: 's' }));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, 'deny');
});

test('hook.ts: exits 2 and names the install command when the daemon is unreachable', async () => {
  const result = await run(HOOK, { HUSH_PORT: String(closedPort) }, JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'ls' } }));
  assert.equal(result.status, 2);
  assert.match(result.stderr, /privacy daemon unavailable .* tool call blocked\. Run: npm i -g cc-hush && cc-hush install/);
});

test('ensure-daemon.ts: reports a running daemon and stays quiet when the proxy is in use', async () => {
  const result = await run(ENSURE, { ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}` });
  assert.equal(result.status, 0, result.stderr);
  assert.match(context(result), /^cc-hush daemon v\d+\.\d+\.\d+ running \(model ready\)\./);
  assert.doesNotMatch(context(result), /WARNING/);
});

test('ensure-daemon.ts: warns when ANTHROPIC_BASE_URL bypasses the proxy', async () => {
  const result = await run(ENSURE, { ANTHROPIC_BASE_URL: 'http://127.0.0.1:8787/w/claude' });
  assert.match(context(result), /WARNING: ANTHROPIC_BASE_URL is "http:\/\/127\.0\.0\.1:8787\/w\/claude"/);
});

test('ensure-daemon.ts: with no daemon and no cc-hush on PATH it says so', async () => {
  const result = await run(ENSURE, { HUSH_PORT: String(closedPort), PATH: '', Path: '', ANTHROPIC_BASE_URL: `http://127.0.0.1:${closedPort}` });
  assert.equal(result.status, 0, result.stderr);
  assert.match(context(result), /not reachable\. Install with `npm i -g cc-hush && cc-hush install`/);
});

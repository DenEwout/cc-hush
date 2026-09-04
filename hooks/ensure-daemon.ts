import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const DATA = process.env.CLAUDE_PLUGIN_DATA ?? path.join(os.homedir(), '.claude', 'plugins', 'data', 'hush');
const VERSION: string = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const BASE_URL = 'http://127.0.0.1:47831';
const HEALTH_TIMEOUT_MS = 1500;
const STARTUP_WAIT_MS = 1500;
const SHUTDOWN_WAIT_MS = 500;
const PROXY_URL = /^http:\/\/(127\.0\.0\.1|localhost):47831\/?$/;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const dependenciesInstalled = () => fs.existsSync(path.join(ROOT, 'node_modules', '@huggingface', 'transformers'));
const token = () => { try { return fs.readFileSync(path.join(DATA, 'token'), 'utf8').trim(); } catch { return ''; } };

async function health(): Promise<{ version: string; model: string } | null> {
  try {
    const response = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS) });
    const body = response.ok ? await response.json() : null;
    return body?.ok === true && typeof body.version === 'string' ? body : null;
  } catch { return null; }
}

function startDetachedDaemon() {
  fs.mkdirSync(DATA, { recursive: true });
  const log = fs.openSync(path.join(DATA, 'daemon.log'), 'a');
  spawn(process.execPath, [path.join(ROOT, 'daemon', 'server.ts')], {
    detached: true, stdio: ['ignore', log, log], env: { ...process.env, CLAUDE_PLUGIN_DATA: DATA }, windowsHide: true,
  }).unref();
}

async function stopDaemon() {
  await fetch(`${BASE_URL}/shutdown`, { method: 'POST', headers: { 'x-hush-token': token() } }).catch(() => {});
  await sleep(SHUTDOWN_WAIT_MS);
}

async function ensureDaemonAtCurrentVersion(): Promise<string> {
  if (!dependenciesInstalled()) return `cc-hush: dependencies missing. Run the hush-setup skill (npm install in ${ROOT}). The privacy proxy is NOT running.`;
  let running = await health();
  const outdated = running && running.version !== VERSION;
  if (outdated) { await stopDaemon(); running = null; }
  if (!running) { startDetachedDaemon(); await sleep(STARTUP_WAIT_MS); running = await health(); }
  return running
    ? `cc-hush daemon v${running.version} running (model ${running.model}).`
    : `cc-hush daemon starting; check ${path.join(DATA, 'daemon.log')} if /health stays down.`;
}

function baseUrlWarning(): string {
  const baseUrl = process.env.ANTHROPIC_BASE_URL ?? '';
  if (PROXY_URL.test(baseUrl)) return '';
  const current = baseUrl ? `"${baseUrl}"` : 'not set';
  return `\nWARNING: ANTHROPIC_BASE_URL is ${current}; API traffic is NOT going through the cc-hush proxy. Set it to ${BASE_URL} in ~/.claude/settings.json env and restart. Tell the user this first.`;
}

const status = (await ensureDaemonAtCurrentVersion()) + baseUrlWarning();

process.stdout.write(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: 'SessionStart',
    additionalContext: `${status}\nPII appears as <PII:label:n> tokens; use them verbatim, never guess real values. See the hush-guide skill for tokens, size-cap messages and guard denials.`,
  },
}));

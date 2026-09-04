import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const DATA = process.env.HUSH_DATA ?? path.join(os.homedir(), '.cc-hush');
const BASE_URL = 'http://127.0.0.1:47831';
const HEALTH_TIMEOUT_MS = 1500;
const STARTUP_WAIT_MS = 1500;
const PROXY_URL = /^http:\/\/(127\.0\.0\.1|localhost):47831\/?$/;
const INSTALL_HINT = 'npm i -g cc-hush && cc-hush install';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function health(): Promise<{ version: string; model: string } | null> {
  try {
    const response = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS) });
    const body = response.ok ? await response.json() : null;
    return body?.ok === true && typeof body.version === 'string' ? body : null;
  } catch { return null; }
}

function startDaemonOutsideService() {
  const launcher = path.join(DATA, 'start.vbs');
  const supervised = process.platform === 'win32' && fs.existsSync(launcher);
  const [command, args] = supervised ? ['wscript.exe', ['//B', '//Nologo', launcher]] : ['cc-hush', ['start', '--log']];
  spawn(command, args, { detached: true, stdio: 'ignore', shell: !supervised && process.platform === 'win32', windowsHide: true })
    .on('error', () => {})
    .unref();
}

async function ensureDaemon(): Promise<string> {
  let running = await health();
  if (running) return `cc-hush daemon v${running.version} running (model ${running.model}).`;
  startDaemonOutsideService();
  await sleep(STARTUP_WAIT_MS);
  running = await health();
  return running
    ? `cc-hush daemon v${running.version} started by this hook, not by the startup service (model ${running.model}). Run \`cc-hush install\` so it starts at logon.`
    : `cc-hush daemon not reachable. Install with \`${INSTALL_HINT}\`, or read ${path.join(DATA, 'daemon.log')}. Every hooked tool call is blocked until it is up.`;
}

function baseUrlWarning(): string {
  const baseUrl = process.env.ANTHROPIC_BASE_URL ?? '';
  if (PROXY_URL.test(baseUrl)) return '';
  const current = baseUrl ? `"${baseUrl}"` : 'not set';
  return `\nWARNING: ANTHROPIC_BASE_URL is ${current}; API traffic is NOT going through the cc-hush proxy. Set it to ${BASE_URL} in ~/.claude/settings.json env and restart. Tell the user this first.`;
}

const status = (await ensureDaemon()) + baseUrlWarning();

process.stdout.write(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: 'SessionStart',
    additionalContext: `${status}\nPII appears as <PII:label:n> tokens; use them verbatim, never guess real values. See the hush-guide skill for tokens, size-cap messages and guard denials.`,
  },
}));

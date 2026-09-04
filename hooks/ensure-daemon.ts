// SessionStart hook: make sure the hush daemon is running at the current version.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const DATA = process.env.CLAUDE_PLUGIN_DATA ?? path.join(os.homedir(), '.claude', 'plugins', 'data', 'hush');
const VERSION: string = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const BASE = 'http://127.0.0.1:47831';

async function health(): Promise<{ version: string; model: string } | null> {
  try {
    const r = await fetch(`${BASE}/health`, { signal: AbortSignal.timeout(1500) });
    if (!r.ok) return null;
    const h = await r.json();
    return h?.ok === true && typeof h.version === 'string' ? h : null;
  } catch { return null; }
}
function token(): string {
  try { return fs.readFileSync(path.join(DATA, 'token'), 'utf8').trim(); } catch { return ''; }
}

function start() {
  fs.mkdirSync(DATA, { recursive: true });
  const log = fs.openSync(path.join(DATA, 'daemon.log'), 'a');
  const child = spawn(process.execPath, [path.join(ROOT, 'daemon', 'server.ts')], {
    detached: true, stdio: ['ignore', log, log], env: { ...process.env, CLAUDE_PLUGIN_DATA: DATA }, windowsHide: true,
  });
  child.unref();
}

let note: string;
if (!fs.existsSync(path.join(ROOT, 'node_modules', '@huggingface', 'transformers'))) {
  note = `cc-hush: dependencies missing. Run the hush-setup skill (npm install in ${ROOT}). The privacy proxy is NOT running.`;
} else {
  let h = await health();
  if (h && h.version !== VERSION) {
    await fetch(`${BASE}/shutdown`, { method: 'POST', headers: { 'x-hush-token': token() } }).catch(() => {});
    await new Promise((r) => setTimeout(r, 500));
    h = null;
  }
  if (!h) { start(); await new Promise((r) => setTimeout(r, 1500)); h = await health(); }
  note = h
    ? `cc-hush daemon v${h.version} running (model ${h.model}).`
    : `cc-hush daemon starting; check ${path.join(DATA, 'daemon.log')} if /health stays down.`;
}

const base = process.env.ANTHROPIC_BASE_URL ?? '';
if (!/^http:\/\/(127\.0\.0\.1|localhost):47831\/?$/.test(base))
  note += `\nWARNING: ANTHROPIC_BASE_URL is ${base ? `"${base}"` : 'not set'}; API traffic is NOT going through the cc-hush proxy. Set it to http://127.0.0.1:47831 in ~/.claude/settings.json env and restart. Tell the user this first.`;

process.stdout.write(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: 'SessionStart',
    additionalContext: `${note}\nPII appears as <PII:label:n> tokens; use them verbatim, never guess real values. See the hush-guide skill for tokens, size-cap messages and guard denials.`,
  },
}));

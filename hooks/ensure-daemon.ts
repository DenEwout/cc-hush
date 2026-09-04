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
    return r.ok ? await r.json() : null;
  } catch { return null; }
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
    await fetch(`${BASE}/shutdown`, { method: 'POST' }).catch(() => {});
    await new Promise((r) => setTimeout(r, 500));
    h = null;
  }
  if (!h) { start(); await new Promise((r) => setTimeout(r, 1500)); h = await health(); }
  note = h
    ? `cc-hush daemon v${h.version} running (model ${h.model}).`
    : `cc-hush daemon starting; check ${path.join(DATA, 'daemon.log')} if /health stays down.`;
}

process.stdout.write(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: 'SessionStart',
    additionalContext: `${note}\nPII appears as <PII:label:n> tokens; use them verbatim, never guess real values. See the hush-guide skill for tokens, size-cap messages and guard denials.`,
  },
}));

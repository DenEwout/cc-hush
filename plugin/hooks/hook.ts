import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const DATA = process.env.HUSH_DATA ?? path.join(os.homedir(), '.cc-hush');
const HOOK_URL = `http://127.0.0.1:${process.env.HUSH_PORT ?? 47831}/hook`;
const DAEMON_TIMEOUT_MS = 25_000;
const EXIT_CODE_BLOCK = 2;

const token = (() => { try { return fs.readFileSync(path.join(DATA, 'token'), 'utf8').trim(); } catch { return ''; } })();

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

const eventNameOf = (raw: string) => { try { return JSON.parse(raw).hook_event_name ?? 'PreToolUse'; } catch { return 'PreToolUse'; } };

const rawEvent = await readStdin();

try {
  const response = await fetch(HOOK_URL, {
    method: 'POST', body: rawEvent, signal: AbortSignal.timeout(DAEMON_TIMEOUT_MS),
    headers: { 'content-type': 'application/json', 'x-hush-token': token },
  });
  if (!response.ok) throw new Error(`daemon answered ${response.status}`);
  process.stdout.write(JSON.stringify(await response.json()));
} catch (error) {
  const blocked = eventNameOf(rawEvent) === 'UserPromptSubmit' ? 'prompt' : 'tool call';
  process.stderr.write(`cc-hush: privacy daemon unavailable (${(error as Error).message}); ${blocked} blocked. Run: npm i -g cc-hush && cc-hush install`);
  process.exit(EXIT_CODE_BLOCK);
}

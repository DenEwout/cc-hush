// Command hook: forwards the event to the daemon and fails closed (exit 2) when it cannot answer.
const chunks: Buffer[] = [];
for await (const c of process.stdin) chunks.push(c);
const raw = Buffer.concat(chunks).toString('utf8');
let event = 'PreToolUse';
try { event = JSON.parse(raw).hook_event_name ?? event; } catch { /* fall through to fail-closed */ }

try {
  const r = await fetch('http://127.0.0.1:47831/hook', { method: 'POST', headers: { 'content-type': 'application/json' }, body: raw, signal: AbortSignal.timeout(25_000) });
  if (!r.ok) throw new Error(`daemon answered ${r.status}`);
  const out = await r.json();
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
} catch (e) {
  process.stderr.write(`cc-hush: privacy daemon unavailable (${(e as Error).message}); ${event === 'UserPromptSubmit' ? 'prompt' : 'tool call'} blocked. Run the hush-setup skill or node hooks/ensure-daemon.ts.`);
  process.exit(2);
}

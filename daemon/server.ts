// cc-hush daemon: API proxy + http hook server on 127.0.0.1:47831.
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { detect, loadModel, modelReady, mcpKeyPassText } from './detect.ts';
import { applySpans, redactKnown, rehydrateDeep, isWhitelisted, dump, size, DEFAULT_POLICY, type Policy } from './vault.ts';
import { guard, findProject, loadSchema, DATA_SOURCE_RE } from './guard.ts';

const ROOT = path.resolve(import.meta.dirname, '..');
export const VERSION: string = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const PORT = 47831;
const SIZE_CAP = 32 * 1024;
const DATA = process.env.CLAUDE_PLUGIN_DATA ?? path.join(os.homedir(), '.claude', 'plugins', 'data', 'hush');
fs.mkdirSync(path.join(DATA, 'models'), { recursive: true });

// ---------- machine config ----------
let machine: { upstream: string; device?: string } = { upstream: 'https://api.anthropic.com' };
try { machine = { ...machine, ...JSON.parse(fs.readFileSync(path.join(DATA, 'config.json'), 'utf8')) }; } catch { /* defaults */ }
const upstream = new URL(process.env.HUSH_UPSTREAM ?? machine.upstream);
const device = process.env.HUSH_DEVICE ?? machine.device ?? (process.platform === 'win32' ? 'dml' : 'cpu');

// ---------- audit ----------
const db = new DatabaseSync(path.join(DATA, 'audit.sqlite'));
db.exec(`CREATE TABLE IF NOT EXISTS audit(ts TEXT, session_id TEXT, event TEXT, tool_name TEXT, label TEXT, count INTEGER, decision TEXT, latency_ms INTEGER)`);
const ins = db.prepare(`INSERT INTO audit VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)`);
function audit(session: string | null, event: string, tool: string | null, labels: Record<string, number>, decision: string, ms: number) {
  const entries = Object.entries(labels);
  if (!entries.length) entries.push(['', 0]);
  for (const [label, count] of entries) ins.run(session, event, tool, label, count, decision, ms);
}
const countLabels = (spans: { label: string }[]) => spans.reduce<Record<string, number>>((a, s) => ((a[s.label] = (a[s.label] ?? 0) + 1), a), {});

// ---------- project policy ----------
const sessionCwd = new Map<string, string>();
let lastCwd: string | undefined;
function policyFor(cwd: string | undefined): Policy {
  const dir = findProject(cwd);
  if (!dir) return DEFAULT_POLICY;
  try {
    const p = JSON.parse(fs.readFileSync(path.join(dir, '.hush', 'config.json'), 'utf8'));
    return { allowlist: p.allowlist ?? [], allowPii: { ...DEFAULT_POLICY.allowPii, ...(p.allowPii ?? {}) } };
  } catch { return DEFAULT_POLICY; }
}

// ---------- redaction ----------
const memo = new Map<string, string>();
// ponytail: unbounded memo; clear it when it passes 50k entries.
function memoized(key: string, fn: () => Promise<string>): Promise<string> {
  const hit = memo.get(key);
  if (hit !== undefined) return Promise.resolve(hit);
  return fn().then((v) => { if (memo.size > 50_000) memo.clear(); memo.set(key, v); return v; });
}
const hash = (s: string) => crypto.createHash('sha1').update(s).digest('hex');

async function scanText(text: string, allowlist: string[], labels: Record<string, number>): Promise<string> {
  return memoized('scan:' + hash(text + '\0' + allowlist.join(',')), async () => {
    const spans = await detect(text, allowlist);
    for (const [l, n] of Object.entries(countLabels(spans))) labels[l] = (labels[l] ?? 0) + n;
    return applySpans(text, spans);
  });
}

type Block = { type: string; text?: string; content?: unknown; tool_use_id?: string; id?: string; name?: string; input?: Record<string, unknown> };

function isDataSource(name: string | undefined, input: Record<string, unknown> | undefined): boolean {
  if (!name) return false;
  if (name === 'WebFetch' || name.startsWith('mcp__')) return true;
  return name === 'Bash' && DATA_SOURCE_RE.test(String(input?.command ?? ''));
}

async function redactResultText(text: string, tool: { name?: string; input?: Record<string, unknown> } | undefined, allowlist: string[], labels: Record<string, number>): Promise<string> {
  if (!isDataSource(tool?.name, tool?.input)) return redactKnown(text);
  if (Buffer.byteLength(text) > SIZE_CAP)
    return `Output too large for PII filter (${Math.round(Buffer.byteLength(text) / 1024)} KB). Narrow the query: head, grep, LIMIT, or a smaller page.`;
  const pre = tool?.name?.startsWith('mcp__') ? mcpKeyPassText(text) : text;
  return scanText(pre, allowlist, labels);
}

export async function redactBody(body: any, allowlist: string[]): Promise<Record<string, number>> {
  const labels: Record<string, number> = {};
  if (!Array.isArray(body?.messages)) return labels;
  const uses = new Map<string, { name?: string; input?: Record<string, unknown> }>();
  for (const msg of body.messages) {
    if (msg.role === 'assistant' && Array.isArray(msg.content)) {
      for (const b of msg.content as Block[]) if (b.type === 'tool_use' && b.id) uses.set(b.id, { name: b.name, input: b.input });
      continue;
    }
    if (msg.role !== 'user') continue;
    if (typeof msg.content === 'string') { msg.content = await scanText(msg.content, allowlist, labels); continue; }
    if (!Array.isArray(msg.content)) continue;
    for (const b of msg.content as Block[]) {
      if (b.type === 'text' && typeof b.text === 'string') b.text = await scanText(b.text, allowlist, labels);
      else if (b.type === 'tool_result') {
        const tool = b.tool_use_id ? uses.get(b.tool_use_id) : undefined;
        if (typeof b.content === 'string') b.content = await redactResultText(b.content, tool, allowlist, labels);
        else if (Array.isArray(b.content))
          for (const c of b.content as Block[]) if (c.type === 'text' && typeof c.text === 'string') c.text = await redactResultText(c.text, tool, allowlist, labels);
      }
    }
  }
  return labels;
}

// ---------- hooks ----------
async function handleHook(ev: any): Promise<unknown> {
  const t0 = Date.now();
  const session = ev.session_id ?? null;
  if (ev.cwd) { sessionCwd.set(session, ev.cwd); lastCwd = ev.cwd; }
  const policy = policyFor(ev.cwd);

  if (ev.hook_event_name === 'UserPromptSubmit') {
    const spans = await detect(String(ev.prompt ?? ''), policy.allowlist);
    const secrets = spans.filter((s) => s.label === 'secret');
    const decision = secrets.length ? 'block' : 'allow';
    audit(session, 'UserPromptSubmit', null, countLabels(spans), decision, Date.now() - t0);
    if (secrets.length) return { decision: 'block', reason: `cc-hush: prompt contains ${secrets.length} secret(s). Remove the secret and reference it by name or env var instead.` };
    return {};
  }

  if (ev.hook_event_name === 'PreToolUse') {
    const name: string = ev.tool_name ?? '';
    let input: Record<string, unknown> = ev.tool_input ?? {};
    const out: Record<string, unknown> = { hookEventName: 'PreToolUse' };
    let decision = 'allow';
    let rehydrated = false;
    if (isWhitelisted(name, policy)) {
      const r = rehydrateDeep(input);
      if (JSON.stringify(r) !== JSON.stringify(input)) { input = r; out.updatedInput = input; rehydrated = true; }
    }
    if (name === 'Bash' || name.startsWith('mcp__')) {
      const v = guard(name, input, ev.cwd ?? process.cwd(), loadSchema(findProject(ev.cwd)));
      if (v) { decision = v.decision; out.permissionDecision = v.decision; out.permissionDecisionReason = `cc-hush: ${v.reason}`; }
    }
    audit(session, 'PreToolUse', name, {}, decision + (rehydrated ? '+rehydrate' : ''), Date.now() - t0);
    return { hookSpecificOutput: out };
  }
  return {};
}

// ---------- proxy ----------
function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((res, rej) => { const c: Buffer[] = []; req.on('data', (d) => c.push(d)); req.on('end', () => res(Buffer.concat(c))); req.on('error', rej); });
}

function json(res: http.ServerResponse, code: number, body: unknown) {
  const s = JSON.stringify(body);
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(s) });
  res.end(s);
}

let ready: Promise<void>;

async function proxy(req: http.IncomingMessage, res: http.ServerResponse) {
  const t0 = Date.now();
  let body = await readBody(req);
  await ready; // hold requests until the model is loaded: nothing leaves unredacted
  if (req.method === 'POST' && body.length) {
    try {
      const parsed = JSON.parse(body.toString('utf8'));
      let sid: string | null = null;
      try { sid = JSON.parse(parsed.metadata?.user_id ?? '{}').session_id ?? null; } catch { /* no session in metadata */ }
      const cwd = (sid && sessionCwd.get(sid)) || lastCwd;
      const labels = await redactBody(parsed, policyFor(cwd).allowlist);
      body = Buffer.from(JSON.stringify(parsed));
      audit(sid, 'proxy', null, labels, 'redacted', Date.now() - t0);
    } catch (e) { console.error('[hush] body not JSON, forwarded as-is', (e as Error).message); }
  }
  const headers: http.OutgoingHttpHeaders = { ...req.headers, host: upstream.host, 'content-length': body.length };
  delete headers['transfer-encoding'];
  const mod = upstream.protocol === 'https:' ? https : http;
  const up = mod.request({ host: upstream.hostname, port: upstream.port || undefined, method: req.method, path: upstream.pathname.replace(/\/$/, '') + req.url, headers }, (r) => {
    const h = { ...r.headers }; delete h['transfer-encoding'];
    res.writeHead(r.statusCode ?? 502, h);
    r.pipe(res);
  });
  up.on('error', (e) => json(res, 502, { type: 'error', error: { type: 'api_error', message: `cc-hush: upstream ${upstream.href} unreachable: ${e.message}` } }));
  up.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = req.url ?? '/';
  try {
    if (url === '/health') return json(res, 200, { ok: true, version: VERSION, model: modelReady() ? 'ready' : 'loading', device, upstream: upstream.href, vault: size(), pid: process.pid });
    if (url === '/debug/vault') return json(res, 200, dump());
    if (url === '/shutdown' && req.method === 'POST') { json(res, 200, { bye: true }); setTimeout(() => process.exit(0), 50); return; }
    if (url === '/hook' && req.method === 'POST') {
      await ready;
      const ev = JSON.parse((await readBody(req)).toString('utf8'));
      return json(res, 200, await handleHook(ev));
    }
    await proxy(req, res);
  } catch (e) {
    console.error('[hush]', e);
    if (!res.headersSent) json(res, 500, { error: String(e) });
  }
});
server.keepAliveTimeout = 65_000;
server.requestTimeout = 0;
server.headersTimeout = 0;

server.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EADDRINUSE') { console.log('[hush] port in use, another daemon won'); process.exit(0); }
  throw e;
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[hush] v${VERSION} listening on 127.0.0.1:${PORT}, upstream ${upstream.href}, device ${device}`);
  ready = loadModel(path.join(DATA, 'models'), device).catch((e) => { console.error('[hush] model load failed', e); process.exit(1); });
});

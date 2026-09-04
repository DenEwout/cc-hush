import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { detect, loadModel, modelReady, mcpKeyPassText } from './detect.ts';
import { applySpans, redactKnown, rehydrateDeep, isWhitelisted, dump, size, DEFAULT_POLICY, type Policy, type Span } from './vault.ts';
import { guard, findProject, loadSchema, DATA_SOURCE_RE } from './guard.ts';
import { CONFIG_FILE, DATA, PORT, TOKEN_FILE } from './paths.ts';

const ROOT = path.resolve(import.meta.dirname, '..');
const VERSION: string = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const TOOL_RESULT_SIZE_CAP_BYTES = 32 * 1024;
const REDACTION_CACHE_MAX_ENTRIES = 50_000;
const SHUTDOWN_GRACE_MS = 50;
fs.mkdirSync(path.join(DATA, 'models'), { recursive: true });

const readJson = (file: string) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return undefined; } };

const machineConfig = readJson(CONFIG_FILE) ?? {};
const upstream = new URL(process.env.HUSH_UPSTREAM ?? machineConfig.upstream ?? 'https://api.anthropic.com');
const device: string = process.env.HUSH_DEVICE ?? machineConfig.device ?? 'cpu';

if (!fs.existsSync(TOKEN_FILE)) fs.writeFileSync(TOKEN_FILE, crypto.randomBytes(24).toString('hex'), { mode: 0o600 });
const TOKEN = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
const TOKEN_PROTECTED_PATHS = new Set(['/hook', '/debug/vault', '/shutdown']);
const POST_ONLY_PATHS = new Set(['/hook', '/shutdown']);

const cwdBySession = new Map<string, string>();

function policyFor(cwd: string | undefined): Policy {
  const projectDir = findProject(cwd);
  const config = projectDir && readJson(path.join(projectDir, '.hush', 'config.json'));
  if (!config) return DEFAULT_POLICY;
  return { allowlist: config.allowlist ?? [], allowPii: { ...DEFAULT_POLICY.allowPii, ...config.allowPii } };
}

const db = new DatabaseSync(path.join(DATA, 'audit.sqlite'));
db.exec(`CREATE TABLE IF NOT EXISTS audit(ts TEXT, session_id TEXT, event TEXT, tool_name TEXT, label TEXT, count INTEGER, decision TEXT, latency_ms INTEGER)`);
const insertAuditRow = db.prepare(`INSERT INTO audit VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)`);

type LabelCounts = Record<string, number>;

function audit(session: string | null | undefined, event: string, tool: string | null, labels: LabelCounts, decision: string, startedAt: number) {
  const rows = Object.entries(labels).length ? Object.entries(labels) : [['', 0] as [string, number]];
  for (const [label, count] of rows) insertAuditRow.run(session ?? null, event, tool, label, count, decision, Date.now() - startedAt);
}

function countLabels(into: LabelCounts, spans: Span[]) {
  for (const span of spans) into[span.label] = (into[span.label] ?? 0) + 1;
}

const redactionByHash = new Map<string, Promise<{ text: string; spans: Span[] }>>();
const sha1 = (s: string) => crypto.createHash('sha1').update(s).digest('hex');

type Block = { type: string; text?: string; content?: unknown; tool_use_id?: string; id?: string; name?: string; input?: Record<string, unknown> };
type ToolUse = { name?: string; input?: Record<string, unknown> };
const blocksOf = (content: unknown): Block[] => (Array.isArray(content) ? content : []);

function isExternalDataSource(tool?: ToolUse): boolean {
  const name = tool?.name ?? '';
  if (name === 'WebFetch' || name.startsWith('mcp__')) return true;
  return name === 'Bash' && DATA_SOURCE_RE.test(String(tool?.input?.command ?? ''));
}

class RequestRedaction {
  labels: LabelCounts = {};
  private allowlist: string[];
  constructor(allowlist: string[]) { this.allowlist = allowlist; }

  private async scanWithModel(text: string): Promise<string> {
    const key = sha1(text + '\0' + this.allowlist.join(','));
    let pending = redactionByHash.get(key);
    const firstScan = !pending;
    if (!pending) {
      pending = detect(text, this.allowlist).then((spans) => ({ text: applySpans(text, spans), spans }));
      pending.catch(() => redactionByHash.delete(key));
      if (redactionByHash.size > REDACTION_CACHE_MAX_ENTRIES) redactionByHash.clear();
      redactionByHash.set(key, pending);
    }
    const { text: redacted, spans } = await pending;
    if (firstScan) countLabels(this.labels, spans);
    return redacted;
  }

  private async scanWithRegexAndVault(text: string): Promise<string> {
    const spans = await detect(text, this.allowlist, false);
    countLabels(this.labels, spans);
    return redactKnown(applySpans(text, spans));
  }

  private async redactToolResult(text: string, tool?: ToolUse): Promise<string> {
    if (!isExternalDataSource(tool)) return this.scanWithRegexAndVault(text);
    const bytes = Buffer.byteLength(text);
    if (bytes > TOOL_RESULT_SIZE_CAP_BYTES) return `Output too large for PII filter (${Math.round(bytes / 1024)} KB). Narrow the query: head, grep, LIMIT, or a smaller page.`;
    const isMcpResult = tool!.name!.startsWith('mcp__');
    return this.scanWithModel(isMcpResult ? mcpKeyPassText(text) : text);
  }

  private async mapText(content: unknown, transform: (text: string) => Promise<string>): Promise<unknown> {
    if (typeof content === 'string') return transform(content);
    for (const block of blocksOf(content)) if (block.type === 'text' && typeof block.text === 'string') block.text = await transform(block.text);
    return content;
  }

  async redactBody(body: any): Promise<void> {
    body.system = await this.mapText(body.system, (text) => this.scanWithModel(text));
    const toolUseById = new Map<string, ToolUse>();
    for (const message of body.messages ?? []) {
      if (message.role === 'assistant') {
        for (const block of blocksOf(message.content)) if (block.type === 'tool_use' && block.id) toolUseById.set(block.id, { name: block.name, input: block.input });
      } else if (message.role === 'user') {
        message.content = await this.mapText(message.content, (text) => this.scanWithModel(text));
        for (const block of blocksOf(message.content)) {
          if (block.type !== 'tool_result') continue;
          const tool = toolUseById.get(block.tool_use_id ?? '');
          block.content = await this.mapText(block.content, (text) => this.redactToolResult(text, tool));
        }
      }
    }
  }
}

const NETWORK_COMMAND = /\b(curl|wget|ssh|scp|sftp|rsync|nc|ncat|telnet|gh|aws|gcloud|az|kubectl|helm|mail|mailx|sendmail|http|xh|Invoke-WebRequest|Invoke-RestMethod)\b|\bgit\s+(push|remote)\b|\b(docker|npm|cargo|twine)\s+(push|publish|upload)\b/i;

const deny = (reason: string) => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `cc-hush: ${reason}` } });
const block = (reason: string) => ({ decision: 'block', reason: `cc-hush: ${reason}` });

async function onUserPromptSubmit(event: any, policy: Policy, startedAt: number) {
  const spans = await detect(String(event.prompt ?? ''), policy.allowlist);
  const secretCount = spans.filter((s) => s.label === 'secret').length;
  const labels: LabelCounts = {};
  countLabels(labels, spans);
  audit(event.session_id, 'UserPromptSubmit', null, labels, secretCount ? 'block' : 'allow', startedAt);
  if (!secretCount) return {};
  return block(`prompt contains ${secretCount} secret(s). Remove the secret and reference it by name or env var instead.`);
}

function onPreToolUse(event: any, policy: Policy, startedAt: number) {
  const toolName: string = event.tool_name ?? '';
  let input: Record<string, unknown> = event.tool_input ?? {};
  const output: Record<string, unknown> = { hookEventName: 'PreToolUse' };
  let rehydrated = false;

  if (isWhitelisted(toolName, policy)) {
    const withRealValues = rehydrateDeep(input);
    rehydrated = JSON.stringify(withRealValues) !== JSON.stringify(input);
    const wouldLeaveTheMachine = toolName === 'Bash' && NETWORK_COMMAND.test(String(input.command ?? ''));
    if (rehydrated && wouldLeaveTheMachine) {
      audit(event.session_id, 'PreToolUse', toolName, {}, 'deny', startedAt);
      return deny('refusing to rehydrate PII tokens into a command that can send data off the machine. Ask the user to run this step.');
    }
    if (rehydrated) input = output.updatedInput = withRealValues;
  }

  let decision = 'allow';
  const runsShellOrSql = toolName === 'Bash' || toolName.startsWith('mcp__');
  if (runsShellOrSql) {
    const cwd = event.cwd ?? process.cwd();
    const verdict = guard(toolName, input, cwd, loadSchema(findProject(cwd)));
    if (verdict) {
      decision = output.permissionDecision = verdict.decision;
      output.permissionDecisionReason = `cc-hush: ${verdict.reason}`;
    }
  }
  audit(event.session_id, 'PreToolUse', toolName, {}, rehydrated ? `${decision}+rehydrate` : decision, startedAt);
  return { hookSpecificOutput: output };
}

async function handleHook(event: any): Promise<unknown> {
  const startedAt = Date.now();
  if (event.session_id && event.cwd) cwdBySession.set(event.session_id, event.cwd);
  const policy = policyFor(event.cwd);
  if (event.hook_event_name === 'UserPromptSubmit') return onUserPromptSubmit(event, policy, startedAt);
  if (event.hook_event_name === 'PreToolUse') return onPreToolUse(event, policy, startedAt);
  return {};
}

async function hookResponseFailingClosed(req: http.IncomingMessage): Promise<unknown> {
  await modelLoaded;
  const event = JSON.parse((await readBody(req)).toString('utf8'));
  try {
    return await handleHook(event);
  } catch (error) {
    console.error('[hush] hook failed, failing closed:', error);
    const reason = `hook error, failing closed: ${(error as Error).message}`;
    return event.hook_event_name === 'PreToolUse' ? deny(reason) : block(reason);
  }
}

function sessionIdOf(body: any): string | null {
  try { return JSON.parse(body.metadata?.user_id ?? '{}').session_id ?? null; } catch { return null; }
}

async function redactRequest(raw: Buffer, startedAt: number): Promise<Buffer> {
  const body = JSON.parse(raw.toString('utf8'));
  const session = sessionIdOf(body);
  const policy = policyFor(session ? cwdBySession.get(session) : undefined);
  const redaction = new RequestRedaction(policy.allowlist);
  await redaction.redactBody(body);
  audit(session, 'proxy', null, redaction.labels, 'redacted', startedAt);
  return Buffer.from(JSON.stringify(body));
}

async function proxy(req: http.IncomingMessage, res: http.ServerResponse) {
  const startedAt = Date.now();
  let clientGone = false;
  res.on('close', () => { clientGone = true; });
  let body = await readBody(req);
  await modelLoaded;
  const hasBodyToRedact = req.method === 'POST' && body.length > 0;
  if (hasBodyToRedact) {
    try {
      body = await redactRequest(body, startedAt);
    } catch (error) {
      console.error('[hush] redaction failed, request dropped:', (error as Error).message);
      audit(null, 'proxy', null, {}, 'dropped', startedAt);
      return apiError(res, `redaction failed, request not forwarded: ${(error as Error).message}`, 400);
    }
  }
  if (clientGone) {
    console.error(`[hush] client left during redaction, not forwarded: ${req.method} ${req.url}`);
    audit(null, 'proxy', null, {}, 'abandoned', startedAt);
    return;
  }
  forwardUpstream(req, res, body);
}

function forwardUpstream(req: http.IncomingMessage, res: http.ServerResponse, body: Buffer) {
  const headers: http.OutgoingHttpHeaders = { ...req.headers, host: upstream.host, 'content-length': body.length };
  delete headers['transfer-encoding'];
  const client = upstream.protocol === 'https:' ? https : http;
  const options = { host: upstream.hostname, port: upstream.port || undefined, method: req.method, path: upstream.pathname.replace(/\/$/, '') + req.url, headers };
  const upstreamRequest = client.request(options, (upstreamResponse) => {
    const status = upstreamResponse.statusCode ?? 502;
    if (status >= 400) console.error(`[hush] upstream ${status} for ${req.method} ${req.url} (client retry ${req.headers['x-stainless-retry-count'] ?? 0}${upstreamResponse.headers['retry-after'] ? `, retry-after ${upstreamResponse.headers['retry-after']}` : ''})`);
    const responseHeaders = { ...upstreamResponse.headers };
    delete responseHeaders['transfer-encoding'];
    res.writeHead(status, responseHeaders);
    upstreamResponse.on('error', (error) => { console.error('[hush] upstream stream broke:', error.message); res.destroy(); });
    upstreamResponse.pipe(res);
  });
  upstreamRequest.on('error', (error) => apiError(res, `upstream ${upstream.href} unreachable: ${error.message}`));
  res.on('close', () => upstreamRequest.destroy());
  upstreamRequest.end(body);
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(chunk)).on('end', () => resolve(Buffer.concat(chunks))).on('error', reject);
  });
}

function json(res: http.ServerResponse, status: number, body: unknown) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
  res.end(payload);
}

const apiError = (res: http.ServerResponse, message: string, status = 502) =>
  res.headersSent ? res.destroy() : json(res, status, { type: 'error', error: { type: 'api_error', message: `cc-hush: ${message}` } });

const health = () => ({ ok: true, version: VERSION, model: modelReady() ? 'ready' : 'loading', device, upstream: upstream.href, vault: size(), pid: process.pid });

let modelLoaded: Promise<void>;

const server = http.createServer(async (req, res) => {
  const url = req.url ?? '/';
  try {
    const hasToken = req.headers['x-hush-token'] === TOKEN;
    if (TOKEN_PROTECTED_PATHS.has(url) && !hasToken) return json(res, 401, { error: `cc-hush: send header x-hush-token from ${TOKEN_FILE}` });
    if (POST_ONLY_PATHS.has(url) && req.method !== 'POST') return json(res, 405, { error: 'POST only' });
    switch (url) {
      case '/health': return json(res, 200, health());
      case '/debug/vault': return json(res, 200, dump());
      case '/shutdown': json(res, 200, { bye: true }); setTimeout(() => process.exit(0), SHUTDOWN_GRACE_MS); return;
      case '/hook': return json(res, 200, await hookResponseFailingClosed(req));
      default: return proxy(req, res);
    }
  } catch (error) {
    console.error('[hush]', error);
    if (!res.headersSent) json(res, 500, { error: String(error) });
  }
});
server.keepAliveTimeout = 65_000;
server.requestTimeout = 0;
server.headersTimeout = 0;

server.on('error', (error: NodeJS.ErrnoException) => {
  if (error.code !== 'EADDRINUSE') throw error;
  console.log('[hush] port in use, another daemon won');
  process.exit(0);
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[hush] v${VERSION} listening on 127.0.0.1:${PORT}, upstream ${upstream.href}, device ${device}`);
  modelLoaded = loadModel(path.join(DATA, 'models'), device).catch((error) => { console.error('[hush] model load failed', error); process.exit(1); });
});

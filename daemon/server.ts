import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { detect, loadModel, modelReady } from './detect.ts';
import { openVault, rehydrateDeep, unresolvedTokens, isWhitelisted, dump, size, DEFAULT_POLICY, type Policy } from './vault.ts';
import { guard, findProject, loadSchema } from './guard.ts';
import { RequestRedaction, countLabels, type Detector, type LabelCounts } from './redaction.ts';
import { DATA, PORT } from './paths.ts';

export type DaemonOptions = { port?: number; data?: string; upstream?: string; device?: string; detector?: Detector; exit?: (code: number) => void };

const VERSION: string = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '..', 'package.json'), 'utf8')).version;
const SHUTDOWN_GRACE_MS = 50;
const TOKEN_PROTECTED_PATHS = new Set(['/hook', '/debug/vault', '/shutdown']);
const POST_ONLY_PATHS = new Set(['/hook', '/shutdown']);
const NETWORK_COMMAND = /\b(curl|wget|ssh|scp|sftp|rsync|nc|ncat|telnet|gh|aws|gcloud|az|kubectl|helm|mail|mailx|sendmail|http|xh|Invoke-WebRequest|Invoke-RestMethod)\b|\bgit\s+(push|remote)\b|\b(docker|npm|cargo|twine)\s+(push|publish|upload)\b/i;

const realDetector: Detector = { detect, load: loadModel, ready: modelReady };
const readJson = (file: string) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return undefined; } };
const deny = (reason: string) => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `cc-hush: ${reason}` } });
const block = (reason: string) => ({ decision: 'block', reason: `cc-hush: ${reason}` });
const sessionIdOf = (body: any): string | null => { try { return JSON.parse(body.metadata?.user_id ?? '{}').session_id ?? null; } catch { return null; } };

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

export function startDaemon(options: DaemonOptions = {}): http.Server {
  const data = options.data ?? DATA;
  const config = readJson(path.join(data, 'config.json')) ?? {};
  const upstream = new URL(options.upstream ?? process.env.HUSH_UPSTREAM ?? config.upstream ?? 'https://api.anthropic.com');
  const device: string = options.device ?? process.env.HUSH_DEVICE ?? config.device ?? 'cpu';
  const detector = options.detector ?? realDetector;
  const exit = options.exit ?? process.exit;
  fs.mkdirSync(path.join(data, 'models'), { recursive: true });

  const tokenFile = path.join(data, 'token');
  if (!fs.existsSync(tokenFile)) fs.writeFileSync(tokenFile, crypto.randomBytes(24).toString('hex'), { mode: 0o600 });
  const token = fs.readFileSync(tokenFile, 'utf8').trim();

  const vault = openVault(path.join(data, 'vault.sqlite'));
  const db = new DatabaseSync(path.join(data, 'audit.sqlite'));
  db.exec(`CREATE TABLE IF NOT EXISTS audit(ts TEXT, session_id TEXT, event TEXT, tool_name TEXT, label TEXT, count INTEGER, decision TEXT, latency_ms INTEGER)`);
  const insertAuditRow = db.prepare(`INSERT INTO audit VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)`);
  function audit(session: string | null | undefined, event: string, tool: string | null, labels: LabelCounts, decision: string, startedAt: number) {
    const rows = Object.entries(labels).length ? Object.entries(labels) : [['', 0] as [string, number]];
    for (const [label, count] of rows) insertAuditRow.run(session ?? null, event, tool, label, count, decision, Date.now() - startedAt);
  }

  const cwdBySession = new Map<string, string>();
  function policyFor(cwd: string | undefined): Policy {
    const projectDir = findProject(cwd);
    const projectConfig = projectDir && readJson(path.join(projectDir, '.hush', 'config.json'));
    if (!projectConfig) return DEFAULT_POLICY;
    return { allowlist: projectConfig.allowlist ?? [], allowPii: { ...DEFAULT_POLICY.allowPii, ...projectConfig.allowPii } };
  }

  const modelLoaded = detector.load(path.join(data, 'models'), device).catch((error) => { console.error('[hush] model load failed', error); exit(1); });

  async function onUserPromptSubmit(event: any, policy: Policy, startedAt: number) {
    const spans = await detector.detect(String(event.prompt ?? ''), policy.allowlist);
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
    const unknownTokens = isWhitelisted(toolName, policy) ? unresolvedTokens(JSON.stringify(input)) : [];
    if (unknownTokens.length) {
      decision = output.permissionDecision = 'ask';
      output.permissionDecisionReason = `cc-hush: ${unknownTokens.length} PII token(s) this daemon cannot resolve (${unknownTokens.slice(0, 3).join(', ')}). They were issued before the vault was persisted, or by another machine. Allowing writes them as literal placeholders; re-fetch the source data to get resolvable tokens.`;
    }
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

  async function redactRequest(raw: Buffer, startedAt: number): Promise<Buffer> {
    const body = JSON.parse(raw.toString('utf8'));
    const session = sessionIdOf(body);
    const policy = policyFor(session ? cwdBySession.get(session) : undefined);
    const redaction = new RequestRedaction(policy.allowlist, detector.detect);
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
    if (req.method === 'POST' && body.length > 0) {
      try {
        body = await redactRequest(body, startedAt);
      } catch (error) {
        console.error('[hush] redaction failed, request dropped:', (error as Error).message);
        audit(null, 'proxy', null, {}, 'dropped', startedAt);
        // 400 rather than 502: the client SDK retries 5xx, and a redaction failure repeats deterministically.
        return apiError(res, `redaction failed, request not forwarded: ${(error as Error).message}`, 400);
      }
    }
    // A client that gave up during a long scan (a user interrupt) must not still cost a full request upstream.
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
      if (status >= 400) {
        let body = '';
        upstreamResponse.on('data', (chunk: Buffer) => { if (body.length < 600) body += chunk.toString('utf8', 0, 600); });
        upstreamResponse.on('end', () => console.error(`[hush] upstream ${status} for ${req.method} ${req.url} (client retry ${req.headers['x-stainless-retry-count'] ?? 0}, retry-after ${upstreamResponse.headers['retry-after'] ?? 'none'}): ${body.replace(/\s+/g, ' ').slice(0, 600)}`));
      }
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

  const health = () => ({ ok: true, version: VERSION, model: detector.ready() ? 'ready' : 'loading', device, upstream: upstream.href, vault: size(), pid: process.pid });

  const server = http.createServer(async (req, res) => {
    const url = req.url ?? '/';
    try {
      const hasToken = req.headers['x-hush-token'] === token;
      if (TOKEN_PROTECTED_PATHS.has(url) && !hasToken) return json(res, 401, { error: `cc-hush: send header x-hush-token from ${tokenFile}` });
      if (POST_ONLY_PATHS.has(url) && req.method !== 'POST') return json(res, 405, { error: 'POST only' });
      switch (url) {
        case '/health': return json(res, 200, health());
        case '/debug/vault': return json(res, 200, dump());
        case '/shutdown': json(res, 200, { bye: true }); setTimeout(() => { server.close(); exit(0); }, SHUTDOWN_GRACE_MS); return;
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
  server.on('close', () => { db.close(); vault.close(); });
  server.on('error', (error: NodeJS.ErrnoException) => {
    if (error.code !== 'EADDRINUSE') throw error;
    // Exit 0 on purpose: launchd, systemd and start.vbs only restart on failure, and another daemon already serves.
    console.log('[hush] port in use, another daemon won');
    exit(0);
  });
  server.listen(options.port ?? PORT, '127.0.0.1', () => {
    const { port } = server.address() as { port: number };
    console.log(`[hush] v${VERSION} listening on 127.0.0.1:${port}, upstream ${upstream.href}, device ${device}`);
  });
  return server;
}

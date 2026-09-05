import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { startDaemon } from '../daemon/server.ts';
import { regexDetect, mergeSpans } from '../daemon/detect.ts';
import { tokenize } from '../daemon/vault.ts';
import type { Detector } from '../daemon/redaction.ts';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const KNOWN_NAME = 'Jan Vermeulen';
const STREAM_BODY = 'event: message_start\ndata: {}\n\nevent: content_block_delta\ndata: {"delta":{"text":"po"}}\n\nevent: message_stop\ndata: {}\n\n';

const modelCalls: string[] = [];
const fakeDetector: Detector = {
  ready: () => true,
  load: async () => {},
  detect: async (text, allowlist, useModel = true) => {
    if (useModel) modelCalls.push(text);
    if (text.includes('BOOM')) throw new Error('boom');
    if (text.includes('SLOW')) await sleep(400);
    const spans = regexDetect(text);
    if (useModel) for (const m of text.matchAll(new RegExp(KNOWN_NAME, 'g'))) spans.push({ start: m.index!, end: m.index! + KNOWN_NAME.length, label: 'private_person', score: 0.99 });
    return mergeSpans(spans, text, allowlist);
  },
};

type Seen = { method?: string; url?: string; headers: http.IncomingHttpHeaders; body: string };
const seen: Seen[] = [];
const fakeUpstream = http.createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => (body += chunk)).on('end', () => {
    seen.push({ method: req.method, url: req.url, headers: req.headers, body });
    const status = Number(req.headers['x-test-status'] ?? 200);
    if (status !== 200) {
      res.writeHead(status, { 'content-type': 'application/json', 'retry-after': '7' });
      return res.end('{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}');
    }
    if (req.headers['x-test-stream']) {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      const [head, ...rest] = STREAM_BODY.split(/(?<=\n\n)/);
      res.write(head);
      return setTimeout(() => res.end(rest.join('')), 50);
    }
    res.writeHead(200, { 'content-type': 'application/json', 'x-upstream': 'fake' });
    res.end(JSON.stringify({ echo: body ? JSON.parse(body) : null }));
  });
});

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hush-proxy-'));
let hush = '';
let upstreamPort = 0;
let token = '';
let daemon: http.Server;
const withToken = () => ({ 'x-hush-token': token, 'content-type': 'application/json' });
const post = (url: string, body: unknown, headers: Record<string, string> = {}, init: RequestInit = {}) =>
  fetch(`${hush}${url}`, { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json', ...headers }, ...init });
const hook = (event: unknown) => post('/hook', event, withToken()).then((r) => r.json() as Promise<any>);

before(async () => {
  mock.method(console, 'error', () => {});
  mock.method(console, 'log', () => {});
  fakeUpstream.listen(0, '127.0.0.1');
  await once(fakeUpstream, 'listening');
  upstreamPort = (fakeUpstream.address() as { port: number }).port;
  daemon = startDaemon({ port: 0, data: tmp, upstream: `http://127.0.0.1:${upstreamPort}/w/claude`, detector: fakeDetector, exit: () => {} });
  await once(daemon, 'listening');
  hush = `http://127.0.0.1:${(daemon.address() as { port: number }).port}`;
  token = fs.readFileSync(path.join(tmp, 'token'), 'utf8').trim();
});

after(() => {
  daemon.closeAllConnections(); daemon.close();
  fakeUpstream.closeAllConnections(); fakeUpstream.close();
});

test('proxy: path prefix, host rewrite, auth headers untouched, body redacted with recomputed length', async () => {
  const r = await post('/v1/messages?beta=true', { model: 'm', messages: [{ role: 'user', content: `Mail ${KNOWN_NAME}, IBAN BE68 5390 0754 7034` }] },
    { 'x-api-key': 'sk-ant-test', 'anthropic-version': '2023-06-01', authorization: 'Bearer t' });
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-upstream'), 'fake');
  const last = seen.at(-1)!;
  assert.equal(last.method, 'POST');
  assert.equal(last.url, '/w/claude/v1/messages?beta=true');
  assert.equal(last.headers.host, `127.0.0.1:${upstreamPort}`);
  assert.equal(last.headers['x-api-key'], 'sk-ant-test');
  assert.equal(last.headers.authorization, 'Bearer t');
  assert.equal(last.headers['anthropic-version'], '2023-06-01');
  assert.equal(Number(last.headers['content-length']), Buffer.byteLength(last.body));
  const forwarded: string = JSON.parse(last.body).messages[0].content;
  assert.doesNotMatch(forwarded, /Vermeulen|BE68/);
  assert.match(forwarded, /^Mail <PII:person:\d+>, IBAN <PII:account:\d+>$/);
});

test('proxy: Read results get regex and vault only, MCP results get the model, oversized MCP results get the cap message', async () => {
  const body = { messages: [
    { role: 'assistant', content: [
      { type: 'tool_use', id: 'r1', name: 'Read', input: {} },
      { type: 'tool_use', id: 'm1', name: 'mcp__jira__get', input: {} },
      { type: 'tool_use', id: 'm2', name: 'mcp__jira__list', input: {} } ] },
    { role: 'user', content: [
      { type: 'tool_result', tool_use_id: 'r1', content: `file says ${KNOWN_NAME} and Piet Peeters` },
      { type: 'tool_result', tool_use_id: 'm1', content: [{ type: 'text', text: `issue by Piet Peeters, contact ${KNOWN_NAME}` }] },
      { type: 'tool_result', tool_use_id: 'm2', content: 'x'.repeat(33 * 1024) } ] } ] };
  const before = modelCalls.length;
  assert.equal((await post('/v1/messages', body)).status, 200);
  const results = JSON.parse(seen.at(-1)!.body).messages[1].content;
  const personToken = tokenize(KNOWN_NAME, 'private_person');
  assert.equal(results[0].content, `file says ${personToken} and Piet Peeters`);
  assert.equal(results[1].content[0].text, `issue by Piet Peeters, contact ${personToken}`);
  assert.match(results[2].content, /^Output too large for PII filter \(33 KB\)/);
  assert.equal(modelCalls.slice(before).filter((t) => t.startsWith('file says')).length, 0, 'Read result never reaches the model');
});

test('proxy: streaming response passes through byte for byte', async () => {
  const r = await post('/v1/messages', { stream: true, messages: [] }, { 'x-test-stream': '1' });
  assert.equal(r.headers.get('content-type'), 'text/event-stream');
  assert.equal(await r.text(), STREAM_BODY);
});

test('proxy: upstream 429 with retry-after reaches the client unchanged', async () => {
  const r = await post('/v1/messages', { messages: [] }, { 'x-test-status': '429' });
  assert.equal(r.status, 429);
  assert.equal(r.headers.get('retry-after'), '7');
  assert.equal((await r.json() as any).error.type, 'rate_limit_error');
});

test('proxy: GET passes through without a body', async () => {
  const r = await fetch(`${hush}/v1/models`, { headers: { 'x-api-key': 'k' } });
  assert.equal(r.status, 200);
  assert.deepEqual([seen.at(-1)!.method, seen.at(-1)!.url, seen.at(-1)!.body], ['GET', '/w/claude/v1/models', '']);
});

test('proxy: a request abandoned during redaction is never forwarded', async () => {
  const before = seen.length;
  await assert.rejects(post('/v1/messages', { messages: [{ role: 'user', content: `SLOW abandoned ${Date.now()}` }] }, {}, { signal: AbortSignal.timeout(100) }));
  await sleep(700);
  assert.equal(seen.length, before);
});

test('proxy: concurrent identical blocks share one model pass', async () => {
  const text = `SLOW twins ${Date.now()}`;
  const body = { messages: [{ role: 'user', content: text }] };
  const [a, b] = await Promise.all([post('/v1/messages', body), post('/v1/messages', body)]);
  assert.deepEqual([a.status, b.status], [200, 200]);
  assert.equal(modelCalls.filter((t) => t === text).length, 1);
});

test('proxy: redaction failure answers 400 and forwards nothing', async () => {
  const before = seen.length;
  const r = await post('/v1/messages', { messages: [{ role: 'user', content: 'BOOM' }] });
  assert.equal(r.status, 400);
  assert.match((await r.json() as any).error.message, /redaction failed/);
  assert.equal(seen.length, before);
});

test('hook endpoint: token gate, guard deny, secret block, rehydration only for whitelisted tools', async () => {
  assert.equal((await post('/hook', {})).status, 401);
  assert.equal((await fetch(`${hush}/hook`, { headers: withToken() })).status, 405);
  const denied = await hook({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git push --force origin main' }, cwd: tmp, session_id: 's1' });
  assert.equal(denied.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(denied.hookSpecificOutput.permissionDecisionReason, /^cc-hush: Force push/);
  const blocked = await hook({ hook_event_name: 'UserPromptSubmit', prompt: 'key AKIAIOSFODNN7EXAMPLE', cwd: tmp, session_id: 's1' });
  assert.equal(blocked.decision, 'block');
  const personToken = tokenize(KNOWN_NAME, 'private_person');
  const write = await hook({ hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: 'x', content: `hello ${personToken}` }, cwd: tmp, session_id: 's1' });
  assert.equal(write.hookSpecificOutput.updatedInput.content, `hello ${KNOWN_NAME}`);
  const bash = await hook({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: `echo ${personToken}` }, cwd: tmp, session_id: 's1' });
  assert.equal(bash.hookSpecificOutput.updatedInput, undefined);
  const stale = await hook({ hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: 'x', content: `${personToken} and <PII:person:999>` }, cwd: tmp, session_id: 's1' });
  assert.equal(stale.hookSpecificOutput.permissionDecision, 'ask');
  assert.match(stale.hookSpecificOutput.permissionDecisionReason, /1 PII token\(s\) this daemon cannot resolve \(<PII:person:999>\)/);
  assert.equal(stale.hookSpecificOutput.updatedInput.content, `${KNOWN_NAME} and <PII:person:999>`);
});

test('health, vault and audit reflect what happened', async () => {
  const health: any = await fetch(`${hush}/health`).then((r) => r.json());
  assert.equal(health.ok, true);
  assert.equal(health.model, 'ready');
  assert.match(health.upstream, /\/w\/claude$/);
  assert.equal((await fetch(`${hush}/debug/vault`)).status, 401);
  const vault = await fetch(`${hush}/debug/vault`, { headers: withToken() }).then((r) => r.text());
  assert.ok(vault.includes(KNOWN_NAME));
  const rows = new DatabaseSync(path.join(tmp, 'audit.sqlite')).prepare('select event, decision, count(*) n from audit group by 1, 2').all() as { event: string; decision: string; n: number }[];
  const has = (event: string, decision: string) => rows.some((r) => r.event === event && r.decision === decision);
  assert.ok(has('proxy', 'redacted') && has('proxy', 'abandoned') && has('proxy', 'dropped') && has('PreToolUse', 'deny') && has('UserPromptSubmit', 'block'), JSON.stringify(rows));
});

test('shutdown closes the server and asks the process to exit 0', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hush-shutdown-'));
  let exitCode: number | undefined;
  const server = startDaemon({ port: 0, data: dir, upstream: 'http://127.0.0.1:9', detector: fakeDetector, exit: (code) => { exitCode = code; } });
  await once(server, 'listening');
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const ownToken = fs.readFileSync(path.join(dir, 'token'), 'utf8').trim();
  assert.deepEqual(await fetch(`${base}/shutdown`, { method: 'POST', headers: { 'x-hush-token': ownToken } }).then((r) => r.json()), { bye: true });
  await once(server, 'close');
  assert.equal(exitCode, 0);
  await assert.rejects(fetch(`${base}/health`));
});

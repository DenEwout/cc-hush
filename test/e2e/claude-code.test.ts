import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { execFileSync, spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { startDaemon } from '../../daemon/server.ts';

// Runs the real `claude -p` through a real daemon with the real model, using the credentials already on this
// machine. One Haiku call per run, so it is opt-in: `npm run test:e2e`.
const HOME_CONFIG = process.env.CLAUDE_CONFIG_DIR ?? path.join(os.homedir(), '.claude');
const REAL_MODELS = path.join(os.homedir(), '.cc-hush', 'models');
const MODEL = 'claude-haiku-4-5-20251001';
const PLUGIN_ROOT = path.resolve('plugin');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const claudeBin = (() => { try { return execFileSync(process.platform === 'win32' ? 'where.exe' : 'which', ['claude'], { encoding: 'utf8' }).split(/\r?\n/)[0].trim(); } catch { return ''; } })();
const missing = [
  !claudeBin && 'claude on PATH',
  !fs.existsSync(path.join(HOME_CONFIG, '.credentials.json')) && `${HOME_CONFIG}/.credentials.json`,
  !fs.existsSync(REAL_MODELS) && `${REAL_MODELS} (run cc-hush install)`,
].filter(Boolean);

test('e2e: claude -p redacts through cc-hush, hooks fire, Write rehydrates', { skip: missing.length ? `needs ${missing.join(', ')}` : false }, async () => {
  // Long path on purpose: Claude Code treats the 8.3 short form (EWOUTV~1) as a suspicious path and refuses to write there.
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), 'hush-e2e-'));
  const data = path.join(tmp, 'data');
  fs.mkdirSync(data);
  fs.symlinkSync(REAL_MODELS, path.join(data, 'models'), 'junction');

  const daemon = startDaemon({ port: 0, data, upstream: 'https://api.anthropic.com', exit: () => {} });
  await once(daemon, 'listening');
  const base = `http://127.0.0.1:${(daemon.address() as { port: number }).port}`;
  const port = String((daemon.address() as { port: number }).port);
  for (let waited = 0; waited < 120_000; waited += 1000) {
    const health: any = await fetch(`${base}/health`).then((r) => r.json()).catch(() => null);
    if (health?.model === 'ready') break;
    await sleep(1000);
  }

  const configDir = path.join(tmp, 'claude');
  fs.mkdirSync(configDir);
  fs.copyFileSync(path.join(HOME_CONFIG, '.credentials.json'), path.join(configDir, '.credentials.json'));
  const homeState = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.claude.json'), 'utf8'));
  fs.writeFileSync(path.join(configDir, '.claude.json'), JSON.stringify({ hasCompletedOnboarding: true, oauthAccount: homeState.oauthAccount, cachedGrowthBookFeatures: homeState.cachedGrowthBookFeatures, numStartups: 10 }));
  const hooks = JSON.parse(fs.readFileSync(path.join(PLUGIN_ROOT, 'hooks', 'hooks.json'), 'utf8').replaceAll('${CLAUDE_PLUGIN_ROOT}', PLUGIN_ROOT.replaceAll('\\', '/'))).hooks;
  delete hooks.SessionStart;
  const env = { ANTHROPIC_BASE_URL: base, HUSH_PORT: port, HUSH_DATA: data };
  fs.writeFileSync(path.join(configDir, 'settings.json'), JSON.stringify({ env, hooks }, null, 2));

  const outerEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^CLAUDE_?CODE/i.test(key)));
  // Async on purpose: the daemon serving these requests runs in this very process, so a blocking spawnSync would
  // freeze it and Claude Code would wait forever.
  const claude = (prompt: string, ...extra: string[]) => new Promise<any>((resolve, reject) => {
    const child = spawn(claudeBin, ['-p', prompt, '--model', MODEL, '--output-format', 'json', ...extra], { cwd: tmp, env: { ...outerEnv, ...env, CLAUDE_CONFIG_DIR: configDir } });
    child.stdin.end();
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    const timer = setTimeout(() => child.kill(), 240_000);
    child.on('close', (status) => {
      clearTimeout(timer);
      try { resolve({ status, ...JSON.parse(stdout) }); } catch { reject(new Error(`claude exited ${status} without a JSON result\n${stderr}\n${stdout.slice(0, 2000)}`)); }
    });
  });

  let passed = false;
  try {
    const email = 'e2e.person@example.org';
    const run = await claude(`Reply with exactly the word pong. Also use the Write tool to save the requester's email address, and nothing else, into note.txt in the current directory. Requester: ${email}`, '--allowedTools', 'Write');
    assert.match(String(run.result), /pong/i, `claude exited ${run.status}: ${JSON.stringify(run.result)}`);
    assert.ok(!String(run.result).includes(email), 'the model never saw the real address');
    const token = fs.readFileSync(path.join(data, 'token'), 'utf8').trim();
    const vault = await fetch(`${base}/debug/vault`, { headers: { 'x-hush-token': token } }).then((r) => r.text());
    assert.ok(vault.includes(email), 'the address was redacted into the vault before leaving the machine');
    const note = fs.existsSync(path.join(tmp, 'note.txt')) ? fs.readFileSync(path.join(tmp, 'note.txt'), 'utf8').trim() : null;
    assert.equal(note, email, `the Write hook rehydrated the token, so the file holds the real address. run=${JSON.stringify({ status: run.status, turns: run.num_turns, denials: run.permission_denials, result: run.result })}`);
    const audit = new DatabaseSync(path.join(data, 'audit.sqlite'));
    const rows = audit.prepare('select event, tool_name, decision, count(*) n from audit group by 1, 2, 3').all() as { event: string; tool_name: string | null; decision: string }[];
    audit.close();
    const has = (event: string, decision: string, tool: string | null = null) => rows.some((r) => r.event === event && r.decision === decision && (tool === null || r.tool_name === tool));
    assert.ok(has('proxy', 'redacted'), `API traffic went through the proxy: ${JSON.stringify(rows)}`);
    assert.ok(has('UserPromptSubmit', 'allow'), `the UserPromptSubmit hook fired: ${JSON.stringify(rows)}`);
    assert.ok(has('PreToolUse', 'allow+rehydrate', 'Write'), `the PreToolUse hook fired and rehydrated the Write input: ${JSON.stringify(rows)}`);
    passed = true;
  } finally {
    daemon.closeAllConnections();
    daemon.close();
    await once(daemon, 'close');
    fs.rmdirSync(path.join(data, 'models'));
    if (!passed) console.log(`kept for inspection (transcript under claude/projects): ${tmp}`);
    else try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (error) { console.log(`temp dir left behind (${(error as Error).message}): ${tmp}`); }
  }
});

#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { BASE_URL, CONFIG_FILE, DATA, LOG_FILE, TOKEN_FILE } from '../daemon/paths.ts';
import { loadModel } from '../daemon/detect.ts';
import { claudeSettingsFile, configuredBaseUrl, installService, mergeBaseUrl, startService, uninstallService } from '../daemon/service.ts';

const HEALTH_TIMEOUT_MS = 1500;
const SHUTDOWN_WAIT_MS = 500;
const START_WAIT_MS = 20_000;
const USAGE = `usage: cc-hush <command>
  install    download the model, register the startup service, start the daemon, point Claude Code at it
  uninstall  stop the daemon and remove the startup service (data in ${DATA} is kept)
  start      run the daemon in the foreground (--log appends to ${LOG_FILE} instead of stdout)
  stop       ask the running daemon to exit
  status     print /health`;

const [command, ...flags] = process.argv.slice(2);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const token = () => { try { return fs.readFileSync(TOKEN_FILE, 'utf8').trim(); } catch { return ''; } };

async function health(): Promise<{ version: string; model: string; upstream: string } | null> {
  try {
    const response = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS) });
    return response.ok ? await response.json() : null;
  } catch { return null; }
}

async function waitHealthy(ms: number) {
  const deadline = Date.now() + ms;
  let running = await health();
  while (!running && Date.now() < deadline) { await sleep(500); running = await health(); }
  return running;
}

async function stop() {
  const stopped = await fetch(`${BASE_URL}/shutdown`, { method: 'POST', headers: { 'x-hush-token': token() } }).then((r) => r.ok).catch(() => false);
  if (stopped) await sleep(SHUTDOWN_WAIT_MS);
  return stopped;
}

const reportDownload = (event: any) => {
  if (event.status === 'progress') process.stdout.write(`\r${event.file} ${Math.round(event.progress)}%   `);
  if (event.status === 'done') process.stdout.write(`\r${event.file} done\n`);
};

const readJson = (file: string) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return undefined; } };

async function askToChain(settingsJson: string | undefined): Promise<boolean> {
  const current = configuredBaseUrl(settingsJson);
  if (!current || current === BASE_URL || !process.stdin.isTTY) return false;
  const prompt = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await prompt.question(`ANTHROPIC_BASE_URL is "${current}". Chain it behind cc-hush (Claude Code -> cc-hush -> ${current})? [Y/n] `);
  prompt.close();
  return !/^n/i.test(answer.trim());
}

async function planClaudeSettings() {
  const file = claudeSettingsFile();
  const existing = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : undefined;
  try {
    return mergeBaseUrl(existing, await askToChain(existing));
  } catch (error) {
    return { note: `could not parse ${file} (${(error as Error).message}); add {"env":{"ANTHROPIC_BASE_URL":"${BASE_URL}"}} by hand.` };
  }
}

const launcher = { node: process.execPath, script: import.meta.filename };

switch (command) {
  case 'start': {
    fs.mkdirSync(DATA, { recursive: true });
    if (flags.includes('--log')) {
      const log = fs.openSync(LOG_FILE, 'a');
      process.stdout.write = process.stderr.write = ((chunk: string | Uint8Array) => { fs.writeSync(log, chunk); return true; }) as typeof process.stdout.write;
    }
    await import('../daemon/server.ts');
    break;
  }
  case 'install': {
    fs.mkdirSync(path.join(DATA, 'models'), { recursive: true });
    const settings = await planClaudeSettings();
    if (settings.upstream) fs.writeFileSync(CONFIG_FILE, JSON.stringify({ ...readJson(CONFIG_FILE), upstream: settings.upstream }, null, 2) + '\n');
    console.log(`downloading openai/privacy-filter into ${path.join(DATA, 'models')} (about 917 MB the first time)`);
    await loadModel(path.join(DATA, 'models'), 'cpu', reportDownload);
    console.log(installService(launcher));
    if (await stop()) console.log('previous daemon stopped');
    startService();
    const running = await waitHealthy(START_WAIT_MS);
    console.log(running ? `daemon v${running.version} up on ${BASE_URL} (model ${running.model}, upstream ${running.upstream})` : `daemon not reachable yet; check ${LOG_FILE}`);
    if (settings.text) fs.writeFileSync(claudeSettingsFile(), settings.text);
    console.log(settings.note);
    console.log('then: claude plugin marketplace add DenEwout/cc-hush && claude plugin install hush');
    process.exit(0);
  }
  case 'uninstall':
    await stop();
    uninstallService();
    console.log(`startup service removed. ${DATA} kept; delete it by hand to drop the model, token and audit log.`);
    break;
  case 'stop':
    console.log((await stop()) ? 'daemon stopped' : 'no daemon running');
    break;
  case 'status':
    console.log(JSON.stringify((await health()) ?? { ok: false, hint: 'run: cc-hush install' }));
    break;
  default:
    console.error(USAGE);
    process.exit(command ? 1 : 0);
}

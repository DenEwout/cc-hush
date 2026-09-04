import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { regexDetect, mergeSpans, mcpKeyPass } from '../daemon/detect.ts';
import { destructive, piiColumns, guard, extract, loadSchema, BROKEN_SCHEMA } from '../daemon/guard.ts';
import { tokenize, applySpans, redactKnown, rehydrate, isWhitelisted, DEFAULT_POLICY } from '../daemon/vault.ts';

const labels = (t: string) => regexDetect(t).map((s) => [t.slice(s.start, s.end), s.label]);

test('regex: Belgian identifiers and secrets', () => {
  assert.deepEqual(labels('rrn 85.07.30-033.28 ok'), [['85.07.30-033.28', 'account_number']]);
  assert.deepEqual(labels('rrn 85.07.30-033.29 bad checksum'), []);
  assert.deepEqual(labels('iban BE68 5390 0754 7034'), [['BE68 5390 0754 7034', 'account_number']]);
  assert.deepEqual(labels('iban BE68 5390 0754 7035'), []);
  assert.deepEqual(labels('btw BE0123.456.749'), [['BE0123.456.749', 'account_number']]);
  assert.deepEqual(labels('call +32 470 12 34 56'), [['+32 470 12 34 56', 'private_phone']]);
  assert.deepEqual(labels('key AKIAIOSFODNN7EXAMPLE'), [['AKIAIOSFODNN7EXAMPLE', 'secret']]);
  assert.deepEqual(labels('api_key = "abcdefghijklmnop1234"'), [['abcdefghijklmnop1234', 'secret']]);
  assert.deepEqual(labels('-----BEGIN RSA PRIVATE KEY-----')[0][1], 'secret');
});

test('merge: overlap keeps highest score, allowlist drops', () => {
  const t = 'Ewout Van Gossum at qmino.com';
  const spans = [
    { start: 0, end: 16, label: 'private_person', score: 0.9 },
    { start: 6, end: 16, label: 'private_person', score: 0.6 },
    { start: 20, end: 29, label: 'private_url', score: 0.8 },
  ];
  assert.equal(mergeSpans(spans, t, []).length, 2);
  assert.equal(mergeSpans(spans, t, ['qmino.com']).length, 1);
  assert.equal(mergeSpans(spans, t, ['Ewout Van Gossum', 'qmino.com']).length, 0);
  const mail = 'alice@qmino.com';
  assert.equal(mergeSpans([{ start: 0, end: 15, label: 'private_email', score: 0.9 }], mail, ['qmino.com']).length, 1);
  const u = mergeSpans([{ start: 0, end: 10, label: 'private_person', score: 0.9 }, { start: 5, end: 16, label: 'private_person', score: 0.7 }], t, []);
  assert.deepEqual([u[0].start, u[0].end], [0, 16]);
});

test('vault: stable tokens, round trip, known-value redaction', () => {
  const tok = tokenize('alice@example.com', 'private_email');
  assert.equal(tok, tokenize('alice@example.com', 'private_email'));
  assert.match(tok, /^<PII:email:\d+>$/);
  const t = 'mail alice@example.com now';
  const red = applySpans(t, [{ start: 5, end: 22, label: 'private_email', score: 1 }]);
  assert.equal(red, `mail ${tok} now`);
  assert.equal(rehydrate(red), t);
  assert.equal(redactKnown('cat: alice@example.com'), `cat: ${tok}`);
  assert.equal(isWhitelisted('Write', DEFAULT_POLICY), true);
  assert.equal(isWhitelisted('Bash', DEFAULT_POLICY), false);
  assert.equal(isWhitelisted('mcp__claude_ai_Atlassian_Rovo__addCommentToJiraIssue', DEFAULT_POLICY), false);
  assert.equal(isWhitelisted('mcp__claude_ai_Atlassian_Rovo__addCommentToJiraIssue', { ...DEFAULT_POLICY, allowPii: { tools: [], mcpServers: ['claude_ai_Atlassian'] } }), true);
});

test('mcp key pass', () => {
  const out: any = mcpKeyPass({ fields: { reporter: { displayName: 'Bob Jones', self: 'https://x/1' }, description: { type: 'mention', attrs: { text: '@Bob Jones' } } } });
  assert.match(out.fields.reporter.displayName, /^<PII:person:/);
  assert.equal(out.fields.reporter.self, 'https://x/1');
  assert.match(out.fields.description.attrs.text, /^<PII:person:/);
});

test('guard: destructive tiers', () => {
  assert.equal(destructive('git push --force origin main')?.decision, 'deny');
  assert.equal(destructive('git push -f origin master')?.decision, 'deny');
  assert.equal(destructive('git push origin +main')?.decision, 'deny');
  assert.equal(destructive('git push --force origin feature/x')?.decision, 'ask');
  assert.equal(destructive('git push origin feature/x'), null);
  assert.equal(destructive('rm -rf /')?.decision, 'deny');
  assert.equal(destructive('rm -rf ~')?.decision, 'deny');
  assert.equal(destructive('rm -rf "$HOME"')?.decision, 'deny');
  assert.equal(destructive('rm -rf ./build')?.decision, 'ask');
  assert.equal(destructive('rm -r ./build'), null);
  assert.equal(destructive('psql -c "DROP TABLE customer"')?.decision, 'deny');
  assert.equal(destructive('psql -c "TRUNCATE customer"')?.decision, 'deny');
  assert.equal(destructive('git stash drop'), null);
  assert.equal(destructive('truncate -s 0 log.txt'), null);
  assert.equal(destructive('psql -c "UPDATE customer SET x=1"')?.decision, 'ask');
  assert.equal(destructive('psql -c "UPDATE customer SET x=1 WHERE id=3"'), null);
  assert.equal(destructive("psql -c \"UPDATE t SET x=1 /* where */\"")?.decision, 'ask');
  assert.equal(destructive("psql -c \"UPDATE t SET note='where' -- where\"")?.decision, 'ask');
  assert.equal(destructive('git -C repo push --force origin main')?.decision, 'deny');
  assert.equal(destructive('psql -c "DELETE FROM customer"')?.decision, 'ask');
  assert.equal(destructive('psql -c "ALTER TABLE customer ADD COLUMN x int"')?.decision, 'ask');
  assert.equal(destructive('git reset --hard HEAD~1')?.decision, 'ask');
  assert.equal(destructive('git clean -fd')?.decision, 'ask');
  assert.equal(destructive('terraform destroy')?.decision, 'ask');
  assert.equal(destructive('kubectl delete pod x')?.decision, 'ask');
  assert.equal(destructive('ls -la && git status'), null);
});

test('guard: PII columns', () => {
  const schema = { tables: { customer: { email: 'private_email', naam: 'private_person' }, invoice: { iban: 'account_number' } } };
  assert.equal(piiColumns('select * from customer', schema)?.decision, 'ask');
  assert.equal(piiColumns('select c.* from customer c', schema)?.decision, 'ask');
  assert.match(piiColumns("select id from customer where email = 'x'", schema)!.reason, /customer\.email \(private_email\)/);
  assert.equal(piiColumns('select count(*) from customer', schema), null);
  assert.equal(piiColumns('select id, "Email" from customer', schema)?.decision, 'ask');
  assert.equal(piiColumns('select emailed from customer', schema), null);
  assert.equal(piiColumns('echo email', schema), null);
});

test('guard: referenced script file and npm script', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hush-'));
  fs.writeFileSync(path.join(dir, 'deploy.sh'), 'psql -c "DROP TABLE customer"\n');
  fs.writeFileSync(path.join(dir, 'q.sql'), 'select email from customer;\n');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ scripts: { nuke: 'git push --force origin main' } }));
  const schema = { tables: { customer: { email: 'private_email' } } };
  const v = guard('Bash', { command: 'bash deploy.sh' }, dir, schema);
  assert.equal(v?.decision, 'deny');
  assert.match(v!.reason, /deploy\.sh/);
  assert.equal(guard('Bash', { command: 'psql -f q.sql' }, dir, schema)?.decision, 'ask');
  assert.equal(guard('Bash', { command: 'npm run nuke' }, dir, schema)?.decision, 'deny');
  assert.equal(guard('Bash', { command: 'cat q.sql' }, dir, schema), null);
  assert.equal(guard('mcp__db__query', { sql: 'select email from customer' }, dir, schema)?.decision, 'ask');
  assert.equal(guard('mcp__db__query', { args: { params: { sqlText: 'drop table x' } } }, dir, schema)?.decision, 'deny');
  fs.writeFileSync(path.join(dir, 'run.sh'), 'rm -rf /\n');
  assert.equal(guard('Bash', { command: './run.sh' }, dir, schema)?.decision, 'deny');
  fs.writeFileSync(path.join(dir, 'big.sh'), 'x'.repeat(1_100_000));
  assert.equal(guard('Bash', { command: 'bash big.sh' }, dir, schema)?.decision, 'ask');
  fs.writeFileSync(path.join(dir, '.hush.json'), '{');
  fs.mkdirSync(path.join(dir, '.hush')); fs.writeFileSync(path.join(dir, '.hush', 'schema.json'), '{ broken');
  assert.equal(loadSchema(dir), BROKEN_SCHEMA);
  assert.equal(guard('Bash', { command: 'psql -c "select 1"' }, dir, BROKEN_SCHEMA)?.decision, 'ask');
  assert.equal(extract('Bash', { command: 'echo select email' }, dir).hasSqlSource, false);
});

test('detect: never re-tag inside an existing token', async () => {
  const { detect } = await import('../daemon/detect.ts');
  const spans = await detect('reporter <PII:person:3> rrn 85.07.30-033.28', [], false);
  assert.deepEqual(spans.map((s) => s.start), [28]);
});

test('install: ANTHROPIC_BASE_URL merge into settings.json', async () => {
  const { mergeBaseUrl, windowsLauncherVbs, systemdUnit } = await import('../daemon/service.ts');
  const proxy = 'http://127.0.0.1:47831';
  const fresh = mergeBaseUrl(undefined);
  assert.equal(JSON.parse(fresh.text!).env.ANTHROPIC_BASE_URL, proxy);
  const merged = mergeBaseUrl(JSON.stringify({ env: { FOO: '1' }, hooks: {} }));
  assert.deepEqual(JSON.parse(merged.text!), { env: { FOO: '1', ANTHROPIC_BASE_URL: proxy }, hooks: {} });
  assert.equal(mergeBaseUrl(JSON.stringify({ env: { ANTHROPIC_BASE_URL: proxy } })).text, undefined);
  const other = mergeBaseUrl(JSON.stringify({ env: { ANTHROPIC_BASE_URL: 'http://127.0.0.1:8787/w/claude' } }));
  assert.equal(other.text, undefined);
  assert.match(other.note, /left unchanged/);
  const chained = mergeBaseUrl(JSON.stringify({ env: { ANTHROPIC_BASE_URL: 'http://127.0.0.1:8787/w/claude' } }), true);
  assert.equal(JSON.parse(chained.text!).env.ANTHROPIC_BASE_URL, proxy);
  assert.equal(chained.upstream, 'http://127.0.0.1:8787/w/claude');
  assert.equal(mergeBaseUrl(undefined, true).upstream, undefined);
  assert.throws(() => mergeBaseUrl('{ not json'));
  const launcher = { node: '/usr/local/bin/node', script: '/usr/local/lib/node_modules/cc-hush/bin/cc-hush.ts' };
  const vbs = windowsLauncherVbs({ node: 'C:\\n\\node.exe', script: 'C:\\x y\\cc-hush.ts' });
  assert.match(vbs, /^ {2}code = shell\.Run\("""C:\\n\\node\.exe"" ""C:\\x y\\cc-hush\.ts"" start --log", 0, True\)\r$/m);
  assert.match(vbs, /Loop While code <> 0/);
  assert.match(systemdUnit(launcher), /ExecStart="\/usr\/local\/bin\/node" "\/usr\/local\/lib\/node_modules\/cc-hush\/bin\/cc-hush.ts" start --log/);
});

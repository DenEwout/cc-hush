import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { regexDetect, mergeSpans, mcpKeyPass } from '../daemon/detect.ts';
import { destructive, piiColumns, guard, extract } from '../daemon/guard.ts';
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
  assert.equal(extract('Bash', { command: 'echo select email' }, dir).sqlish, false);
});

test('detect: never re-tag inside an existing token', async () => {
  const { detect } = await import('../daemon/detect.ts');
  const spans = await detect('reporter <PII:person:3> rrn 85.07.30-033.28', [], false);
  assert.deepEqual(spans.map((s) => s.start), [28]);
});

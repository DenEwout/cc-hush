import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

export type Span = { start: number; end: number; label: string; score: number };

export type Policy = {
  allowlist: string[];
  allowPii: { mcpServers: string[]; tools: string[] };
};

export const DEFAULT_POLICY: Policy = {
  allowlist: [],
  allowPii: { mcpServers: [], tools: ['Write', 'Edit', 'MultiEdit'] },
};

const TOKEN_RE = /<PII:[a-z_]+:\d+>/g;
const MIN_KNOWN_VALUE_LENGTH = 3;

const tokenByValue = new Map<string, string>();
const valueByToken = new Map<string, string>();
const lastNumberByLabel = new Map<string, number>();
let persist: ((value: string, token: string, label: string) => void) | undefined;

const shortLabel = (label: string) => (label === 'account_number' ? 'account' : label.replace(/^private_/, ''));

// Tokens live in transcripts that outlive any daemon process (claude --resume), so the map must too. The file holds
// real values at the same trust level as Claude Code's own transcript on this disk.
export function openVault(file: string): { close: () => void } {
  const db = new DatabaseSync(file);
  try { fs.chmodSync(file, 0o600); } catch {}
  db.exec('CREATE TABLE IF NOT EXISTS vault(value TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL, label TEXT NOT NULL)');
  tokenByValue.clear(); valueByToken.clear(); lastNumberByLabel.clear();
  for (const row of db.prepare('SELECT value, token, label FROM vault').all() as { value: string; token: string; label: string }[]) {
    tokenByValue.set(row.value, row.token);
    valueByToken.set(row.token, row.value);
    lastNumberByLabel.set(row.label, Math.max(lastNumberByLabel.get(row.label) ?? 0, Number(/:(\d+)>$/.exec(row.token)![1])));
  }
  const insert = db.prepare('INSERT OR IGNORE INTO vault VALUES (?, ?, ?)');
  persist = (value, token, label) => { insert.run(value, token, label); };
  return { close: () => { persist = undefined; db.close(); } };
}

export function tokenize(value: string, label: string): string {
  const existing = tokenByValue.get(value);
  if (existing) return existing;
  const short = shortLabel(label);
  const number = (lastNumberByLabel.get(short) ?? 0) + 1;
  lastNumberByLabel.set(short, number);
  const token = `<PII:${short}:${number}>`;
  tokenByValue.set(value, token);
  valueByToken.set(token, value);
  persist?.(value, token, short);
  return token;
}

export function applySpans(text: string, spans: Span[]): string {
  let out = '';
  let cursor = 0;
  for (const span of [...spans].sort((a, b) => a.start - b.start)) {
    if (span.start < cursor) continue;
    out += text.slice(cursor, span.start) + tokenize(text.slice(span.start, span.end), span.label);
    cursor = span.end;
  }
  return out + text.slice(cursor);
}

export function redactKnown(text: string): string {
  const longestFirst = [...tokenByValue.keys()].filter((v) => v.length >= MIN_KNOWN_VALUE_LENGTH).sort((a, b) => b.length - a.length);
  for (const value of longestFirst) if (text.includes(value)) text = text.split(value).join(tokenByValue.get(value)!);
  return text;
}

export const rehydrate = (text: string) => text.replace(TOKEN_RE, (token) => valueByToken.get(token) ?? token);

export function rehydrateDeep<T>(value: T): T {
  if (typeof value === 'string') return rehydrate(value) as T;
  if (Array.isArray(value)) return value.map(rehydrateDeep) as T;
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, rehydrateDeep(v)])) as T;
  return value;
}

export const unresolvedTokens = (text: string) => [...new Set(text.match(TOKEN_RE) ?? [])].filter((token) => !valueByToken.has(token));

export const mcpServer = (toolName: string) => /^mcp__(.+?)__/.exec(toolName)?.[1] ?? null;

export function isWhitelisted(toolName: string, policy: Policy): boolean {
  const server = mcpServer(toolName);
  if (server) return policy.allowPii.mcpServers.some((prefix) => server.startsWith(prefix));
  return policy.allowPii.tools.includes(toolName);
}

export const dump = () => Object.fromEntries(tokenByValue);
export const size = () => tokenByValue.size;

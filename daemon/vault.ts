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

const shortLabel = (label: string) => (label === 'account_number' ? 'account' : label.replace(/^private_/, ''));

export function tokenize(value: string, label: string): string {
  const existing = tokenByValue.get(value);
  if (existing) return existing;
  const short = shortLabel(label);
  const number = (lastNumberByLabel.get(short) ?? 0) + 1;
  lastNumberByLabel.set(short, number);
  const token = `<PII:${short}:${number}>`;
  tokenByValue.set(value, token);
  valueByToken.set(token, value);
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

export const mcpServer = (toolName: string) => /^mcp__(.+?)__/.exec(toolName)?.[1] ?? null;

export function isWhitelisted(toolName: string, policy: Policy): boolean {
  const server = mcpServer(toolName);
  if (server) return policy.allowPii.mcpServers.some((prefix) => server.startsWith(prefix));
  return policy.allowPii.tools.includes(toolName);
}

export const dump = () => Object.fromEntries(tokenByValue);
export const size = () => tokenByValue.size;

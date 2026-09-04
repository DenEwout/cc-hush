// Global in-memory vault: real value <-> stable <PII:label:n> token.
// Lives as long as the daemon. Same value always yields the same token, which keeps prompt caching intact.

export type Span = { start: number; end: number; label: string; score: number };

export type Policy = {
  allowlist: string[];
  allowPii: { mcpServers: string[]; tools: string[] };
};

export const DEFAULT_POLICY: Policy = {
  allowlist: [],
  allowPii: { mcpServers: [], tools: ['Write', 'Edit', 'MultiEdit', 'Bash'] },
};

const TOKEN_RE = /<PII:[a-z_]+:\d+>/g;

const toToken = new Map<string, string>();
const toReal = new Map<string, string>();
const counters = new Map<string, number>();

export function shortLabel(label: string): string {
  return label.replace(/^private_/, '').replace(/^account_number$/, 'account');
}

export function tokenize(value: string, label: string): string {
  const hit = toToken.get(value);
  if (hit) return hit;
  const short = shortLabel(label);
  const n = (counters.get(short) ?? 0) + 1;
  counters.set(short, n);
  const token = `<PII:${short}:${n}>`;
  toToken.set(value, token);
  toReal.set(token, value);
  return token;
}

/** Replace detected spans in text with tokens. Spans must be non-overlapping. */
export function applySpans(text: string, spans: Span[]): string {
  let out = '';
  let cursor = 0;
  for (const s of [...spans].sort((a, b) => a.start - b.start)) {
    if (s.start < cursor) continue;
    out += text.slice(cursor, s.start) + tokenize(text.slice(s.start, s.end), s.label);
    cursor = s.end;
  }
  return out + text.slice(cursor);
}

/** Replace every vault-known real value with its token. Plain string match, longest first. */
export function redactKnown(text: string): string {
  if (toToken.size === 0) return text;
  // ponytail: O(vault * text) scan per block; switch to Aho-Corasick if the vault grows past a few thousand entries.
  const values = [...toToken.keys()].filter((v) => v.length >= 3).sort((a, b) => b.length - a.length);
  for (const v of values) if (text.includes(v)) text = text.split(v).join(toToken.get(v)!);
  return text;
}

export function rehydrate(text: string): string {
  return text.replace(TOKEN_RE, (t) => toReal.get(t) ?? t);
}

/** Recursively rehydrate every string in a JSON value. */
export function rehydrateDeep<T>(v: T): T {
  if (typeof v === 'string') return rehydrate(v) as T;
  if (Array.isArray(v)) return v.map(rehydrateDeep) as T;
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = rehydrateDeep(x);
    return out as T;
  }
  return v;
}

export function hasTokens(text: string): boolean {
  TOKEN_RE.lastIndex = 0;
  return TOKEN_RE.test(text);
}

export function mcpServer(toolName: string): string | null {
  const m = /^mcp__([^_].*?)__/.exec(toolName);
  return m ? m[1] : null;
}

export function isWhitelisted(toolName: string, policy: Policy): boolean {
  const server = mcpServer(toolName);
  if (server) return policy.allowPii.mcpServers.some((p) => server.startsWith(p));
  return policy.allowPii.tools.includes(toolName);
}

export function dump(): Record<string, string> {
  return Object.fromEntries(toToken);
}

export function size(): number {
  return toToken.size;
}

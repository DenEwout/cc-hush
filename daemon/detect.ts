// Two detectors over text: deterministic regex (Belgian identifiers + secrets) and openai/privacy-filter.
import { env, AutoTokenizer, AutoModelForTokenClassification } from '@huggingface/transformers';
import { tokenize, type Span } from './vault.ts';

export const THRESHOLD = 0.5;
export const LABELS = ['account_number', 'private_address', 'private_email', 'private_person', 'private_phone', 'private_url', 'private_date', 'secret'];

// ---------- regex ----------

const mod97ok = (digits: string, check: string) => 97 - (Number(BigInt(digits) % 97n)) === Number(check);

function rrnValid(raw: string): boolean {
  const d = raw.replace(/\D/g, '');
  if (d.length !== 11) return false;
  const body = d.slice(0, 9), check = d.slice(9);
  return mod97ok(body, check) || mod97ok('2' + body, check);
}

function ibanValid(raw: string): boolean {
  const s = raw.replace(/\s/g, '').toUpperCase();
  const rearranged = s.slice(4) + s.slice(0, 4);
  const numeric = rearranged.replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  return BigInt(numeric) % 97n === 1n;
}

type Rule = { re: RegExp; label: string; valid?: (m: string) => boolean; group?: number };

const RULES: Rule[] = [
  { re: /\b\d{2}[.\- ]?\d{2}[.\- ]?\d{2}[.\- ]?\d{3}[.\- ]?\d{2}\b/g, label: 'account_number', valid: rrnValid },
  { re: /\bBE\d{2}(?: ?\d{4}){3}\b/gi, label: 'account_number', valid: ibanValid },
  { re: /\bBE ?0\d{3}[. ]?\d{3}[. ]?\d{3}\b/g, label: 'account_number' },
  { re: /\+32 ?\(?0?\)? ?\d(?:[ .\-]?\d){7,8}\b/g, label: 'private_phone' },
  // gitleaks-style secrets
  { re: /\bAKIA[0-9A-Z]{16}\b/g, label: 'secret' },
  { re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g, label: 'secret' },
  { re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, label: 'secret' },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, label: 'secret' },
  { re: /\bsk-[A-Za-z0-9_-]{20,}\b/g, label: 'secret' },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, label: 'secret' },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, label: 'secret' },
  { re: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret)\b\s*[=:]\s*["']?([A-Za-z0-9_\-\/+.]{12,})["']?/gi, label: 'secret', group: 1 },
];

export function regexDetect(text: string): Span[] {
  const spans: Span[] = [];
  for (const r of RULES) {
    r.re.lastIndex = 0;
    for (const m of text.matchAll(r.re)) {
      let start = m.index!, value = m[0];
      if (r.group) {
        value = m[r.group];
        start += m[0].indexOf(value);
      }
      if (r.valid && !r.valid(value)) continue;
      spans.push({ start, end: start + value.length, label: r.label, score: 1 });
    }
  }
  return spans;
}

// ---------- model ----------

let tokenizer: any, model: any;
let loading: Promise<void> | null = null;

export function modelReady(): boolean {
  return !!model;
}

export function loadModel(cacheDir: string, device: string): Promise<void> {
  if (loading) return loading;
  env.cacheDir = cacheDir;
  const id = 'openai/privacy-filter';
  loading = (async () => {
    const t0 = Date.now();
    tokenizer = await AutoTokenizer.from_pretrained(id);
    model = await AutoModelForTokenClassification.from_pretrained(id, { dtype: 'q4', device: device as any });
    console.log(`[hush] model ready on ${device} in ${Date.now() - t0}ms`);
  })();
  return loading;
}

function softmaxMax(row: Float32Array | number[]): [number, number] {
  let best = 0;
  for (let i = 1; i < row.length; i++) if (row[i] > row[best]) best = i;
  let sum = 0;
  for (let i = 0; i < row.length; i++) sum += Math.exp(row[i] - row[best]);
  return [best, 1 / sum];
}

export async function modelDetect(text: string): Promise<Span[]> {
  if (!model) await loading;
  const inputs = tokenizer([text], { padding: true, truncation: true });
  const { logits } = await model(inputs);
  const ids: number[] = inputs.input_ids[0].tolist().map(Number);
  const id2label: Record<number, string> = model.config.id2label;
  const nLabels = logits.dims[2];
  const data = logits.data as Float32Array;

  // Map tokens to char offsets by decoding each token and searching forward.
  // ponytail: sequential indexOf; tokens that split a multibyte char are skipped. Good enough for span boundaries.
  const spans: Span[] = [];
  let cursor = 0;
  let open: (Span & { n: number }) | null = null;
  const close = () => {
    if (open && open.score / open.n >= THRESHOLD) spans.push({ start: open.start, end: open.end, label: open.label, score: open.score / open.n });
    open = null;
  };
  for (let j = 0; j < ids.length; j++) {
    const piece: string = tokenizer.decode([ids[j]], { skip_special_tokens: true });
    if (piece === '') continue;
    const at = text.indexOf(piece, cursor);
    if (at < 0) continue;
    const trimmedStart = at + (piece.length - piece.trimStart().length);
    const end = at + piece.length;
    cursor = end;
    const [idx, score] = softmaxMax(data.subarray(j * nLabels, (j + 1) * nLabels));
    const entity = id2label[idx] ?? 'O';
    if (entity === 'O') { close(); continue; }
    const prefix = entity[1] === '-' ? entity[0] : 'I';
    const label = entity[1] === '-' ? entity.slice(2) : entity;
    const extend = open && open.label === label && prefix !== 'B' && prefix !== 'S';
    if (extend) {
      open!.end = end; open!.score += score; open!.n++;
      if (prefix === 'E') close();
    } else {
      close();
      open = { start: trimmedStart, end, label, score, n: 1 };
      if (prefix === 'S') close();
    }
  }
  close();
  return spans;
}

// ---------- merge ----------

export function mergeSpans(spans: Span[], text: string, allowlist: string[]): Span[] {
  const allow = allowlist.map((a) => a.toLowerCase()).filter(Boolean);
  const kept = spans
    .filter((s) => s.end > s.start)
    .filter((s) => {
      const v = text.slice(s.start, s.end).toLowerCase();
      return !allow.some((a) => v.includes(a) || (v.length >= 3 && a.includes(v)));
    })
    .sort((a, b) => a.start - b.start || b.score - a.score);
  const out: Span[] = [];
  for (const s of kept) {
    const last = out[out.length - 1];
    if (last && s.start < last.end) {
      if (s.score > last.score) out[out.length - 1] = s;
      continue;
    }
    out.push(s);
  }
  return out;
}

export async function detect(text: string, allowlist: string[], useModel = true): Promise<Span[]> {
  const spans = regexDetect(text);
  if (useModel && text.trim()) spans.push(...(await modelDetect(text)));
  // Never re-tag inside an existing <PII:...> token (e.g. the counter digits).
  const tokens = [...text.matchAll(/<PII:[a-z_]+:\d+>/g)].map((m) => [m.index!, m.index! + m[0].length]);
  const clean = spans.filter((s) => !tokens.some(([a, b]) => s.start < b && s.end > a));
  return mergeSpans(clean, text, allowlist);
}

// ---------- MCP JSON key pass ----------

const KEY_LABELS: Record<string, string> = {
  emailAddress: 'private_email', displayName: 'private_person', accountId: 'account_number',
  author: 'private_person', reporter: 'private_person', assignee: 'private_person', creator: 'private_person',
};

export function mcpKeyPass(v: unknown, keyLabel?: string): unknown {
  if (typeof v === 'string') return keyLabel && v.trim() ? tokenize(v, keyLabel) : v;
  if (Array.isArray(v)) return v.map((x) => mcpKeyPass(x, keyLabel));
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    const isMention = o.type === 'mention';
    for (const [k, x] of Object.entries(o)) {
      if (isMention && k === 'attrs' && x && typeof x === 'object') {
        const attrs = { ...(x as Record<string, unknown>) };
        if (typeof attrs.text === 'string') attrs.text = tokenize(attrs.text, 'private_person');
        out[k] = attrs;
      } else out[k] = mcpKeyPass(x, KEY_LABELS[k]);
    }
    return out;
  }
  return v;
}

/** Apply the key pass to an MCP tool result string if it holds JSON. */
export function mcpKeyPassText(text: string): string {
  const t = text.trim();
  if (!(t.startsWith('{') || t.startsWith('['))) return text;
  try { return JSON.stringify(mcpKeyPass(JSON.parse(t))); } catch { return text; }
}

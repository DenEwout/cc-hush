import { env, AutoTokenizer, AutoModelForTokenClassification } from '@huggingface/transformers';
import { tokenize, type Span } from './vault.ts';

const MODEL_ID = 'openai/privacy-filter';
const MODEL_CONTEXT_TOKENS = 128_000;
const MAX_CHUNK_CHARS = 6_000;
const MIN_SPAN_CONFIDENCE = 0.5;
const MIN_ALLOWLIST_FRAGMENT_LENGTH = 3;

const mod97Matches = (digits: string, check: string) => 97 - Number(BigInt(digits) % 97n) === Number(check);

function isRijksregisternummer(raw: string): boolean {
  const digits = raw.replace(/\D/g, '');
  if (digits.length !== 11) return false;
  const body = digits.slice(0, 9), check = digits.slice(9);
  const bornAfter1999 = '2' + body;
  return mod97Matches(body, check) || mod97Matches(bornAfter1999, check);
}

function isIban(raw: string): boolean {
  const compact = raw.replace(/\s/g, '').toUpperCase();
  const countryAndCheckMovedToEnd = compact.slice(4) + compact.slice(0, 4);
  const lettersAsNumbers = countryAndCheckMovedToEnd.replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  return BigInt(lettersAsNumbers) % 97n === 1n;
}

const RIJKSREGISTERNUMMER = /\b\d{2}[.\- ]?\d{2}[.\- ]?\d{2}[.\- ]?\d{3}[.\- ]?\d{2}\b/g;
const BELGIAN_IBAN = /\bBE\d{2}(?: ?\d{4}){3}\b/gi;
const BELGIAN_VAT = /\bBE ?0\d{3}[. ]?\d{3}[. ]?\d{3}\b/g;
const BELGIAN_PHONE = /\+32 ?\(?0?\)? ?\d(?:[ .\-]?\d){7,8}\b/g;
const AWS_ACCESS_KEY = /\bAKIA[0-9A-Z]{16}\b/g;
const GITHUB_TOKEN = /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g;
const GITHUB_FINE_GRAINED_TOKEN = /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g;
const SLACK_TOKEN = /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g;
const SK_API_KEY = /\bsk-[A-Za-z0-9_-]{20,}\b/g;
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const PRIVATE_KEY_HEADER = /-----BEGIN [A-Z ]*PRIVATE KEY-----/g;
const SECRET_ASSIGNMENT = /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret)\b\s*[=:]\s*["']?([A-Za-z0-9_\-\/+.]{12,})["']?/gi;

type Rule = { re: RegExp; label: string; checksum?: (match: string) => boolean; valueGroup?: number };

// Deterministic backstop: the model misses addresses that do not look like a real person's (e2e.person@example.org).
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g;

const RULES: Rule[] = [
  { label: 'private_email', re: EMAIL },
  { label: 'account_number', re: RIJKSREGISTERNUMMER, checksum: isRijksregisternummer },
  { label: 'account_number', re: BELGIAN_IBAN, checksum: isIban },
  { label: 'account_number', re: BELGIAN_VAT },
  { label: 'private_phone', re: BELGIAN_PHONE },
  { label: 'secret', re: AWS_ACCESS_KEY },
  { label: 'secret', re: GITHUB_TOKEN },
  { label: 'secret', re: GITHUB_FINE_GRAINED_TOKEN },
  { label: 'secret', re: SLACK_TOKEN },
  { label: 'secret', re: SK_API_KEY },
  { label: 'secret', re: JWT },
  { label: 'secret', re: PRIVATE_KEY_HEADER },
  { label: 'secret', re: SECRET_ASSIGNMENT, valueGroup: 1 },
];

export function regexDetect(text: string): Span[] {
  const spans: Span[] = [];
  for (const rule of RULES) {
    for (const match of text.matchAll(rule.re)) {
      const value = rule.valueGroup ? match[rule.valueGroup] : match[0];
      if (rule.checksum && !rule.checksum(value)) continue;
      const start = match.index! + match[0].indexOf(value);
      spans.push({ start, end: start + value.length, label: rule.label, score: 1 });
    }
  }
  return spans;
}

let tokenizer: any, model: any;
let loading: Promise<void> | undefined;

export const modelReady = () => !!model;

export function loadModel(cacheDir: string, device: string, progress_callback?: (event: unknown) => void): Promise<void> {
  env.cacheDir = cacheDir;
  loading ??= (async () => {
    const started = Date.now();
    tokenizer = await AutoTokenizer.from_pretrained(MODEL_ID, { progress_callback });
    model = await AutoModelForTokenClassification.from_pretrained(MODEL_ID, { dtype: 'q4', device: device as any, progress_callback });
    console.log(`[hush] model ready on ${device} in ${Date.now() - started}ms`);
  })();
  return loading;
}

function argmax(row: Float32Array): { index: number; probability: number } {
  let index = 0;
  for (let i = 1; i < row.length; i++) if (row[i] > row[index]) index = i;
  let sum = 0;
  for (const x of row) sum += Math.exp(x - row[index]);
  return { index, probability: 1 / sum };
}

type TaggedToken = { start: number; end: number; tag: string; score: number };

async function tagEachToken(text: string): Promise<TaggedToken[]> {
  const inputs = tokenizer([text], { padding: true, truncation: false });
  if (inputs.input_ids.dims[1] >= MODEL_CONTEXT_TOKENS) throw new Error('text exceeds model context, refusing to scan partially');
  const { logits } = await model(inputs);
  const ids: number[] = inputs.input_ids[0].tolist().map(Number);
  const labelCount: number = logits.dims[2];
  const tagged: TaggedToken[] = [];
  let searchFrom = 0;
  ids.forEach((id, i) => {
    const piece: string = tokenizer.decode([id], { skip_special_tokens: true });
    const at = piece ? text.indexOf(piece, searchFrom) : -1;
    if (at < 0) return;
    searchFrom = at + piece.length;
    const { index, probability } = argmax(logits.data.subarray(i * labelCount, (i + 1) * labelCount));
    const leadingWhitespace = piece.length - piece.trimStart().length;
    tagged.push({ start: at + leadingWhitespace, end: searchFrom, tag: model.config.id2label[index] ?? 'O', score: probability });
  });
  return tagged;
}

const splitBioesTag = (tag: string): [prefix: string, label: string] => (tag[1] === '-' ? [tag[0], tag.slice(2)] : ['I', tag]);

function groupBioesTags(tokens: TaggedToken[]): Span[] {
  const spans: Span[] = [];
  let open: { start: number; end: number; label: string; scoreSum: number; count: number } | null = null;
  const close = () => {
    if (open && open.scoreSum / open.count >= MIN_SPAN_CONFIDENCE) spans.push({ start: open.start, end: open.end, label: open.label, score: open.scoreSum / open.count });
    open = null;
  };
  for (const token of tokens) {
    if (token.tag === 'O') { close(); continue; }
    const [prefix, label] = splitBioesTag(token.tag);
    const continuesOpenSpan = open?.label === label && prefix !== 'B' && prefix !== 'S';
    if (continuesOpenSpan) {
      open!.end = token.end; open!.scoreSum += token.score; open!.count++;
    } else {
      close();
      open = { start: token.start, end: token.end, label, scoreSum: token.score, count: 1 };
    }
    if (prefix === 'E' || prefix === 'S') close();
  }
  close();
  return spans;
}

export function chunkStarts(text: string): number[] {
  const starts = [0];
  while (text.length - starts.at(-1)! > MAX_CHUNK_CHARS) {
    const from = starts.at(-1)!;
    let breakAt = from + MAX_CHUNK_CHARS;
    while (breakAt > from && !/\s/.test(text[breakAt])) breakAt--;
    starts.push(breakAt > from ? breakAt + 1 : from + MAX_CHUNK_CHARS);
  }
  return starts;
}

export async function modelDetect(text: string): Promise<Span[]> {
  await loading;
  const spans: Span[] = [];
  const starts = chunkStarts(text);
  for (let i = 0; i < starts.length; i++) {
    const from = starts[i];
    const tagged = await tagEachToken(text.slice(from, starts[i + 1] ?? text.length));
    for (const span of groupBioesTags(tagged)) spans.push({ ...span, start: span.start + from, end: span.end + from });
  }
  return spans;
}

export function mergeSpans(spans: Span[], text: string, allowlist: string[]): Span[] {
  const terms = allowlist.map((t) => t.trim().toLowerCase()).filter(Boolean);
  const isTermOrPartOfTerm = (span: Span) => {
    const value = text.slice(span.start, span.end).trim().toLowerCase();
    return terms.some((term) => value === term || (value.length >= MIN_ALLOWLIST_FRAGMENT_LENGTH && term.includes(value)));
  };
  const candidates = spans.filter((s) => s.end > s.start && !isTermOrPartOfTerm(s)).sort((a, b) => a.start - b.start || b.score - a.score);
  const merged: Span[] = [];
  for (const span of candidates) {
    const previous = merged.at(-1);
    const overlaps = previous && span.start < previous.end;
    if (!overlaps) { merged.push({ ...span }); continue; }
    previous.end = Math.max(previous.end, span.end);
    if (span.score > previous.score) { previous.label = span.label; previous.score = span.score; }
  }
  return merged;
}

export async function detect(text: string, allowlist: string[], useModel = true): Promise<Span[]> {
  const spans = regexDetect(text);
  if (useModel && text.trim()) spans.push(...(await modelDetect(text)));
  const existingTokens = [...text.matchAll(/<PII:[a-z_]+:\d+>/g)].map((m) => [m.index!, m.index! + m[0].length]);
  const insideExistingToken = (s: Span) => existingTokens.some(([start, end]) => s.start < end && s.end > start);
  return mergeSpans(spans.filter((s) => !insideExistingToken(s)), text, allowlist);
}

const PII_LABEL_BY_JSON_KEY: Record<string, string> = {
  emailAddress: 'private_email', displayName: 'private_person', accountId: 'account_number',
  author: 'private_person', reporter: 'private_person', assignee: 'private_person', creator: 'private_person',
};

export function mcpKeyPass(value: unknown, label?: string): unknown {
  if (typeof value === 'string') return label && value.trim() ? tokenize(value, label) : value;
  if (Array.isArray(value)) return value.map((item) => mcpKeyPass(item, label));
  if (!value || typeof value !== 'object') return value;
  const object = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(object)) {
    const mentionAttrs = object.type === 'mention' && key === 'attrs' ? (child as Record<string, unknown>) : null;
    out[key] = typeof mentionAttrs?.text === 'string'
      ? { ...mentionAttrs, text: tokenize(mentionAttrs.text, 'private_person') }
      : mcpKeyPass(child, PII_LABEL_BY_JSON_KEY[key]);
  }
  return out;
}

export function mcpKeyPassText(text: string): string {
  const looksLikeJson = /^\s*[{[]/.test(text);
  if (!looksLikeJson) return text;
  try { return JSON.stringify(mcpKeyPass(JSON.parse(text))); } catch { return text; }
}

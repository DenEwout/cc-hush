import crypto from 'node:crypto';
import { mcpKeyPassText } from './detect.ts';
import { applySpans, redactKnown, type Span } from './vault.ts';
import { DATA_SOURCE_RE } from './guard.ts';

export type Detect = (text: string, allowlist: string[], useModel?: boolean) => Promise<Span[]>;
export type Detector = { detect: Detect; load: (modelsDir: string, device: string) => Promise<void>; ready: () => boolean };
export type LabelCounts = Record<string, number>;

export const TOOL_RESULT_SIZE_CAP_BYTES = 32 * 1024;
const CACHE_MAX_ENTRIES = 50_000;

type Block = { type: string; text?: string; content?: unknown; tool_use_id?: string; id?: string; name?: string; input?: Record<string, unknown> };
type ToolUse = { name?: string; input?: Record<string, unknown> };
type Redacted = { text: string; spans: Span[] };

// Keyed by content hash so identical blocks across turns and sessions redact to identical text, which keeps
// Anthropic prompt caching intact. Holding the promise, not the result, makes concurrent identical requests
// (a client retry while the first scan is still running) share one model pass.
const redactionByHash = new Map<string, Promise<Redacted>>();

const sha1 = (s: string) => crypto.createHash('sha1').update(s).digest('hex');
const blocksOf = (content: unknown): Block[] => (Array.isArray(content) ? content : []);

export function countLabels(into: LabelCounts, spans: Span[]) {
  for (const span of spans) into[span.label] = (into[span.label] ?? 0) + 1;
}

function isExternalDataSource(tool?: ToolUse): boolean {
  const name = tool?.name ?? '';
  if (name === 'WebFetch' || name.startsWith('mcp__')) return true;
  return name === 'Bash' && DATA_SOURCE_RE.test(String(tool?.input?.command ?? ''));
}

export class RequestRedaction {
  labels: LabelCounts = {};
  private allowlist: string[];
  private detect: Detect;

  constructor(allowlist: string[], detect: Detect) {
    this.allowlist = allowlist;
    this.detect = detect;
  }

  private async scanWithModel(text: string): Promise<string> {
    const key = sha1(text + '\0' + this.allowlist.join(','));
    let pending = redactionByHash.get(key);
    const firstScan = !pending;
    if (!pending) {
      pending = this.detect(text, this.allowlist).then((spans) => ({ text: applySpans(text, spans), spans }));
      pending.catch(() => redactionByHash.delete(key));
      if (redactionByHash.size > CACHE_MAX_ENTRIES) redactionByHash.clear();
      redactionByHash.set(key, pending);
    }
    const { text: redacted, spans } = await pending;
    if (firstScan) countLabels(this.labels, spans);
    return redacted;
  }

  private async scanWithRegexAndVault(text: string): Promise<string> {
    const spans = await this.detect(text, this.allowlist, false);
    countLabels(this.labels, spans);
    return redactKnown(applySpans(text, spans));
  }

  private async redactToolResult(text: string, tool?: ToolUse): Promise<string> {
    if (!isExternalDataSource(tool)) return this.scanWithRegexAndVault(text);
    const bytes = Buffer.byteLength(text);
    if (bytes > TOOL_RESULT_SIZE_CAP_BYTES) return `Output too large for PII filter (${Math.round(bytes / 1024)} KB). Narrow the query: head, grep, LIMIT, or a smaller page.`;
    const isMcpResult = tool!.name!.startsWith('mcp__');
    return this.scanWithModel(isMcpResult ? mcpKeyPassText(text) : text);
  }

  private async mapText(content: unknown, transform: (text: string) => Promise<string>): Promise<unknown> {
    if (typeof content === 'string') return transform(content);
    for (const block of blocksOf(content)) if (block.type === 'text' && typeof block.text === 'string') block.text = await transform(block.text);
    return content;
  }

  async redactBody(body: any): Promise<void> {
    body.system = await this.mapText(body.system, (text) => this.scanWithModel(text));
    const toolUseById = new Map<string, ToolUse>();
    for (const message of body.messages ?? []) {
      if (message.role === 'assistant') {
        for (const block of blocksOf(message.content)) if (block.type === 'tool_use' && block.id) toolUseById.set(block.id, { name: block.name, input: block.input });
      } else if (message.role === 'user') {
        message.content = await this.mapText(message.content, (text) => this.scanWithModel(text));
        for (const block of blocksOf(message.content)) {
          if (block.type !== 'tool_result') continue;
          const tool = toolUseById.get(block.tool_use_id ?? '');
          block.content = await this.mapText(block.content, (text) => this.redactToolResult(text, tool));
        }
      }
    }
  }
}

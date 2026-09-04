// Shell and SQL guard: destructive command tiers and PII column matching. Regex only, no SQL parser.
import fs from 'node:fs';
import path from 'node:path';

export type Schema = { tables: Record<string, Record<string, string>> };
export type Verdict = { decision: 'deny' | 'ask'; reason: string } | null;

export const DATA_SOURCE_RE = /\b(psql|mysql|sqlite3|sqlplus|mongosh|curl|gh|wget)\b/;
const SQL_RE = /\b(select|insert|update|delete|alter|drop|truncate|create|merge)\b/i;

const FILE_REFS: RegExp[] = [
  /\b(?:bash|sh|zsh|source|\.)\s+([^\s;&|<>]+)/g,
  /(?:^|[;&|]\s*|\bsudo\s+)((?:\.{1,2}\/|\/)[^\s;&|<>]+)/gm,
  /\b(?:psql|sqlplus)\b[^;&|\n]*?\s-f\s*([^\s;&|<>]+)/g,
  /\b(?:psql|mysql|sqlite3|sqlplus|mongosh)\b[^;&|\n]*?<\s*([^\s;&|>]+)/g,
  /\bpython3?\s+([^\s;&|<>]+\.py)\b/g,
  /\bnode\s+([^\s;&|<>]+\.[cm]?[jt]s)\b/g,
];

/** Collect the command plus content of referenced local files (depth 1). */
export type Extracted = { text: string; files: string[]; sqlish: boolean; uninspectable: string[] };

export function extract(toolName: string, input: Record<string, unknown>, cwd: string): Extracted {
  if (toolName === 'Bash') {
    const cmd = String(input.command ?? '');
    const files: string[] = [];
    const uninspectable: string[] = [];
    const parts: string[] = [cmd];
    const read = (rel: string) => {
      const p = path.resolve(cwd, rel.replace(/^["']|["']$/g, ''));
      let st: fs.Stats;
      try { st = fs.statSync(p); } catch { return; /* not a local file */ }
      if (!st.isFile()) return;
      if (st.size > 1_000_000) { uninspectable.push(rel); return; }
      try { parts.push(fs.readFileSync(p, 'utf8')); files.push(rel); } catch { uninspectable.push(rel); }
    };
    for (const re of FILE_REFS) for (const m of cmd.matchAll(re)) read(m[1]);
    for (const m of cmd.matchAll(/\bnpm\s+run\s+([^\s;&|]+)/g)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8'));
        const s = pkg.scripts?.[m[1]];
        if (s) { parts.push(s); files.push(`package.json#${m[1]}`); }
      } catch { /* no package.json */ }
    }
    const text = parts.join('\n');
    const sqlish = DATA_SOURCE_RE.test(cmd) || files.some((f) => /\.sql$/i.test(f));
    return { text, files, sqlish, uninspectable };
  }
  // MCP: any sql/query/statement/command string field, at any depth
  const found: string[] = [];
  const walk = (v: unknown, key: string) => {
    if (typeof v === 'string') { if (/sql|query|statement|command|script/i.test(key)) found.push(v); return; }
    if (Array.isArray(v)) v.forEach((x) => walk(x, key));
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, k);
  };
  walk(input, '');
  const text = found.join('\n');
  return { text, files: [], sqlish: text.length > 0, uninspectable: [] };
}

/** Remove SQL comments and string literals so structural checks (WHERE) cannot be spoofed.
 *  Shell text wraps whole statements in quotes, so a quoted chunk that itself holds SQL keywords is kept. */
export function stripSql(sql: string): string {
  const literal = (m: string) => (SQL_RE.test(m) ? m : m[0] + m[0]);
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|\s)--\s[^\n]*/g, '$1')
    .replace(/'(?:[^'\\]|\\.|'')*'/g, literal)
    .replace(/"(?:[^"\\]|\\.)*"/g, (m) => (/^"[\w.]+"$/.test(m) ? m : literal(m)));
}

const ROOTS = new Set(['/', '/*', '~', '~/', '~/*', '$HOME', '$HOME/', '${HOME}', '${HOME}/', '/.', '~/.']);

function rmVerdict(seg: string): Verdict {
  const m = /(?:^|\s)(?:sudo\s+)?rm\s+(.*)$/s.exec(seg);
  if (!m) return null;
  const toks = m[1].split(/\s+/).filter(Boolean);
  const flags = toks.filter((t) => t.startsWith('-'));
  const r = flags.some((f) => /^-[a-zA-Z]*[rR]/.test(f) || f === '--recursive');
  const f = flags.some((f) => /^-[a-zA-Z]*f/.test(f) || f === '--force');
  if (!(r && f)) return null;
  const targets = toks.filter((t) => !t.startsWith('-')).map((t) => t.replace(/^["']|["']$/g, ''));
  if (targets.some((t) => ROOTS.has(t) || /^[A-Za-z]:[\\/]?\*?$/.test(t))) return { decision: 'deny', reason: `rm -rf on a root path: ${seg.trim()}` };
  return { decision: 'ask', reason: `Recursive force delete: ${seg.trim()}` };
}

const ASK_SHELL: [RegExp, string][] = [
  [/\bgit\s+reset\s+(?:\S+\s+)*--hard\b/, 'git reset --hard'],
  [/\bgit\s+clean\b[^\n;&|]*\s-[a-zA-Z]*f/, 'git clean -f'],
  [/\bgit\s+branch\s+(?:\S+\s+)*-D\b/, 'git branch -D'],
  [/\bterraform\s+destroy\b/, 'terraform destroy'],
  [/\bkubectl\s+delete\b/, 'kubectl delete'],
  [/\bdocker\s+system\s+prune\b/, 'docker system prune'],
  [/\balembic\s+downgrade\b/, 'alembic downgrade'],
  [/\bflyway\s+clean\b/, 'flyway clean'],
  [/\bprisma\s+migrate\s+reset\b/, 'prisma migrate reset'],
  [/Remove-Item\b[^\n;|]*-Recurse[^\n;|]*-Force|Remove-Item\b[^\n;|]*-Force[^\n;|]*-Recurse/i, 'Remove-Item -Recurse -Force'],
];

function forcePush(seg: string): Verdict {
  const m = /\bgit\b(?:\s+(?:-[Cc]\s+\S+|--?[\w-]+(?:=\S*)?))*\s+push\b(.*)$/s.exec(seg);
  if (!m) return null;
  const args = m[1];
  const force = /(?:^|\s)(?:--force(?:-with-lease)?|--force-if-includes|-[a-zA-Z]*f[a-zA-Z]*)(?:\s|$|=)/.test(args) || /(?:^|\s)\+\S+/.test(args);
  if (!force) return null;
  const refs = args.split(/\s+/).filter((t) => t && !t.startsWith('-'));
  const target = refs.some((r) => /^(?:\+?\S+:)?\+?(?:refs\/heads\/)?(main|master)$/.test(r));
  if (target) return { decision: 'deny', reason: `Force push to main/master: ${seg.trim()}` };
  return { decision: 'ask', reason: `Force push: ${seg.trim()}` };
}

function sqlVerdict(raw: string): Verdict {
  const text = stripSql(raw);
  for (const stmt of text.split(/;/)) {
    if (/\b(drop)\s+(table|database|schema|index|view|column|constraint|sequence|type|user|role|function|procedure|trigger|materialized\s+view|extension|owned)\b/i.test(stmt))
      return { decision: 'deny', reason: `DROP statement: ${stmt.trim().slice(0, 120)}` };
    if (/\btruncate\s+(table\s+)?["`\[]?\w/i.test(stmt))
      return { decision: 'deny', reason: `TRUNCATE statement: ${stmt.trim().slice(0, 120)}` };
  }
  for (const stmt of text.split(/;/)) {
    if (/\bupdate\s+["`\[]?[\w.]+["`\]]?\s+set\b/i.test(stmt) && !/\bwhere\b/i.test(stmt))
      return { decision: 'ask', reason: `UPDATE without WHERE: ${stmt.trim().slice(0, 120)}` };
    if (/\bdelete\s+from\s+["`\[]?[\w.]+/i.test(stmt) && !/\bwhere\b/i.test(stmt))
      return { decision: 'ask', reason: `DELETE without WHERE: ${stmt.trim().slice(0, 120)}` };
    if (/\balter\s+(table|database|schema|index|view|sequence|type|user|role|column)\b/i.test(stmt))
      return { decision: 'ask', reason: `ALTER statement: ${stmt.trim().slice(0, 120)}` };
  }
  return null;
}

/** Destructive pass: deny tier first, then ask tier. */
export function destructive(text: string): Verdict {
  const segs = text.split(/\n|&&|\|\||;|\|/);
  const verdicts: Verdict[] = [];
  for (const seg of segs) verdicts.push(forcePush(seg), rmVerdict(seg));
  verdicts.push(sqlVerdict(text));
  for (const [re, name] of ASK_SHELL) if (re.test(text)) verdicts.push({ decision: 'ask', reason: `Destructive command: ${name}` });
  return verdicts.find((v) => v?.decision === 'deny') ?? verdicts.find((v) => v) ?? null;
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** PII column pass: ask when SQL names a classified column or SELECT * from a classified table. */
export function piiColumns(sql: string, schema: Schema | null): Verdict {
  if (!schema || !SQL_RE.test(sql)) return null;
  const tables = Object.entries(schema.tables ?? {}).filter(([, cols]) => Object.keys(cols).length);
  for (const [table, cols] of tables) {
    const star = new RegExp(`\\bselect\\s+(?:distinct\\s+)?(?:[\\w"\`\\[\\]]+\\.)?\\*[\\s\\S]*?\\bfrom\\s+["\`\\[]?(?:\\w+\\.)?${esc(table)}["\`\\]]?\\b`, 'i');
    if (star.test(sql)) return { decision: 'ask', reason: `SELECT * from ${table}, which has PII columns (${Object.keys(cols).join(', ')}). Select explicit non-PII columns.` };
    for (const [col, label] of Object.entries(cols)) {
      const re = new RegExp(`(?<![\\w])["\`\\[]?${esc(col)}["\`\\]]?(?![\\w])`, 'i');
      if (re.test(sql)) return { decision: 'ask', reason: `Query touches PII column ${table}.${col} (${label}). Filter on a surrogate key or drop the column.` };
    }
  }
  return null;
}

export const BROKEN_SCHEMA: Schema = { tables: {} };

/** null: no schema configured. BROKEN_SCHEMA: file exists but cannot be read, SQL then asks. */
export function loadSchema(projectDir: string | null): Schema | null {
  if (!projectDir) return null;
  const p = path.join(projectDir, '.hush', 'schema.json');
  if (!fs.existsSync(p)) return null;
  try {
    const s = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!s || typeof s.tables !== 'object') return BROKEN_SCHEMA;
    return s;
  } catch { return BROKEN_SCHEMA; }
}

/** Walk up from cwd to the directory holding .hush/. */
export function findProject(cwd: string | undefined): string | null {
  if (!cwd) return null;
  let dir = path.resolve(cwd);
  for (;;) {
    if (fs.existsSync(path.join(dir, '.hush'))) return dir;
    const up = path.dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

export function guard(toolName: string, input: Record<string, unknown>, cwd: string, schema: Schema | null): Verdict {
  const { text, files, sqlish, uninspectable } = extract(toolName, input, cwd);
  if (!text.trim()) return null;
  const where = files.length ? ` (in ${files.join(', ')})` : '';
  const d = destructive(text);
  if (d) return { ...d, reason: d.reason + where };
  if (uninspectable.length) return { decision: 'ask', reason: `Script too large or unreadable to inspect: ${uninspectable.join(', ')}` };
  if (sqlish) {
    if (schema === BROKEN_SCHEMA) return { decision: 'ask', reason: '.hush/schema.json exists but is not valid JSON with a "tables" object, PII column guard is off until it is fixed.' };
    const p = piiColumns(stripSql(text), schema);
    if (p) return { ...p, reason: p.reason + where };
  }
  return null;
}

import fs from 'node:fs';
import path from 'node:path';

export type Schema = { tables: Record<string, Record<string, string>> };
export type Verdict = { decision: 'deny' | 'ask'; reason: string } | null;

export const DATA_SOURCE_RE = /\b(psql|mysql|sqlite3|sqlplus|mongosh|curl|gh|wget)\b/;
const SQL_KEYWORD = /\b(select|insert|update|delete|alter|drop|truncate|create|merge)\b/i;
const MAX_SCRIPT_BYTES = 1_000_000;
const REASON_EXCERPT_LENGTH = 120;

type Extracted = { text: string; files: string[]; hasSqlSource: boolean; uninspectable: string[] };

const SHELL_SCRIPT_ARGUMENT = /\b(?:bash|sh|zsh|source|\.)\s+([^\s;&|<>]+)/g;
const DIRECT_SCRIPT_PATH = /(?:^|[;&|]\s*|\bsudo\s+)((?:\.{1,2}\/|\/)[^\s;&|<>]+)/gm;
const SQL_CLIENT_FILE_FLAG = /\b(?:psql|sqlplus)\b[^;&|\n]*?\s-f\s*([^\s;&|<>]+)/g;
const SQL_CLIENT_STDIN_REDIRECT = /\b(?:psql|mysql|sqlite3|sqlplus|mongosh)\b[^;&|\n]*?<\s*([^\s;&|>]+)/g;
const PYTHON_SCRIPT = /\bpython3?\s+([^\s;&|<>]+\.py)\b/g;
const NODE_SCRIPT = /\bnode\s+([^\s;&|<>]+\.[cm]?[jt]s)\b/g;
const NPM_RUN_SCRIPT = /\bnpm\s+run\s+([^\s;&|]+)/g;
const SCRIPT_REFERENCES = [SHELL_SCRIPT_ARGUMENT, DIRECT_SCRIPT_PATH, SQL_CLIENT_FILE_FLAG, SQL_CLIENT_STDIN_REDIRECT, PYTHON_SCRIPT, NODE_SCRIPT];

const unquote = (s: string) => s.replace(/^["']|["']$/g, '');
const readJson = (file: string) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return undefined; } };

function extractBash(command: string, cwd: string): Extracted {
  const parts = [command], files: string[] = [], uninspectable: string[] = [];
  const includeScript = (reference: string) => {
    const file = path.resolve(cwd, unquote(reference));
    let stat: fs.Stats;
    try { stat = fs.statSync(file); } catch { return; }
    if (!stat.isFile()) return;
    if (stat.size > MAX_SCRIPT_BYTES) return uninspectable.push(reference);
    try { parts.push(fs.readFileSync(file, 'utf8')); files.push(reference); } catch { uninspectable.push(reference); }
  };
  for (const pattern of SCRIPT_REFERENCES) for (const match of command.matchAll(pattern)) includeScript(match[1]);
  for (const match of command.matchAll(NPM_RUN_SCRIPT)) {
    const script = readJson(path.join(cwd, 'package.json'))?.scripts?.[match[1]];
    if (script) { parts.push(script); files.push(`package.json#${match[1]}`); }
  }
  const hasSqlSource = DATA_SOURCE_RE.test(command) || files.some((f) => /\.sql$/i.test(f));
  return { text: parts.join('\n'), files, uninspectable, hasSqlSource };
}

function extractMcp(input: unknown): Extracted {
  const statements: string[] = [];
  const collect = (value: unknown, key: string) => {
    if (typeof value === 'string') { if (/sql|query|statement|command|script/i.test(key)) statements.push(value); }
    else if (Array.isArray(value)) value.forEach((item) => collect(item, key));
    else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) collect(v, k);
  };
  collect(input, '');
  return { text: statements.join('\n'), files: [], uninspectable: [], hasSqlSource: statements.length > 0 };
}

export function extract(toolName: string, input: Record<string, unknown>, cwd: string): Extracted {
  return toolName === 'Bash' ? extractBash(String(input.command ?? ''), cwd) : extractMcp(input);
}

export function stripSql(sql: string): string {
  const keepIfHoldsSql = (quoted: string) => (SQL_KEYWORD.test(quoted) ? quoted : quoted[0] + quoted[0]);
  const isQuotedIdentifier = (quoted: string) => /^"[\w.]+"$/.test(quoted);
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|\s)--\s[^\n]*/g, '$1')
    .replace(/'(?:[^'\\]|\\.|'')*'/g, keepIfHoldsSql)
    .replace(/"(?:[^"\\]|\\.)*"/g, (quoted) => (isQuotedIdentifier(quoted) ? quoted : keepIfHoldsSql(quoted)));
}

const ROOT_PATHS = new Set(['/', '/*', '~', '~/', '~/*', '$HOME', '$HOME/', '${HOME}', '${HOME}/', '/.', '~/.']);
const isDriveRoot = (target: string) => /^[A-Za-z]:[\\/]?\*?$/.test(target);

function rmVerdict(segment: string): Verdict {
  const rm = /(?:^|\s)(?:sudo\s+)?rm\s+(.*)$/s.exec(segment);
  if (!rm) return null;
  const args = rm[1].split(/\s+/).filter(Boolean);
  const flags = args.filter((a) => a.startsWith('-'));
  const recursive = flags.some((f) => /^-[a-zA-Z]*[rR]/.test(f) || f === '--recursive');
  const force = flags.some((f) => /^-[a-zA-Z]*f/.test(f) || f === '--force');
  if (!recursive || !force) return null;
  const targets = args.filter((a) => !a.startsWith('-')).map(unquote);
  if (targets.some((t) => ROOT_PATHS.has(t) || isDriveRoot(t))) return { decision: 'deny', reason: `rm -rf on a root path: ${segment.trim()}` };
  return { decision: 'ask', reason: `Recursive force delete: ${segment.trim()}` };
}

const GIT_PUSH = /\bgit\b(?:\s+(?:-[Cc]\s+\S+|--?[\w-]+(?:=\S*)?))*\s+push\b(.*)$/s;
const FORCE_FLAG = /(?:^|\s)(?:--force(?:-with-lease)?|--force-if-includes|-[a-zA-Z]*f[a-zA-Z]*)(?:\s|$|=)/;
const FORCE_REFSPEC = /(?:^|\s)\+\S+/;
const PROTECTED_BRANCH_REF = /^(?:\+?\S+:)?\+?(?:refs\/heads\/)?(main|master)$/;

function pushVerdict(segment: string): Verdict {
  const push = GIT_PUSH.exec(segment);
  if (!push) return null;
  const args = push[1];
  if (!FORCE_FLAG.test(args) && !FORCE_REFSPEC.test(args)) return null;
  const refs = args.split(/\s+/).filter((a) => a && !a.startsWith('-'));
  if (refs.some((r) => PROTECTED_BRANCH_REF.test(r))) return { decision: 'deny', reason: `Force push to main/master: ${segment.trim()}` };
  return { decision: 'ask', reason: `Force push: ${segment.trim()}` };
}

type SqlRule = { re: RegExp; decision: 'deny' | 'ask'; name: string; unlessWhere?: boolean };

const SQL_RULES: SqlRule[] = [
  { decision: 'deny', name: 'DROP statement', re: /\bdrop\s+(table|database|schema|index|view|column|constraint|sequence|type|user|role|function|procedure|trigger|materialized\s+view|extension|owned)\b/i },
  { decision: 'deny', name: 'TRUNCATE statement', re: /\btruncate\s+(table\s+)?["`\[]?\w/i },
  { decision: 'ask', name: 'UPDATE without WHERE', re: /\bupdate\s+["`\[]?[\w.]+["`\]]?\s+set\b/i, unlessWhere: true },
  { decision: 'ask', name: 'DELETE without WHERE', re: /\bdelete\s+from\s+["`\[]?[\w.]+/i, unlessWhere: true },
  { decision: 'ask', name: 'ALTER statement', re: /\balter\s+(table|database|schema|index|view|sequence|type|user|role|column)\b/i },
];

function sqlVerdicts(text: string): Verdict[] {
  const verdicts: Verdict[] = [];
  for (const statement of stripSql(text).split(';')) {
    const hasWhere = /\bwhere\b/i.test(statement);
    for (const rule of SQL_RULES) {
      const applies = rule.re.test(statement) && !(rule.unlessWhere && hasWhere);
      if (applies) verdicts.push({ decision: rule.decision, reason: `${rule.name}: ${statement.trim().slice(0, REASON_EXCERPT_LENGTH)}` });
    }
  }
  return verdicts;
}

const ALWAYS_ASK: [RegExp, string][] = [
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

const COMMAND_SEPARATOR = /\n|&&|\|\||;|\|/;

export function destructive(text: string): Verdict {
  const verdicts: Verdict[] = [];
  for (const segment of text.split(COMMAND_SEPARATOR)) verdicts.push(pushVerdict(segment), rmVerdict(segment));
  verdicts.push(...sqlVerdicts(text));
  for (const [pattern, name] of ALWAYS_ASK) if (pattern.test(text)) verdicts.push({ decision: 'ask', reason: `Destructive command: ${name}` });
  return verdicts.find((v) => v?.decision === 'deny') ?? verdicts.find(Boolean) ?? null;
}

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const selectStarFrom = (table: string) => new RegExp(`\\bselect\\s+(?:distinct\\s+)?(?:[\\w"\`\\[\\]]+\\.)?\\*[\\s\\S]*?\\bfrom\\s+["\`\\[]?(?:\\w+\\.)?${escapeRegex(table)}["\`\\]]?\\b`, 'i');
const columnIdentifier = (column: string) => new RegExp(`(?<![\\w])["\`\\[]?${escapeRegex(column)}["\`\\]]?(?![\\w])`, 'i');

export function piiColumns(sql: string, schema: Schema | null): Verdict {
  if (!schema || !SQL_KEYWORD.test(sql)) return null;
  for (const [table, columns] of Object.entries(schema.tables ?? {})) {
    const classified = Object.keys(columns);
    if (!classified.length) continue;
    if (selectStarFrom(table).test(sql)) return { decision: 'ask', reason: `SELECT * from ${table}, which has PII columns (${classified.join(', ')}). Select explicit non-PII columns.` };
    for (const [column, label] of Object.entries(columns)) {
      if (columnIdentifier(column).test(sql)) return { decision: 'ask', reason: `Query touches PII column ${table}.${column} (${label}). Filter on a surrogate key or drop the column.` };
    }
  }
  return null;
}

export function findProject(cwd: string | undefined): string | null {
  if (!cwd) return null;
  for (let dir = path.resolve(cwd); ; dir = path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, '.hush'))) return dir;
    const isFilesystemRoot = dir === path.dirname(dir);
    if (isFilesystemRoot) return null;
  }
}

export const BROKEN_SCHEMA: Schema = { tables: {} };

export function loadSchema(projectDir: string | null): Schema | null {
  if (!projectDir) return null;
  const file = path.join(projectDir, '.hush', 'schema.json');
  if (!fs.existsSync(file)) return null;
  const schema = readJson(file);
  return schema && typeof schema.tables === 'object' ? schema : BROKEN_SCHEMA;
}

export function guard(toolName: string, input: Record<string, unknown>, cwd: string, schema: Schema | null): Verdict {
  const { text, files, hasSqlSource, uninspectable } = extract(toolName, input, cwd);
  if (!text.trim()) return null;
  const location = files.length ? ` (in ${files.join(', ')})` : '';
  const withLocation = (verdict: Verdict) => verdict && { ...verdict, reason: verdict.reason + location };

  const dangerous = destructive(text);
  if (dangerous) return withLocation(dangerous);
  if (uninspectable.length) return { decision: 'ask', reason: `Script too large or unreadable to inspect: ${uninspectable.join(', ')}` };
  if (!hasSqlSource) return null;
  if (schema === BROKEN_SCHEMA) return { decision: 'ask', reason: '.hush/schema.json exists but is not valid JSON with a "tables" object; the PII column guard is off until it is fixed.' };
  return withLocation(piiColumns(stripSql(text), schema));
}

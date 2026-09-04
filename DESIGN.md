# cc-hush

Generic privacy plugin for Claude Code. Keeps PII and secrets out of the Anthropic API and out of third-party tools, blocks destructive operations, keeps ad-hoc SQL away from PII columns, and keeps a local audit log. TypeScript, Node 24, no framework, no build step.

## What it protects against

1. PII in prompts and tool results reaching the Anthropic API.
2. PII and secrets reaching third parties through tools (WebFetch, MCP servers, curl, gh).
3. Claude running destructive commands (force push, mutating SQL, rm -rf, terraform destroy).
4. Claude running ad-hoc queries that select or filter on PII columns.
5. No record of what flowed where (audit trail).

## Architecture

One native Node daemon on `127.0.0.1:47831` (fixed, `hooks.json` needs a static URL), started per machine, shared by all Claude Code sessions. It holds the model in memory and plays two roles:

- **API proxy.** `ANTHROPIC_BASE_URL` points at the daemon. The daemon rewrites outbound request bodies and forwards to the previous upstream (currently the caveman proxy at `http://127.0.0.1:8787/w/claude`). Responses stream back unchanged. All redaction happens here.
- **Hook server.** `hooks.json` uses command hooks (`hooks/hook.ts`) for UserPromptSubmit and PreToolUse. The wrapper posts the event JSON to the daemon and prints the decision; if the daemon cannot answer it exits 2, which blocks the prompt or tool call. Claude Code treats unreachable `type: http` hooks as non-blocking, so http hooks would fail open.

Because the daemon is also the API proxy, "daemon down" means Claude cannot reach the model at all. That is the fail-closed guarantee: nothing leaves unredacted. While the model is still loading, the daemon accepts connections and holds requests until ready.

```
Claude Code --http hooks--> hush daemon --/v1/*--> caveman proxy :8787 --> Anthropic
                            |
                            +- privacy-filter (openai/privacy-filter, q4, DirectML)
                            +- Belgian + secret regex
                            +- vault (in-memory, global)
                            +- audit (SQLite, node:sqlite)
```

Runtime: `node:http`, `@huggingface/transformers` with onnxruntime-node (auto-selects DirectML on Windows, CUDA where present, else CPU), `node:sqlite`. Node 24 strips types natively, so `.ts` files run directly. No Docker (would lose DirectML). No Express. No tsc.

Constants in code: dtype `q4`, threshold `0.5`, size cap `32KB`, data-source pattern `psql|mysql|sqlite3|sqlplus|mongosh|curl|gh|wget`.

## Configuration

**Machine** (`${CLAUDE_PLUGIN_DATA}/config.json`, per developer): `{ "upstream": "http://127.0.0.1:8787/w/claude" }`.

**Project** (`.hush/` in the repo, committed and shared):

- `.hush/config.json`
  ```json
  {
    "allowlist": ["Ewout Van Gossum", "qmino.com"],
    "allowPii": {
      "mcpServers": ["claude_ai_Atlassian_Rovo"],
      "tools": ["Write", "Edit", "MultiEdit"]
    }
  }
  ```
  `allowlist`: terms never treated as PII. `allowPii.mcpServers`: MCP server name prefixes whose tool inputs get real values rehydrated. `allowPii.tools`: built-in tools that get rehydrated. Defaults when the file is absent: no MCP servers, tools `Write`, `Edit`, `MultiEdit`. `Bash` is not rehydrated by default: `curl https://x/<PII:secret:1>` would otherwise exfiltrate the real value. Projects that add `Bash` still get a hard deny when the rehydrated command contains a network tool (`curl`, `wget`, `ssh`, `scp`, `gh`, `git push`, cloud CLIs, `docker push`, `npm publish`, ...).
- `.hush/schema.json`: PII column classification, built by the `hush-schema` skill, see below.

The daemon resolves `.hush/` by walking up from the hook payload's `cwd`. The proxy maps a request to its session through `metadata.user_id` (Claude Code puts `session_id` there) and uses that session's project policy; an unknown session gets the default policy with an empty allowlist, never another session's. Project config is trusted once Claude Code runs in that directory: opening a repo already means accepting its `.claude/settings.json` hooks, which are far more powerful than `.hush/config.json`, so no second trust prompt.

## Detection

Two detectors run over text. Spans are merged, highest score wins on overlap.

| Detector | Covers | Notes |
|---|---|---|
| Regex | Rijksregisternummer (11 digits, mod-97 check), BE IBAN, BTW `BE0xxx.xxx.xxx`, `+32` phones, gitleaks-style secret patterns (AWS, GitHub PAT, JWT, private key headers, generic `api[_-]?key=`) | Deterministic, runs first. |
| `openai/privacy-filter` (1.5B MoE, 50M active, q4 917MB) | account_number, private_address, private_email, private_person, private_phone, private_url, private_date, secret | English-trained. |

The project `allowlist` removes known-safe terms from results before tokenization. A span is dropped when it equals an allowlisted term or is a piece of one (`Van Gossum` for `Ewout Van Gossum`); containing a term is not enough, so `alice@qmino.com` stays PII when only `qmino.com` is allowlisted. Overlapping spans are merged into their union, the label follows the highest score.

Deferred: a Dutch NER model for person and location names. Added only if gate 2 on a Dutch Rovo issue shows misses. Candidate `Xenova/bert-base-multilingual-cased-ner-hrl`.

## Pseudonymization and the vault

Detected values are replaced with stable tokens: `<PII:email:3>`, `<PII:person:1>`, `<PII:secret:2>`. The vault is one global in-memory map `real value -> token` for the daemon's lifetime. The same value always yields the same token, which keeps Anthropic prompt caching intact across turns and across sessions. The vault dies with the daemon; older tokens in a transcript then stop rehydrating. Accepted.

Rehydration (token -> real value) happens in PreToolUse for tools listed in `allowPii.tools` and for MCP tools whose server is listed in `allowPii.mcpServers`. Everything else keeps the tokens in its input, so nothing leaks, at the cost of a literal `<PII:person:1>` landing in the target if Claude tries. Outputs of whitelisted MCP servers are still tokenized on the way in; the whitelist only governs what goes out.

`GET /debug/vault` dumps the map. Loopback only, and like `/hook` and `/shutdown` it requires the header `x-hush-token` with the contents of `${CLAUDE_PLUGIN_DATA}/token` (generated on first start, mode 0600), so other local users or stray processes cannot read or rehydrate the vault. The `/v1/*` proxy needs no token: it only ever removes data. `curl -H "x-hush-token: $(cat ~/.claude/plugins/data/hush/token)" 127.0.0.1:47831/debug/vault`.

The vault is shared by every session of the same OS user, by design (stable tokens across sessions). Tokens are guessable (`<PII:secret:1>`), so any Claude session on the machine can have a token rehydrated into its own Write. That is the same user's data landing in the same user's files; accepted.

## Redaction in the proxy

The proxy rewrites the request body before forwarding. Any error during parsing or redaction drops the request with a 502; the original body is never forwarded. Each `tool_result` block is paired with its `tool_use` block in the preceding assistant message, which gives the tool name and input.

| Block | Treatment | Model |
|---|---|---|
| `role: user` text | Full scan, all labels + regex, tokenize | Yes |
| `tool_result` of a data source (WebFetch, `mcp__*`, Bash whose command matches the data-source pattern) | Above 32KB: replaced with `Output too large for PII filter (N KB). Narrow the query: head, grep, LIMIT, or a smaller page.` Otherwise: MCP JSON key pass, then full scan, tokenize | Yes |
| Every other `tool_result` (Read, Grep, other Bash) | Regex pass (secrets, Belgian identifiers), then replace vault-known real values with their tokens, plain string match | No |
| System prompt (`system` string or text blocks) | Full scan, tokenize (memoized, so once per distinct prompt) | Yes |
| Assistant messages | Untouched | |

The third row closes the loop: a value rehydrated into a Bash command or written to a file cannot re-enter the API through Read or grep output. Redaction is memoized per block by content hash, so resent history costs one lookup per block.

MCP JSON key pass: a recursive walk over any MCP result that tokenizes values under the keys `emailAddress`, `displayName`, `accountId`, `author`, `reporter`, `assignee`, `creator`, and ADF `mention` text. One function, covers Jira, Confluence, GitHub. The model then scans the remaining free text.

The local transcript keeps raw values. Only outbound traffic is redacted.

## Prompt blocking

UserPromptSubmit blocks (`decision: block`) only when a **secret** is detected, by regex or model label. All other labels are allowed through and redacted by the proxy. The hook API has no prompt-rewrite field, which is why prompt redaction lives in the proxy.

## Shell and SQL guard

PreToolUse on `Bash` and `mcp__*`. One extraction step, two regex passes, no model, no SQL parser.

**Extraction.** From Bash: the command itself, plus the content of a referenced local file (`bash x.sh`, `sh x.sh`, `psql -f x.sql`, `mysql < x.sql`, `python x.py`, `./x.sh`, `npm run <script>` via `package.json`) read from `cwd`, depth 1. From MCP: any string field named like `sql`, `query`, `statement`, `command` or `script`, at any depth. A referenced script over 1 MB or unreadable makes the command ask. Application code written through Write and Edit is not checked.

**Destructive pass.** Two tiers.

Deny (hard stop, reason shown to Claude):
- `git push` with `--force`, `-f`, or `+refspec` targeting `main` or `master`
- `DROP`, `TRUNCATE`
- `rm -rf` (or `Remove-Item -Recurse -Force`) on `/`, `~`, `$HOME`, or a drive root

Ask (permission prompt with the matched pattern and file as reason):
- Any other force push
- `UPDATE` or `DELETE` without `WHERE`, `ALTER`
- `rm -rf` elsewhere, `git reset --hard`, `git clean -f`, `git branch -D`
- `terraform destroy`, `kubectl delete`, `docker system prune`, `alembic downgrade`, `flyway clean`, `prisma migrate reset`

**PII column pass.** Uses `.hush/schema.json`:

```json
{
  "tables": {
    "customer": { "email": "private_email", "rijksregisternummer": "account_number", "naam": "private_person" },
    "invoice": { "iban": "account_number" }
  }
}
```

Labels are the 8 privacy-filter labels plus `pii` as a generic fallback. Returns `ask` when the extracted SQL contains a classified column name (word-boundary, case-insensitive, with or without table prefix or quotes) or `SELECT *` / `SELECT t.*` from a table that has classified columns. Reason: `Query touches PII column customer.email (private_email). Filter on customer_id or drop the column.` Identifier matching is enough because the outcome is a prompt, not a block. Comments and string literals are stripped before the `WHERE` and column checks; a quoted chunk that itself contains SQL keywords (shell-quoted statements) is kept. A `.hush/schema.json` that exists but does not parse makes every SQL command ask until it is fixed.

## Hooks

`hooks/hooks.json`:

| Event | Matcher | Type | Action |
|---|---|---|---|
| SessionStart | | command | `node hooks/ensure-daemon.ts`: GET `/health`, spawn daemon detached if absent (`EADDRINUSE` means another session won), restart on version mismatch, emit `additionalContext` (two lines pointing at the `hush-guide` skill) |
| UserPromptSubmit | | command | `node hooks/hook.ts`: POST to `/hook`. Secret scan. Block or allow. Exit 2 if the daemon is unreachable. Audit. |
| PreToolUse | `Bash\|Write\|Edit\|MultiEdit\|mcp__.*` | command | `node hooks/hook.ts`, exit 2 if the daemon is unreachable. Dispatch on `tool_name`: shell and SQL guard for Bash and MCP, then rehydrate tokens in the input when the tool or server is whitelisted. Return `updatedInput`. Audit. |

No PostToolUse hook. Issue #34573 reported plugin `hooks.json` command hooks on tool events being dropped on Windows; first build step is a smoke test that the PreToolUse command hook fires in the installed Claude Code (2.1.260). If it does not, `hush-setup` copies the two hook entries into `~/.claude/settings.json`.

## Skills

| Skill | Purpose |
|---|---|
| `hush-setup` | Download the model to `${CLAUDE_PLUGIN_DATA}/models`, write machine `config.json`, start daemon, wait for `/health`, print the `ANTHROPIC_BASE_URL` line to put in settings. |
| `hush-guide` | Knowledge skill. Tells Claude what `<PII:label:n>` tokens are, to use them verbatim in whitelisted tools (they rehydrate), never to guess real values, never to put tokens into non-whitelisted MCP or WebFetch inputs (ask the user to do that step), what the size-cap message means and how to narrow, what the guard reasons mean, how to check `/health` and `/debug/vault`. Triggers on tokens, on the size-cap message, on guard denials. SessionStart injects two lines pointing here. |
| `hush-schema` | Builds or refreshes `.hush/schema.json`. (1) Find schema sources in the repo: entities, migrations, DDL, ORM schemas. (2) If a DB client or MCP DB tool is available, introspect live: `information_schema.columns` plus `col_description()` (PostgreSQL), `COLUMN_COMMENT` (MySQL), `ALL_COL_COMMENTS` (Oracle). Names, types and comments only, never a row. (3) Classify: a column comment containing `pii` wins, `pii:<label>` gives the label, bare `pii` gives the generic label; otherwise a name heuristic in English and Dutch (email, mail, phone, tel, gsm, name, naam, voornaam, achternaam, address, adres, straat, postcode, gemeente, birth, geboortedatum, iban, rekening, rijksregister, rrn, bsn, ssn, btw, vat, password, token, secret). (4) Merge into the existing file, existing entries win. (5) Print the table for review. |
| `hush-query` | How to write ad-hoc SQL that stays PII-free. Consults `.hush/schema.json` first. Select explicit non-PII columns, filter and join on surrogate keys, use aggregates, `LIMIT`, never `SELECT *` on a classified table, hand unavoidable PII queries to the user. Triggers when Claude is about to run SQL through Bash or an MCP DB tool. |
| `hush-logs` | Reviews code for log statements that emit PII: a diff, a file, or the statement Claude is about to write. Any logging or console call whose arguments reference a field classified in `.hush/schema.json` or matching the `hush-schema` name heuristic, or that passes a whole entity or DTO with such fields (implicit `toString()`). Also exception messages and MDC values built from those fields. One line per finding: file:line, leaked field, fix (log the surrogate id, mask, or exclude from `toString`). Advisory only, no hook. |

## Storage

`${CLAUDE_PLUGIN_DATA}/`: `models/`, `config.json`, `audit.sqlite` (table `audit(ts, session_id, event, tool_name, label, count, decision, latency_ms)`, labels and counts only, never values, no retention), `daemon.log`.

Project `.hush/`: `config.json`, `schema.json`.

## Plugin layout

```
cc-hush/
  .claude-plugin/plugin.json
  hooks/hooks.json
  hooks/ensure-daemon.ts
  hooks/hook.ts          command hook wrapper, POST /hook, exit 2 when the daemon is down
  skills/hush-setup/SKILL.md
  skills/hush-guide/SKILL.md
  skills/hush-schema/SKILL.md
  skills/hush-query/SKILL.md
  skills/hush-logs/SKILL.md
  daemon/server.ts   node:http, /health, /hook, /debug/vault, /v1/* proxy, policy load, audit insert
  daemon/detect.ts   regex + model, span merge, allowlist, MCP key pass
  daemon/vault.ts    tokenization, rehydration, whitelist check
  daemon/guard.ts    SQL extraction, destructive tiers, PII column match
  package.json
```

## Acceptance gates

1. The PreToolUse command hook fires from plugin `hooks.json` on Windows, Claude Code 2.1.260. With the daemon stopped, `git push --force origin main` is blocked with the "daemon unavailable" message.
2. p50 latency of a proxy scan on a 4KB Rovo issue result under 2s on the Arc Pro 140T via DirectML. Run once on an English and once on a Dutch issue. Dutch misses trigger the deferred NER model. Latency misses shrink scope before adding hardware.
3. Round trip: Rovo result with a real name becomes a token in the request body, Claude writes it to a file, the file holds the real name, and a `cat` of that file shows the token again in the next request body.
4. `git push --force origin main` is denied. `git push --force origin feature/x` asks. `bash deploy.sh` containing `DROP TABLE` asks.
5. With `customer.email` classified: `psql -c "select * from customer"` asks, `psql -c "select id from customer where email = 'x'"` asks, `psql -c "select count(*) from customer"` passes.
6. `hush-schema` on a repo with a `COMMENT ON COLUMN customer.email IS 'pii:email'` migration produces `"email": "private_email"` without any heuristic.
7. Rovo listed in `allowPii.mcpServers`: an `addCommentToJiraIssue` input with `<PII:person:1>` reaches Jira with the real name. Rovo not listed: the token reaches Jira verbatim.
8. Daemon killed mid-session: the next API call fails, no tool result is sent unredacted.
9. `hush-logs` on `log.info("Login for {}", customer.getEmail())` and on `log.debug("Loaded {}", customer)` where `Customer` has a classified `email` field reports both; `log.info("Login for customer {}", customer.getId())` is clean.

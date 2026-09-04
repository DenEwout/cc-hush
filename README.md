# cc-hush

Privacy plugin for [Claude Code](https://code.claude.com). Keeps PII and secrets out of the Anthropic API and out of third-party tools, blocks destructive commands, keeps ad-hoc SQL away from PII columns, and writes a local audit log.

TypeScript, Node 24, no framework, no build step. Detection runs locally with [`openai/privacy-filter`](https://huggingface.co/openai/privacy-filter) (q4, about 917 MB) plus deterministic regexes for Belgian identifiers and common secret formats.

## How it works

One local daemon on `127.0.0.1:47831`, shared by all Claude Code sessions, plays two roles:

- **API proxy.** `ANTHROPIC_BASE_URL` points at the daemon. Outbound request bodies are rewritten: user text and data-source tool results (WebFetch, MCP, `psql`, `curl`, ...) are scanned and PII is replaced by stable tokens like `<PII:email:3>`. Other tool results (Read, Grep) get the regex pass plus vault-known values replaced by plain string match. Responses stream back unchanged.
- **Hook server.** `UserPromptSubmit` blocks prompts containing secrets. `PreToolUse` runs the shell/SQL guard on `Bash` and MCP tools and rehydrates tokens back to real values for whitelisted tools (`Write`, `Edit`, listed MCP servers) so Claude can still act on the data without seeing it. Hooks are command hooks that exit 2 when the daemon cannot answer, so a dead daemon blocks instead of passing.

Daemon down means Claude cannot reach the model at all and every hooked tool call is blocked. Any redaction error drops the request instead of forwarding it. Nothing leaves unredacted.

```
Claude Code --http hooks--> hush daemon --/v1/*--> upstream (Anthropic or your own proxy)
                            |
                            +- privacy-filter model (onnxruntime: DirectML / CUDA / CPU)
                            +- Belgian + secret regex
                            +- vault (in-memory, real value <-> token)
                            +- audit (SQLite, labels and counts only)
```

## Install

```
claude plugin marketplace add DenEwout/cc-hush
claude plugin install hush
```

Then in Claude Code run the `hush-setup` skill, or by hand:

```
cd <plugin dir> && npm install --omit=dev
node hooks/ensure-daemon.ts        # downloads the model on first start
curl 127.0.0.1:47831/health        # wait for "model":"ready"
```

Add to `~/.claude/settings.json`:

```json
{ "env": { "ANTHROPIC_BASE_URL": "http://127.0.0.1:47831" } }
```

Machine config at `${CLAUDE_PLUGIN_DATA}/config.json` (default `~/.claude/plugins/data/hush/config.json`):

```json
{ "upstream": "https://api.anthropic.com", "device": "cpu" }
```

`device` defaults to `dml` on Windows and `cpu` elsewhere; `cuda` works where onnxruntime-node finds it.

## Project config

`.hush/config.json` in the repo, committed:

```json
{
  "allowlist": ["Ewout Van Gossum", "qmino.com"],
  "allowPii": {
    "mcpServers": ["claude_ai_Atlassian_Rovo"],
    "tools": ["Write", "Edit", "MultiEdit"]
  }
}
```

- `allowlist`: terms never treated as PII. Exact match or a piece of a term; `alice@qmino.com` is still redacted when only `qmino.com` is listed.
- `allowPii.mcpServers`: MCP server name prefixes whose tool inputs get real values. Everything else receives the literal token.
- `allowPii.tools`: built-in tools that get real values. Default when the file is absent: `Write`, `Edit`, `MultiEdit`. Adding `Bash` is possible but a rehydrated command containing `curl`, `wget`, `ssh`, `gh`, `git push` or a cloud CLI is denied.

`.hush/schema.json` classifies PII columns for the SQL guard. Build it with the `hush-schema` skill:

```json
{ "tables": { "customer": { "email": "private_email", "naam": "private_person" } } }
```

## Guard

| Tier | Trigger |
|---|---|
| Deny | force push to `main`/`master`, `DROP`, `TRUNCATE`, `rm -rf` on `/`, `~`, `$HOME` or a drive root |
| Ask | other force pushes, `UPDATE`/`DELETE` without `WHERE`, `ALTER`, `rm -rf` elsewhere, `git reset --hard`, `git clean -f`, `git branch -D`, `terraform destroy`, `kubectl delete`, `docker system prune`, `alembic downgrade`, `flyway clean`, `prisma migrate reset` |
| Ask | SQL naming a classified column, or `SELECT *` from a classified table |

Scripts referenced from the command (`bash x.sh`, `psql -f x.sql`, `mysql < x.sql`, `python x.py`, `npm run x`) are read from `cwd` and checked too.

## Skills

| Skill | Purpose |
|---|---|
| `hush-setup` | Install, model download, config, start daemon, settings line. |
| `hush-guide` | What tokens are, how to use them, what guard messages mean. |
| `hush-schema` | Build `.hush/schema.json` from migrations, ORM models or live `information_schema`. Column comments `pii:<label>` win over name heuristics. |
| `hush-query` | Writing ad-hoc SQL that avoids PII columns. |
| `hush-logs` | Review code for log statements that leak PII. |

## Endpoints

- `GET /health` version, model state, device, upstream, vault size.
- `GET /debug/vault` the token map.
- `POST /shutdown` stop the daemon (used on version upgrade).
- `POST /hook` hook endpoint.

The last three require the header `x-hush-token` with the contents of `${CLAUDE_PLUGIN_DATA}/token`:

```
curl -H "x-hush-token: $(cat ~/.claude/plugins/data/hush/token)" 127.0.0.1:47831/debug/vault
```
- Anything else is proxied to `upstream`.

## Storage

`${CLAUDE_PLUGIN_DATA}/`: `models/`, `config.json`, `token`, `audit.sqlite` (`audit(ts, session_id, event, tool_name, label, count, decision, latency_ms)`, never values), `daemon.log`.

## Limits

- The vault is in memory. Tokens from a previous daemon lifetime do not rehydrate.
- The model is English-trained. Dutch names are partly covered; a multilingual NER model is a planned addition if misses show up.
- The local transcript keeps raw values. Only outbound traffic is redacted.
- Redaction is memoized per block by content hash, which keeps prompt caching stable.

## Development

```
npm install
npm test
HUSH_UPSTREAM=http://127.0.0.1:47999 node daemon/server.ts
```

See [docs/](docs/README.md) for the architecture with diagrams and [DESIGN.md](DESIGN.md) for the design and acceptance gates.

## License

MIT

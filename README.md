# cc-hush

Privacy layer for [Claude Code](https://code.claude.com). Keeps PII and secrets out of the Anthropic API and out of third-party tools, blocks destructive commands, keeps ad-hoc SQL away from PII columns, and writes a local audit log.

Two parts:

- **`cc-hush`**, an npm package: the local daemon plus a CLI that installs it as a startup service.
- **`hush`**, a Claude Code plugin: hooks and skills that talk to the daemon.

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

Node 24 or newer.

```
npm i -g cc-hush
cc-hush install
claude plugin marketplace add DenEwout/cc-hush
claude plugin install hush
```

`cc-hush install` does four things, and is safe to re-run after `npm i -g cc-hush@latest` or a Node upgrade:

1. Downloads the model into `~/.cc-hush/models` with progress.
2. Registers a startup service for your user: a Windows scheduled task at logon (hidden, restarts on failure), a macOS launch agent (`~/Library/LaunchAgents/com.cc-hush.daemon.plist`), or a Linux systemd user unit (`~/.config/systemd/user/cc-hush.service`; headless boxes also need `loginctl enable-linger`).
3. Stops any running daemon and starts the new one through the service, waits for `/health`.
4. Sets `ANTHROPIC_BASE_URL` to `http://127.0.0.1:47831` in `~/.claude/settings.json` (`CLAUDE_CONFIG_DIR` respected). If the variable already holds another value it is left alone and you are told what to do.

Then restart Claude Code. The plugin's SessionStart hook reports `cc-hush daemon vX running (model ready)`. If the service is not running the hook starts `cc-hush start` itself and tells you to re-run `cc-hush install`.

Other commands: `cc-hush status`, `cc-hush stop`, `cc-hush start` (foreground; `--log` appends to `~/.cc-hush/daemon.log`).

### Uninstall

```
cc-hush uninstall        # stops the daemon, removes the startup service
npm rm -g cc-hush
claude plugin uninstall hush
```

`~/.cc-hush` (model, token, audit log) is kept; delete it by hand. Remove the `ANTHROPIC_BASE_URL` line from `~/.claude/settings.json`.

### Machine config

`~/.cc-hush/config.json`, optional:

```json
{ "upstream": "https://api.anthropic.com", "device": "cpu" }
```

`upstream` is where the daemon forwards API traffic; point it at another local proxy to chain them. `device` defaults to `dml` on Windows and `cpu` elsewhere; `cuda` works where onnxruntime-node finds it. `HUSH_UPSTREAM`, `HUSH_DEVICE` and `HUSH_DATA` override from the environment. Restart the daemon after changes (`cc-hush install`, or `cc-hush stop` and let the service bring it back).

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
| `hush-setup` | Install the daemon, service, config, settings line; repair; uninstall. |
| `hush-guide` | What tokens are, how to use them, what guard messages mean. |
| `hush-schema` | Build `.hush/schema.json` from migrations, ORM models or live `information_schema`. Column comments `pii:<label>` win over name heuristics. |
| `hush-query` | Writing ad-hoc SQL that avoids PII columns. |
| `hush-logs` | Review code for log statements that leak PII. |

## Endpoints

- `GET /health` version, model state, device, upstream, vault size.
- `GET /debug/vault` the token map.
- `POST /shutdown` stop the daemon.
- `POST /hook` hook endpoint.

The last three require the header `x-hush-token` with the contents of `~/.cc-hush/token`:

```
curl -H "x-hush-token: $(cat ~/.cc-hush/token)" 127.0.0.1:47831/debug/vault
```
- Anything else is proxied to `upstream`.

## Storage

`~/.cc-hush/`: `models/`, `config.json`, `token`, `audit.sqlite` (`audit(ts, session_id, event, tool_name, label, count, decision, latency_ms)`, never values), `daemon.log`, and on Windows the scheduled task XML.

## Limits

- The vault is in memory. Tokens from a previous daemon lifetime do not rehydrate.
- The model is English-trained. Dutch names are partly covered; a multilingual NER model is a planned addition if misses show up.
- The local transcript keeps raw values. Only outbound traffic is redacted.
- Redaction is memoized per block by content hash, which keeps prompt caching stable.
- The service pins the Node binary that ran `cc-hush install`. After switching Node versions (nvm, fnm, volta), re-run `cc-hush install`.

## Development

```
npm install
npm test
HUSH_UPSTREAM=http://127.0.0.1:47999 HUSH_DATA=/tmp/hush node bin/cc-hush.ts start
```

Repo layout: `bin/` and `daemon/` are the npm package (see `files` in `package.json`); `plugin/` is the Claude Code plugin, referenced from `.claude-plugin/marketplace.json`. To try the plugin from a checkout: `claude plugin marketplace add /path/to/cc-hush`.

See [docs/](docs/README.md) for the architecture with diagrams and [DESIGN.md](DESIGN.md) for the design and acceptance gates.

## License

MIT

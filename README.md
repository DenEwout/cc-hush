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
                            +- vault (SQLite, real value <-> token, survives restarts)
                            +- audit (SQLite, labels and counts only)
```

## Install

Node 24 or newer.

```
npm i -g cc-hush
cc-hush install
```

`cc-hush install` does five things, and is safe to re-run after `npm i -g cc-hush@latest` or a Node upgrade:

1. Downloads the model into `~/.cc-hush/models` with progress.
2. Registers a startup service for your user: a Windows logon entry (`HKCU\...\CurrentVersion\Run`, started hidden through `~/.cc-hush/start.vbs`), a macOS launch agent (`~/Library/LaunchAgents/com.cc-hush.daemon.plist`), or a Linux systemd user unit (`~/.config/systemd/user/cc-hush.service`; headless boxes also need `loginctl enable-linger`).
3. Stops any running daemon and starts the new one through the service, waits for `/health`.
4. Sets `ANTHROPIC_BASE_URL` to `http://127.0.0.1:47831` in `~/.claude/settings.json` (`CLAUDE_CONFIG_DIR` respected). If the variable already points at another proxy, install asks whether to chain it: answer yes and that URL becomes `upstream` in `~/.cc-hush/config.json`, so traffic goes Claude Code, cc-hush, your proxy, Anthropic. Answer no, or run non-interactively, and the setting is left alone with instructions printed.
5. Installs the `hush` plugin through `claude plugin marketplace add DenEwout/cc-hush` and `claude plugin install hush@cc-hush` when the `claude` CLI is on PATH. Otherwise it prints those two commands.

Then restart Claude Code. The plugin's SessionStart hook reports `cc-hush daemon vX running (model ready)`. If the service is not running the hook starts `cc-hush start` itself and tells you to re-run `cc-hush install`.

Other commands: `cc-hush status`, `cc-hush stop`, `cc-hush start` (foreground; `--log` appends to `~/.cc-hush/daemon.log`).

### Uninstall

```
cc-hush uninstall        # stops the daemon, removes the startup service and the plugin
npm rm -g cc-hush
```

`~/.cc-hush` (model, token, audit log) is kept; delete it by hand. Remove the `ANTHROPIC_BASE_URL` line from `~/.claude/settings.json`.

### Machine config

`~/.cc-hush/config.json`, optional:

```json
{ "upstream": "https://api.anthropic.com", "device": "cpu" }
```

`upstream` is where the daemon forwards API traffic; point it at another local proxy to chain them. `device` defaults to `cpu`; `dml` (Windows) and `cuda` are opt-in. Measure before switching: on an Intel Arc Pro 140T, `dml` scanned the q4 model 2x slower than `cpu` (68 KB of prose: 17 s against 10 s). `HUSH_UPSTREAM`, `HUSH_DEVICE` and `HUSH_DATA` override from the environment. Restart the daemon after changes (`cc-hush install`, or `cc-hush stop` and let the service bring it back).

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

`~/.cc-hush/`: `models/`, `config.json`, `token`, `vault.sqlite` (real value, token, label; mode 600; the same data Claude Code's own transcripts already keep on this disk), `audit.sqlite` (`audit(ts, session_id, event, tool_name, label, count, decision, latency_ms)`, never values), `daemon.log`, and on Windows `start.vbs`.

## Limits

- The vault lives in `~/.cc-hush/vault.sqlite`, so tokens survive daemon restarts and `claude --resume`. Tokens issued before that file existed, or on another machine, cannot be resolved; the Write and Edit hooks then ask before leaving literal placeholders in a file.
- The model is English-trained. Dutch names are partly covered; a multilingual NER model is a planned addition if misses show up.
- The local transcript keeps raw values. Only outbound traffic is redacted.
- Redaction is memoized per block by content hash, which keeps prompt caching stable.
- The service pins the Node binary that ran `cc-hush install`. After switching Node versions (nvm, fnm, volta), re-run `cc-hush install`.
- All three launchers restart the daemon after a non-zero exit (the Windows `start.vbs` loops with a 5 s pause). Exit 0, from `cc-hush stop` or a port already in use, is final. Crashes land in `~/.cc-hush/daemon.log`.

## Development

```
npm install
npm test              # unit tests plus proxy and hook integration tests against a fake downstream proxy, no model needed
npm run test:e2e      # opt-in: runs the real `claude -p` through a real daemon with your own credentials, two Haiku calls
HUSH_UPSTREAM=http://127.0.0.1:47999 HUSH_DATA=/tmp/hush HUSH_PORT=47832 node bin/cc-hush.ts start
```

The integration tests start `startDaemon()` on an ephemeral port with a stub detector and a fake upstream that records what it received, so path prefixing, header passthrough, streaming, 429 passthrough, abandoned requests and the hook protocol are all checked without the 917 MB model. The e2e test copies `.credentials.json` into a temporary `CLAUDE_CONFIG_DIR`, points `ANTHROPIC_BASE_URL` and the plugin hooks at a daemon on a free port, and asserts on the daemon's audit log.

Repo layout: `bin/` and `daemon/` are the npm package (see `files` in `package.json`); `plugin/` is the Claude Code plugin, referenced from `.claude-plugin/marketplace.json`. To try the plugin from a checkout: `claude plugin marketplace add /path/to/cc-hush`.

See [docs/](docs/README.md) for the architecture with diagrams and [DESIGN.md](DESIGN.md) for the design and acceptance gates.

## License

MIT

---
name: hush-setup
description: One-time machine setup for cc-hush. Installs the cc-hush daemon globally with npm, registers it as a startup service, downloads the privacy-filter model and points Claude Code at the proxy. Use when the user asks to set up, install, repair or remove cc-hush, or when SessionStart reports the daemon not reachable.
---

# hush-setup

The daemon is an npm package, separate from this plugin. The plugin only ships hooks and skills that talk to it on `127.0.0.1:47831`.

1. **Install the daemon.** Needs Node 24 or newer (`node --version`).
   ```
   npm i -g cc-hush
   cc-hush install
   ```
   `install` downloads `openai/privacy-filter` (q4, about 917 MB) into `~/.cc-hush/models`, registers a startup service (Windows per-user Run key with a hidden launcher, macOS launch agent, Linux systemd user unit), starts the daemon, sets `ANTHROPIC_BASE_URL` to `http://127.0.0.1:47831` in `~/.claude/settings.json` and installs this plugin through `claude plugin` when the `claude` CLI is on PATH. Re-run it after `npm i -g cc-hush@latest` or a Node upgrade; it is idempotent.
2. **Existing proxy.** When `ANTHROPIC_BASE_URL` already holds another value (for example a caveman proxy on `http://127.0.0.1:8787/w/claude`), `install` asks whether to chain it. Yes writes it as `upstream` into `~/.cc-hush/config.json` and points `ANTHROPIC_BASE_URL` at cc-hush. Non-interactive runs skip the question and leave the setting alone; then do it by hand:
   ```json
   { "upstream": "http://127.0.0.1:8787/w/claude" }
   ```
   Optional `"device": "cpu" | "dml" | "cuda"`; default is `cpu`, which measured 2x faster than `dml` for this q4 model on an Intel Arc iGPU. Restart the daemon after editing: `cc-hush install` or `cc-hush stop` and let the service restart it.
3. **Restart Claude Code.** SessionStart must report `cc-hush daemon vX running (model ready)` with no `ANTHROPIC_BASE_URL` warning. From then on, if the daemon is down Claude cannot reach the model at all. That is intended: nothing leaves unredacted.
4. **Project config (optional).** Create `.hush/config.json` in the repo with `allowlist` (terms never treated as PII, for example the team's own names and company domain) and `allowPii` (tools and MCP server prefixes that receive real values). Run `hush-schema` to build `.hush/schema.json`.
5. **Check the guard fires.** Ask Claude to run `git push --force origin main` in a scratch repo. It must be denied with a `cc-hush:` reason. If nothing happens (seen on Windows with plugin hooks on tool events, issue #34573), copy the `UserPromptSubmit` and `PreToolUse` entries from `${CLAUDE_PLUGIN_ROOT}/hooks/hooks.json` into `~/.claude/settings.json` under `hooks`, replacing `${CLAUDE_PLUGIN_ROOT}` with the absolute plugin path.

Verify: `cc-hush status` shows `"model":"ready"`; `curl -H "x-hush-token: $(cat ~/.cc-hush/token)" 127.0.0.1:47831/debug/vault` shows the token map after a prompt containing an email address.

Remove: `cc-hush uninstall` stops the daemon, removes the startup service and uninstalls this plugin. `~/.cc-hush` (model, token, audit log) stays until deleted by hand. Then `npm rm -g cc-hush` and drop the `ANTHROPIC_BASE_URL` line from settings.

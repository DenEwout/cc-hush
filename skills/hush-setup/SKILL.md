---
name: hush-setup
description: One-time machine setup for cc-hush. Installs dependencies, downloads the privacy-filter model, writes machine config, starts the daemon and prints the ANTHROPIC_BASE_URL setting. Use when the user asks to set up, install, or repair cc-hush, or when SessionStart reports the daemon or dependencies missing.
---

# hush-setup

Run these steps in order. `${CLAUDE_PLUGIN_ROOT}` is the plugin install directory, `${CLAUDE_PLUGIN_DATA}` the plugin data directory (default `~/.claude/plugins/data/hush`).

1. **Dependencies.** `cd "${CLAUDE_PLUGIN_ROOT}" && npm install --omit=dev`. Needs Node 24 or newer (`node --version`). Installs `@huggingface/transformers` and `onnxruntime-node`.
2. **Machine config.** Write `${CLAUDE_PLUGIN_DATA}/config.json`:
   ```json
   { "upstream": "https://api.anthropic.com" }
   ```
   If the user already routes through another proxy (for example a caveman proxy on `http://127.0.0.1:8787/w/claude`), put that URL in `upstream` instead. Optional `"device": "dml" | "cuda" | "cpu"`; default is `dml` on Windows, `cpu` elsewhere.
3. **Start the daemon.** `node "${CLAUDE_PLUGIN_ROOT}/hooks/ensure-daemon.ts"`. First start downloads `openai/privacy-filter` (q4, about 917 MB) into `${CLAUDE_PLUGIN_DATA}/models`. Follow `${CLAUDE_PLUGIN_DATA}/daemon.log`.
4. **Wait for health.** Poll `curl -s 127.0.0.1:47831/health` until `"model":"ready"`.
5. **Point Claude Code at the proxy.** Tell the user to add to `~/.claude/settings.json`:
   ```json
   { "env": { "ANTHROPIC_BASE_URL": "http://127.0.0.1:47831" } }
   ```
   and restart Claude Code. From then on, if the daemon is down Claude cannot reach the model at all. That is intended: nothing leaves unredacted.
6. **Project config (optional).** Create `.hush/config.json` in the repo with `allowlist` (terms never treated as PII, for example the team's own names and company domain) and `allowPii` (tools and MCP server prefixes that receive real values). Run `hush-schema` to build `.hush/schema.json`.

7. **Check the guard fires.** Ask Claude to run `git push --force origin main` in a scratch repo. It must be denied with a `cc-hush:` reason. If nothing happens (seen on Windows with plugin hooks on tool events, issue #34573), copy the `UserPromptSubmit` and `PreToolUse` entries from `${CLAUDE_PLUGIN_ROOT}/hooks/hooks.json` into `~/.claude/settings.json` under `hooks`, replacing `${CLAUDE_PLUGIN_ROOT}` with the absolute plugin path.

Verify: `curl -H "x-hush-token: $(cat ${CLAUDE_PLUGIN_DATA}/token)" 127.0.0.1:47831/debug/vault` shows the token map after a prompt containing an email address.

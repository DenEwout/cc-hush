---
name: hush-guide
description: How to work with cc-hush privacy tokens and guard messages. Use whenever text contains <PII:label:n> tokens, when a tool result says "Output too large for PII filter", when a command is denied or prompts with a "cc-hush:" reason, or when asked how cc-hush works or how to check its status.
---

# hush-guide

cc-hush sits between Claude Code and the Anthropic API. Everything you see has already been redacted. The user sees real values locally.

## Tokens

- `<PII:email:3>`, `<PII:person:1>`, `<PII:phone:2>`, `<PII:address:1>`, `<PII:account:4>`, `<PII:url:1>`, `<PII:date:2>`, `<PII:secret:1>` stand for real values held in a local vault. The same real value always maps to the same token.
- **Use tokens verbatim.** In `Write`, `Edit` and whitelisted MCP tools they are rehydrated to the real value before execution. A file you write with `<PII:person:1>` will contain the real name. `Bash` is not rehydrated unless the project enables it, and never for commands that can send data off the machine (`curl`, `ssh`, `gh`, `git push`...).
- **Never guess or reconstruct a real value.** Never ask the user to paste it. If you need to know which token is which, refer to it by token.
- **Never put tokens into non-whitelisted destinations** (WebFetch, MCP servers not listed in `.hush/config.json` `allowPii.mcpServers`, `curl` to external hosts). The token would land there literally. Ask the user to perform that step themselves.
- Output from any tool, including whitelisted MCP servers, is tokenized on the way back in. A `cat` of a file you just wrote shows tokens again. That is expected.
- A permission prompt saying `PII token(s) this daemon cannot resolve` means the token predates the persisted vault or came from another machine. Do not accept it to force the write: re-fetch the source data so fresh, resolvable tokens replace the stale ones, or ask the user for the value.

## Messages you may see

- `Output too large for PII filter (N KB). Narrow the query...` : tool result exceeded 32 KB and was dropped. Re-run with `head`, `grep`, `LIMIT`, pagination or a narrower JQL/CQL.
- `cc-hush: prompt contains N secret(s)` : the user's prompt was blocked before reaching the model. Ask them to remove the secret and refer to it by name or environment variable.
- `cc-hush: Force push to main/master` / `DROP statement` / `rm -rf on a root path` : hard deny. Do not retry with variations. Explain and offer a safe alternative.
- `cc-hush: Query touches PII column table.col (label)` : the user gets a permission prompt. Prefer rewriting per the `hush-query` skill: explicit non-PII columns, filter on surrogate keys, aggregates.
- `cc-hush: UPDATE without WHERE` / `Destructive command: ...` : permission prompt. Confirm intent, add a `WHERE`, or narrow scope.

## Status

- `curl 127.0.0.1:47831/health` : version, model state, device, upstream, vault size.
- `curl -H "x-hush-token: $(cat ~/.cc-hush/token)" 127.0.0.1:47831/debug/vault` : the token map (loopback only, token file at `~/.cc-hush/token`). Do not paste its output back into the conversation.
- Log: `~/.cc-hush/daemon.log`. Audit: `~/.cc-hush/audit.sqlite`, labels and counts only.
- `cc-hush: privacy daemon unavailable ... blocked` : the daemon is down; every hooked tool call and prompt is blocked until it is back. Run the `hush-setup` skill step 3.
- If the API is unreachable, the daemon is down. Same fix.

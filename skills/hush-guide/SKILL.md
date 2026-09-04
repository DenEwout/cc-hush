---
name: hush-guide
description: How to work with cc-hush privacy tokens and guard messages. Use whenever text contains <PII:label:n> tokens, when a tool result says "Output too large for PII filter", when a command is denied or prompts with a "cc-hush:" reason, or when asked how cc-hush works or how to check its status.
---

# hush-guide

cc-hush sits between Claude Code and the Anthropic API. Everything you see has already been redacted. The user sees real values locally.

## Tokens

- `<PII:email:3>`, `<PII:person:1>`, `<PII:phone:2>`, `<PII:address:1>`, `<PII:account:4>`, `<PII:url:1>`, `<PII:date:2>`, `<PII:secret:1>` stand for real values held in a local vault. The same real value always maps to the same token.
- **Use tokens verbatim.** In `Write`, `Edit`, `Bash` and whitelisted MCP tools they are rehydrated to the real value before execution. A file you write with `<PII:person:1>` will contain the real name.
- **Never guess or reconstruct a real value.** Never ask the user to paste it. If you need to know which token is which, refer to it by token.
- **Never put tokens into non-whitelisted destinations** (WebFetch, MCP servers not listed in `.hush/config.json` `allowPii.mcpServers`, `curl` to external hosts). The token would land there literally. Ask the user to perform that step themselves.
- Output from any tool, including whitelisted MCP servers, is tokenized on the way back in. A `cat` of a file you just wrote shows tokens again. That is expected.
- Tokens from a previous daemon lifetime do not rehydrate. If the user reports a literal token in a file, the daemon was restarted; ask them to re-provide the value.

## Messages you may see

- `Output too large for PII filter (N KB). Narrow the query...` : tool result exceeded 32 KB and was dropped. Re-run with `head`, `grep`, `LIMIT`, pagination or a narrower JQL/CQL.
- `cc-hush: prompt contains N secret(s)` : the user's prompt was blocked before reaching the model. Ask them to remove the secret and refer to it by name or environment variable.
- `cc-hush: Force push to main/master` / `DROP statement` / `rm -rf on a root path` : hard deny. Do not retry with variations. Explain and offer a safe alternative.
- `cc-hush: Query touches PII column table.col (label)` : the user gets a permission prompt. Prefer rewriting per the `hush-query` skill: explicit non-PII columns, filter on surrogate keys, aggregates.
- `cc-hush: UPDATE without WHERE` / `Destructive command: ...` : permission prompt. Confirm intent, add a `WHERE`, or narrow scope.

## Status

- `curl 127.0.0.1:47831/health` : version, model state, device, upstream, vault size.
- `curl 127.0.0.1:47831/debug/vault` : the token map (loopback only). Do not paste its output back into the conversation.
- Log: `${CLAUDE_PLUGIN_DATA}/daemon.log`. Audit: `${CLAUDE_PLUGIN_DATA}/audit.sqlite`, labels and counts only.
- If the API is unreachable, the daemon is down. Run the `hush-setup` skill step 3.

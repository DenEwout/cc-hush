# Hooks and guard

Claude Code runs three hooks from `hooks/hooks.json`. All are command hooks: an unreachable daemon makes `hooks/hook.ts` exit 2, which blocks the prompt or tool call. HTTP hooks were not used because Claude Code treats a failed HTTP hook as "continue".

| Event | Script | Matcher | Outcome |
|---|---|---|---|
| SessionStart | `ensure-daemon.ts` | | check the daemon, start `cc-hush start` as a fallback when the startup service did not, inject two lines of context, warn if `ANTHROPIC_BASE_URL` does not point at the proxy |
| UserPromptSubmit | `hook.ts` | | block when the prompt contains a secret |
| PreToolUse | `hook.ts` | `Bash\|Write\|Edit\|MultiEdit\|mcp__.*` | rehydrate tokens for whitelisted tools, run the guard, return `updatedInput` and a permission decision |

## Session start

```mermaid
flowchart TD
    S[SessionStart] --> H{GET /health ok?}
    H -- yes --> R[running]
    H -- no --> ST["spawn cc-hush start --log detached (PATH)"] --> W[wait 1.5 s] --> H2{GET /health ok?}
    H2 -- yes --> R2["started by hook, advise cc-hush install"] --> B
    H2 -- no --> N["not reachable: npm i -g cc-hush && cc-hush install"] --> B
    R --> B{ANTHROPIC_BASE_URL is<br/>http://127.0.0.1:47831?}
    B -- no --> WARN["append WARNING: traffic not going through the proxy"]
    B -- yes --> OUT
    WARN --> OUT[additionalContext for Claude]
```

## Prompt submit

```mermaid
sequenceDiagram
    participant CC as Claude Code
    participant HK as hooks/hook.ts
    participant D as daemon /hook
    CC->>HK: event JSON on stdin
    HK->>D: POST /hook, x-hush-token
    D->>D: onUserPromptSubmit → detect(prompt)
    alt any span labelled secret
        D-->>HK: { decision: block, reason }
    else
        D-->>HK: {}
    end
    HK-->>CC: stdout JSON, exit 0
    Note over HK: daemon unreachable → stderr message, exit 2 → prompt blocked
```

Only secrets block. Names, emails and other PII pass through the hook and are tokenized by the proxy; the hook API has no prompt-rewrite field.

## Tool use

```mermaid
flowchart TD
    E[PreToolUse event] --> REC[cwdBySession ← cwd<br/>policy ← policyFor cwd]
    REC --> WL{isWhitelisted tool?<br/>allowPii.tools or<br/>allowPii.mcpServers prefix}
    WL -- yes --> RH[rehydrateDeep input]
    RH --> CH{changed?}
    CH -- yes --> EG{Bash and<br/>NETWORK_COMMAND?}
    EG -- yes --> DENY1[deny: refusing to rehydrate into a network command]
    EG -- no --> UI[updatedInput ← real values]
    CH -- no --> G
    UI --> G
    WL -- no --> G{Bash or mcp__* ?}
    G -- yes --> GU[guard tool, input, cwd, schema]
    GU --> V{verdict}
    V -- deny --> DENY2[permissionDecision deny + reason]
    V -- ask --> ASK[permissionDecision ask + reason]
    V -- none --> OK[no decision: normal permission flow]
    G -- no --> OK
```

No `permissionDecision` is returned for a clean call. `updatedInput` applies on its own, and returning `allow` would skip the user's own permission prompt for Write and Edit.

Any exception inside `handleHook` is turned into `deny` (PreToolUse) or `block` (UserPromptSubmit) by `hookResponseFailingClosed`, never into a 5xx.

## The guard

```mermaid
flowchart LR
    subgraph extract
        direction TB
        X1["Bash: command + referenced scripts<br/>bash x.sh · ./x.sh · psql -f · mysql &lt; · python · node · npm run"]
        X2["MCP: string fields named<br/>sql · query · statement · command · script, any depth"]
    end
    extract --> D[destructive]
    D -- verdict --> R1[return, deny beats ask]
    D -- none --> U{uninspectable scripts?}
    U -- yes --> R2[ask: too large or unreadable]
    U -- no --> S{hasSqlSource?}
    S -- no --> R3[allow]
    S -- yes --> B{schema BROKEN?}
    B -- yes --> R4[ask: fix .hush/schema.json]
    B -- no --> P[piiColumns on stripSql text]
    P --> R5[ask or allow]
```

### Destructive tiers

| Tier | Trigger |
|---|---|
| deny | `git push` with `--force`, `-f` or `+ref` targeting `main` or `master`, also `git -C dir push` |
| deny | `DROP table/database/schema/…`, `TRUNCATE` |
| deny | `rm` with `-r` and `-f` on `/`, `~`, `$HOME`, or a drive root |
| ask | any other force push, `rm -rf` elsewhere |
| ask | `UPDATE … SET` or `DELETE FROM` without `WHERE`, `ALTER` |
| ask | `git reset --hard`, `git clean -f`, `git branch -D`, `terraform destroy`, `kubectl delete`, `docker system prune`, `alembic downgrade`, `flyway clean`, `prisma migrate reset`, `Remove-Item -Recurse -Force` |

`stripSql` removes comments and string literals before the WHERE check, so `UPDATE t SET x=1 /* where */` still asks. A quoted chunk that itself contains SQL keywords is kept, because shell commands quote whole statements.

### PII column pass

Runs only when the command is a data source or reads a `.sql` file. With `.hush/schema.json`:

```json
{ "tables": { "customer": { "email": "private_email", "naam": "private_person" } } }
```

| SQL | Result |
|---|---|
| `select * from customer` | ask: SELECT * from a table with PII columns |
| `select c.* from customer c` | ask |
| `select id from customer where email = 'x'` | ask: touches `customer.email` (private_email) |
| `select count(*) from customer` | allow |
| `select emailed from customer` | allow, word boundary |

Identifier matching is enough because the outcome is a permission prompt, never a hard block.

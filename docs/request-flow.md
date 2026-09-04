# Request flow

## One API call

```mermaid
sequenceDiagram
    participant CC as Claude Code
    participant PX as proxy()
    participant RR as RequestRedaction
    participant DT as detect()
    participant VT as vault
    participant UP as upstream

    CC->>PX: POST /v1/messages (raw body)
    PX->>PX: readBody, await modelLoaded
    PX->>RR: redactRequest(body)
    RR->>RR: sessionIdOf(body.metadata.user_id)
    RR->>RR: policyFor(cwdBySession[session])
    loop every text-bearing block
        RR->>DT: detect(text, allowlist)
        DT-->>RR: spans
        RR->>VT: applySpans → tokens
    end
    RR-->>PX: redacted body + label counts
    PX->>PX: audit(session, "proxy", labels)
    PX->>UP: forwardUpstream(redacted body)
    UP-->>CC: response streamed through, untouched
    Note over PX,UP: Any throw before forwarding → 502 to Claude Code, nothing sent upstream
```

The session id lets the proxy pick the right project policy. Claude Code puts `{"session_id": ...}` as a JSON string inside `metadata.user_id`; the hooks recorded that session's `cwd` earlier. An unknown session gets `DEFAULT_POLICY` with an empty allowlist.

## What happens to each block

`RequestRedaction.redactBody` walks `system` and every message. Assistant messages are only read to pair each `tool_result` with the `tool_use` that produced it.

```mermaid
flowchart TD
    B[block] --> T{type}
    T -- "system text<br/>user text" --> M[scanWithModel]
    T -- "tool_result" --> DS{isExternalDataSource?<br/>WebFetch, mcp__*, Bash matching<br/>psql·mysql·sqlite3·sqlplus·mongosh·curl·gh·wget}
    DS -- no --> RV[scanWithRegexAndVault<br/>regex spans + redactKnown]
    DS -- yes --> SZ{"> 32 KB?"}
    SZ -- yes --> CAP["replace with<br/>'Output too large for PII filter (N KB)...'"]
    SZ -- no --> MCP{mcp__* ?}
    MCP -- yes --> KP[mcpKeyPassText<br/>tokenize known JSON keys] --> M
    MCP -- no --> M
    T -- "assistant content" --> U[untouched]
    M --> OUT[tokens in place of values]
    RV --> OUT
```

| Block | Treatment | Model |
|---|---|---|
| `system` string or text blocks | full scan, memoized by content hash | yes |
| `role: user` text | full scan, memoized | yes |
| `tool_result` of an external data source | size cap, MCP key pass, full scan | yes |
| every other `tool_result` (Read, Grep, plain Bash) | regex spans, then vault-known values by plain string match | no |
| assistant messages | untouched | |

## Why the cheap pass matters

```mermaid
sequenceDiagram
    participant Rovo as MCP result
    participant PX as proxy
    participant CL as Claude
    participant HK as PreToolUse hook
    participant FS as file / shell

    Rovo->>PX: "reporter: John Doe"
    PX->>CL: "reporter: PII:person:3"
    CL->>HK: Write file with PII:person:3
    HK->>FS: rehydrated → "John Doe" written
    CL->>FS: cat file
    FS->>PX: "John Doe"
    PX->>CL: "PII:person:3"  (redactKnown, no model needed)
```

A value that was rehydrated into a file or command cannot re-enter the API through Read, Grep or Bash output: `redactKnown` swaps every vault-known value back to its token. The regex pass on the same output catches new secrets and Belgian identifiers that never went through the model.

## Memoization

`scanWithModel` caches `sha1(text + allowlist) → redacted text`. Claude Code resends the whole conversation on every turn, so each old block costs one hash lookup and the tokens stay byte-identical, which keeps Anthropic prompt caching intact. The cache is cleared when it passes 50 000 entries.

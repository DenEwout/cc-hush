---
name: hush-logs
description: Review code for log statements that leak PII. Use when asked to check logging for personal data, review a diff or file for PII in logs, or before writing a log statement that references customer, user or person fields.
---

# hush-logs

Advisory review, no hook. Input: a diff, a file, or the statement about to be written.

## What counts as a finding

A logging or console call (`log.*`, `logger.*`, `console.*`, `print`, `System.out`, `slf4j`, `logging.*`, `Log.d`, `NLog`, `Serilog`) whose arguments:

1. Reference a field classified in `.hush/schema.json`, or matching the `hush-schema` name heuristic (email, naam, phone, adres, iban, rijksregister, password, token...). Includes getters: `customer.getEmail()`, `user.email`, `dto.phoneNumber`.
2. Pass a whole entity or DTO that has such a field. Implicit `toString()`, `JSON.stringify(user)`, `{}` formatting of an object, `%s` of a record.
3. Build an exception message or MDC/context value from those fields: `throw new IllegalStateException("No customer " + email)`, `MDC.put("user", user.getEmail())`.

Not a finding: surrogate ids, counts, statuses, timestamps, redacted or hashed values.

## Output

One line per finding:

```
file:line  leaked field  fix
src/Login.java:42  customer.getEmail()  log customer.getId() instead
src/Login.java:57  customer (toString has email)  exclude email from toString or log getId()
```

Fixes, in order of preference: log the surrogate id; mask (`e***@domain`); exclude the field from `toString`/serializer; drop the statement.

If `.hush/schema.json` exists, use its labels in the finding. Otherwise apply the name heuristic and say so.

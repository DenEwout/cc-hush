---
name: hush-query
description: Write ad-hoc SQL that stays PII-free under cc-hush. Use before running any SQL through Bash (psql, mysql, sqlite3, sqlplus) or an MCP database tool, and when the cc-hush guard asks about a PII column.
---

# hush-query

1. Read `.hush/schema.json` first. If absent, run `hush-schema` or ask the user which columns hold personal data.
2. Never `SELECT *` (or `t.*`) from a table listed in the schema. Name the columns you need and leave every classified column out.
3. Filter and join on surrogate keys (`id`, `customer_id`, `order_id`), never on email, name, phone, national number or IBAN. If the user gives you a name to look up, ask them for the id, or hand them the query to run.
4. Prefer aggregates: `COUNT`, `SUM`, `MIN`, `MAX`, `GROUP BY` on non-PII columns.
5. Always add `LIMIT` (or `FETCH FIRST`, `TOP`) to exploratory queries. Tool results over 32 KB are dropped by the proxy.
6. If a query cannot avoid a PII column (for example a data-quality check on `email` format), write it out and ask the user to run it and report the shape of the result, not the rows.
7. Mutations: `UPDATE` and `DELETE` always carry a `WHERE` on a key. Never `DROP` or `TRUNCATE`; propose a migration instead.

Example: instead of `select * from customer where email = 'x@y.be'` write `select id, status, created_at from customer where id = 4711`.

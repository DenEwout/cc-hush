---
name: hush-schema
description: Build or refresh .hush/schema.json, the PII column classification used by the cc-hush SQL guard. Use when the user asks to classify PII columns, set up or update the hush schema, or when the guard needs to know which columns hold personal data.
---

# hush-schema

Produces `.hush/schema.json`:

```json
{ "tables": { "customer": { "email": "private_email", "naam": "private_person" } } }
```

Labels: `account_number`, `private_address`, `private_email`, `private_person`, `private_phone`, `private_url`, `private_date`, `secret`, or `pii` as generic fallback.

## Steps

1. **Find schema sources in the repo.** Entities and ORM models (JPA `@Entity`, Prisma `schema.prisma`, TypeORM, SQLAlchemy, Django models), migrations (Flyway, Liquibase, Alembic, Rails, Prisma), raw DDL (`CREATE TABLE`, `COMMENT ON COLUMN`). Collect table name, column name, type, and any comment.
2. **Introspect live if a client is available.** Only names, types and comments. Never select a row.
   - PostgreSQL: `SELECT table_name, column_name, data_type, col_description(format('%I.%I', table_schema, table_name)::regclass, ordinal_position) FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog','information_schema');`
   - MySQL: `SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, COLUMN_COMMENT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE();`
   - Oracle: `SELECT TABLE_NAME, COLUMN_NAME, COMMENTS FROM ALL_COL_COMMENTS WHERE OWNER = USER;` joined with `ALL_TAB_COLUMNS`.
3. **Classify each column.**
   - A column comment containing `pii` wins over everything. `pii:<label>` gives that label (`pii:email` means `private_email`, `pii:person`, `pii:phone`, `pii:address`, `pii:account`, `pii:url`, `pii:date`, `pii:secret`). Bare `pii` gives `pii`.
   - Otherwise a name heuristic, English and Dutch, case-insensitive, on word parts:
     - `private_email`: email, mail, e_mail
     - `private_phone`: phone, tel, telefoon, gsm, mobile, mobiel, fax
     - `private_person`: name, naam, voornaam, achternaam, firstname, lastname, surname, fullname, contact
     - `private_address`: address, adres, straat, street, postcode, zip, gemeente, city, woonplaats, huisnummer
     - `private_date`: birth, geboortedatum, dob, birthday
     - `account_number`: iban, rekening, account_number, rijksregister, rrn, nationaal_nummer, bsn, ssn, btw, vat, kbo, ondernemingsnummer, card, kaartnummer
     - `secret`: password, wachtwoord, token, secret, api_key, credential, hash
     - Skip: `id`, `*_id`, `created_*`, `updated_*`, booleans, foreign keys, and columns whose name is a company or product field (`company_name` is not PII unless the comment says so).
4. **Merge** into the existing `.hush/schema.json`. Existing entries win. Only add new columns.
5. **Print the resulting table** (table, column, label, source: comment or heuristic) for review and write the file.

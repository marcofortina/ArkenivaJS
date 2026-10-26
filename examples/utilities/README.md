# Pure utility APIs

This example generates UUIDv4 and UUIDv7 identifiers through public framework
imports, parses their supported versions and verifies canonical-input policy.
It also normalizes email/IP input, rejects a literal private URL and validates
an object with a startup-compiled JSON Schema.
Calendar-day and elapsed-hour operations demonstrate the Rome DST transition.
CSV import/export preserves leading-zero identifiers and quoted text through
the native streaming parser and bounded native writer.
It requires no listener, database, credential or application bootstrap.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-utilities start
pnpm --filter @arkenivajs/example-utilities test
```

Expected output:

```json
{
  "v4Version": 4,
  "v7Version": 7,
  "malformedRejected": true,
  "canonicalPolicyEnforced": true,
  "emailNormalized": true,
  "ipNormalized": true,
  "privateUrlRejected": true,
  "schemaAccepted": true,
  "dstCalendarPreserved": true,
  "elapsedHoursPreserved": true,
  "csvTextPreserved": true,
  "csvRoundtripRows": 2
}
```

The packed-artifact verifier also installs and executes this example. See the
[identifier reference](../../packages/data-identifiers/README.md) and
[validation reference](../../packages/data-validation/README.md) for exact
contracts and the limits of UUID ordering, mailbox verification and URL/DNS policy.
The [time reference](../../packages/data-time/README.md) explains explicit DST
policies, locales and deployment ICU/TZDB requirements.
The [CSV reference](../../packages/data-csv/README.md) documents quoting, BOM,
schema, formula, backpressure and cancellation policies.

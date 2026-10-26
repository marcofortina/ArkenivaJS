# Pure utility APIs

This example generates UUIDv4 and UUIDv7 identifiers through public framework
imports, parses their supported versions and verifies canonical-input policy.
It also normalizes email/IP input, rejects a literal private URL and validates
an object with a startup-compiled JSON Schema.
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
  "schemaAccepted": true
}
```

The packed-artifact verifier also installs and executes this example. See the
[identifier reference](../../packages/data-identifiers/README.md) and
[validation reference](../../packages/data-validation/README.md) for exact
contracts and the limits of UUID ordering, mailbox verification and URL/DNS policy.

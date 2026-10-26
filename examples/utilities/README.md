# Pure utility APIs

This example generates UUIDv4 and UUIDv7 identifiers through public framework
imports, parses their supported versions and verifies canonical-input policy.
It requires no listener, database, credential or application bootstrap.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-utilities start
pnpm --filter @arkenivajs/example-utilities test
```

Expected output:

```json
{ "v4Version": 4, "v7Version": 7, "malformedRejected": true, "canonicalPolicyEnforced": true }
```

The packed-artifact verifier also installs and executes this example. See the
[identifier reference](../../packages/data-identifiers/README.md) for exact
contracts and the limits of UUID ordering and authorization.

# MongoDB customer consumer

An executable consumer of `@arkenivajs/database-mongodb` against an explicitly
disposable authenticated replica set. It creates a random collection, preserves
ObjectId/Decimal128/Long values, decodes the opaque inserted ID with canonical
EJSON, verifies modified counts 1/0 and runs an explicitly bounded pipeline.
Native Core session callbacks demonstrate commit and rollback without replay.
The collection and application are closed in `finally`; cleanup errors remain
visible. Run against the [private VM/CI fixture](../../packages/database-mongodb/test/fixtures/README.md).

```sh
pnpm build
pnpm --filter @arkenivajs/example-mongodb test
python3 packages/database-mongodb/test/fixtures/run.py /private/runtime/mongodb-fixture/environment.json pnpm --filter @arkenivajs/example-mongodb test:integration
python3 packages/database-mongodb/test/fixtures/run.py /private/runtime/mongodb-fixture/environment.json pnpm --filter @arkenivajs/example-mongodb start
```

The environment must contain `ARKENIVA_MONGODB_DISPOSABLE=1` and a verified
`ARKENIVA_MONGODB_URL`. The CLI prints an explicit JSON DTO: ObjectId becomes
hexadecimal text, Decimal128 and Long become exact decimal strings. The example
chooses this application representation; the provider does not silently
coerce BSON. Failure output uses safe framework errors without raw causes.

The fixed example tenant is trusted local input, not an HTTP identity example.
An HTTP handler must use `context.auth.tenantId` from verified JWT identity in
every lookup/mutation. A physical native collection name is explicitly composed
from the application's configured prefix; `native()` does not apply prefixes,
portable instrumentation or bounds. The official URI parser is used only to
read that application-owned prefix. Pass the actual session explicitly to each
native operation in a transaction and leave lifecycle ownership to the provider.
Unknown commit effects require reconciliation rather than callback replay.

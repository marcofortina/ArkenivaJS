# MySQL orders example

This independent consumer builds against the actual ESM packages. It creates one
uniquely named InnoDB table, commits an exact bigint/decimal order, rejects a real
duplicate key, verifies rollback and removes its table before closing the pool.
DDL runs outside business transactions because MySQL can commit it implicitly.
The example requires an explicitly disposable database and a restricted account.

Use the [private TLS fixtures](../../packages/database-mysql/test/fixtures/README.md)
inside a disposable VM or CI runner. After preparing `/tmp/arkeniva-mysql-private`
outside the checkout, start the fixtures and run from the workspace root:

```sh
pnpm install --frozen-lockfile
pnpm build
python3 packages/database-mysql/test/fixtures/run.py /tmp/arkeniva-mysql-private/environment.json pnpm --filter @arkenivajs/example-mysql start
python3 packages/database-mysql/test/fixtures/run.py /tmp/arkeniva-mysql-private/environment.json pnpm --filter @arkenivajs/example-mysql test:integration
```

When the consumer runs outside the guest, use equivalent private environment
variables pointing to the forwarded **DNS** endpoint and a host-readable CA file.
Do not copy a guest-only CA path unchanged into the host URL. The fixture runner
requires a private environment file and never prints its credentials.

Successful output contains only the demonstration result:

```json
{
  "rows": [{ "id": "9007199254740993", "total": "5.25" }],
  "duplicateRejected": true,
  "rollbackVerified": true
}
```

`ARKENIVA_MYSQL_URL` must contain a `mysql://` URL with explicit user and database,
`ssl=verify-full` and the private CA where needed. Set
`ARKENIVA_MYSQL_DISPOSABLE=1` only for a disposable test server. Missing settings
fail before resources are created. For an application schema, use your own managed
DDL and connection environment variable; retain the named binds and transaction
callback pattern shown in [the source](src/main.ts).

See the [adapter reference](../../packages/database-mysql/README.md) for conversion,
timeouts, row bounds, TLS identity limits, native access and uncertain commits.

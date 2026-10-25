# Exact Oracle NUMBER consumer

**Oracle adapter contract-tested with mocks; live compatibility not verified**.

This consumer keeps `9007199254740993` exact from a named bigint bind to an Oracle
NUMBER column and a string JSON DTO. It uses Thin mode, a startup readiness query,
one SELECT from DUAL and guaranteed application cleanup. It creates no tables and
does not assert tested server compatibility.

From the workspace root, use the pinned toolchain:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-oracle test
```

The ordinary tests run without Oracle Client or a server. They verify SQL/binds,
exact output, invalid conversion rejection, live opt-in and safe CLI errors.

To opt into a real instance for which you are authorized, set
`ARKENIVA_ORACLE_URL` securely outside Git and `ARKENIVA_ORACLE_LIVE=1`, then run:

```sh
pnpm --filter @arkenivajs/example-oracle start
```

The connection variable has the form
`oracle://user:password@hostname:2484/service?ssl=verify-full`, with percent-encoded
credentials. The [adapter reference](../../packages/database-oracle/README.md)
explains trust/wallet setup and isolated local development exceptions. Expected
JSON is `{"exact":"9007199254740993"}`. Missing opt-in/configuration prints a safe
error code and exits nonzero; no SQL, URL, credentials or stack are printed.

The separate `pnpm test:integration:oracle` suite writes only to an explicitly
authorized disposable schema and verifies transactions, LOB streaming and native
OUT/INOUT binds. It requires different disposable authorization; this read-only
consumer's live opt-in does not authorize that suite. Record exact versions and
evidence before advertising live compatibility. See the adapter reference for
limitations, conversion policies and native ownership.

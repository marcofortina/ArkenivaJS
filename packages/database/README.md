# @arkenivajs/database

Portable SQL contracts and a dialect-aware named binding compiler. This package
does not import a native database client or create a connection pool.

```ts
import { compileSql } from '@arkenivajs/database';

const statement = compileSql(
  { text: 'SELECT :id::bigint, :id', bindings: { id: 9007199254740993n } },
  'postgres',
);
// statement.text is 'SELECT $1::bigint, $1'; parameters contain one bigint.
```

The finite-state scanner keeps quoted tokens and comments opaque. PostgreSQL
supports nested block comments, case-sensitive dollar tags, casts, escape strings
and newline-separated string continuations. MySQL and MariaDB support backticks,
hash comments and the required whitespace boundary for dash comments. Oracle
supports ordinary and alternative quotes, including national and multibyte forms.
Missing, extra or invalid binding keys fail with `EK_CONFIG_INVALID` before pool
acquisition. Legal names such as `constructor` remain safe own properties.

PostgreSQL reuses one positional parameter for repeated names. MySQL and MariaDB
append a parameter for each occurrence. Oracle retains named parameters in a
record with no prototype. Values never enter the SQL text. Date and binary values
are copied synchronously; immutable result containers retain native value types.
Applications must treat returned Date and binary snapshots as read-only.
Non-finite numbers and unsafe integer numbers reject; use bigint for large integers.
Arrays, object values, OUT binds, LOBs and streaming use the owning driver's native API.

Session lexical settings are explicit: `standardConformingStrings` for PostgreSQL,
and `noBackslashEscapes` / `ansiQuotes` for MySQL and MariaDB. Adapters must compile
with the connection's actual settings. Mixing native positional parameters with
portable binds rejects. Version-dependent executable comments also reject with a
clear framework error; their contents are never silently treated as inert comments.
The native API remains available for such dialect-specific statements.

Limits are 1 MiB of UTF-8 statement text, 65,535 placeholder occurrences and named
values, and 16 MiB of captured binding data including names. MySQL and MariaDB also
apply the byte limit after expanding repeated parameters. A fingerprint hashes
the dialect and source text, excludes supplied values, and never exposes SQL text
in a default diagnostic. Compilation validates binding grammar, not SQL syntax or
the authorization of a table name. Identifiers require an application allowlist.

Lexical behavior follows the official
[PostgreSQL lexical structure](https://www.postgresql.org/docs/current/sql-syntax-lexical.html),
[MySQL identifiers](https://dev.mysql.com/doc/refman/8.4/en/identifiers.html),
[MySQL comments](https://dev.mysql.com/doc/refman/8.4/en/comments.html),
[MariaDB comments](https://mariadb.com/docs/server/reference/sql-statements/comment-syntax),
and [Oracle text literals](https://docs.oracle.com/en/database/oracle/oracle-database/26/sqlrf/Literals.html).

Tests include a common dialect corpus, hostile value capture, explicit lexical
modes, malformed input, resource limits, and three reproducible property suites
with 1,000 cases each plus 2,000 arbitrary UTF-16 fuzz cases across all dialects.
These are compiler tests; live database conformance belongs
to each native adapter's integration suite.

## Adapter composition

The `@arkenivajs/database/support` entry provides the common SQL coordinator for
adapter authors. Each native SQL plugin declares `sqlSupportPlugin` under the
core composition symbol `SUPPORT_PLUGINS` and explicitly depends on
`SQL_SUPPORT_ID`. The application resolves that same pure factory once, so several
drivers and named pools share one `app.sql` without an extra application plugin.
The coordinator prepares the facade without opening connections, then publishes
`SQL_DRIVER_REGISTRY` during initialization. Drivers register only names whose
root database definition matches their relational driver identity.

The coordinator verifies all relational names at activation, rejects duplicate or
late registration and captures adapter methods once. Each driver retains pool
ownership and closes its resources before the coordinator clears its registry.
Prepared facades reject calls before activation; retained facades reject after
shutdown. Applications remain independent even when the same native plugin
definition is reused. Diagnostic ports are optional abstract dependencies captured
from the application's explicit logger, telemetry and meter providers.

Transaction callbacks receive immutable handles bound to their active asynchronous
context. Nested provider transactions and pool reentry from a transaction reject
with `EK_DATABASE_TRANSACTION`; use the callback's handle for its statements.
Handles cannot be borrowed by another request or retained after callback completion.
The coordinator never retries a callback and rejects a driver's attempted replay.
Native adapters implement connection pinning, begin/commit/rollback, query
cancellation, bounded cursor fetches and exactly-once release. A coordinator unit
test with a fake adapter establishes routing and context ownership; only a real
adapter integration test establishes database transaction behavior.

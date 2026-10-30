<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native MariaDB prepared-query comparison

Build the workspace and load the private environment for the
[owned MariaDB TLS fixture](../../packages/database-mariadb/test/fixtures/README.md):

```sh
python3 packages/database-mariadb/test/fixtures/run.py /private/mariadb-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation mariadb-query --verify /private/mariadb-verification
```

Four isolated profiles compare pinned `mariadb` with the actual SQL service and
standard/detailed SDK instrumentation against MariaDB 12.3.3. Real prepared results
preserve repeated Unicode/text binds and a signed bigint beyond JavaScript's safe
integer range. MariaDB returns an actual `bigint`; the tool preserves that native
behavior independently of MySQL's text policy. SQL punctuation remains bound data.

The native baseline uses the fixed positional statement for this exact corpus,
verified TLS with explicit hostname checks, a two-connection pool, session reset,
UTF8/UTC/sql_mode setup, session readback, prepared result streaming and statement
close. It omits framework capture, compilation/fingerprinting, admission,
cancellation and lifecycle policy. Public native pool counters verify zero active
checkouts and queued tasks, with all retained connections idle after completion.

`--verify` records functional evidence without samples. `--smoke` measures at least
100 actual query completions after 20 warmups per profile, with concurrency one.
Reports and SDK exports exclude binding values, credentials and connection paths.
Healthy controls precede wrong-hostname certificate rejection tests for native
and framework startup.

Reports retain `releaseGate: false`. This read-only SELECT corpus does not prove
transaction behavior, write outcomes, cross-driver normalization, database-server
CPU, dedicated-runner budgets, five paired repetitions or one-hour soak acceptance.

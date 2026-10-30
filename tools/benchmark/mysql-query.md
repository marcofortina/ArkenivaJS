<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native MySQL prepared-query comparison

Build the workspace and load the private environment for the
[owned MySQL TLS fixture](../../packages/database-mysql/test/fixtures/README.md):

```sh
python3 packages/database-mysql/test/fixtures/run.py /private/mysql-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation mysql-query --verify /private/mysql-verification
```

Four isolated profiles compare pinned `mysql2` with the actual SQL service and
standard/detailed SDK instrumentation against MySQL 9.7.4. Actual prepared results
preserve a repeated Unicode/text bind and a signed bigint above JavaScript's safe
integer range. The driver's explicit bigint policy returns exact text. SQL
punctuation remains bound data; no native parser is reimplemented.

The native baseline uses the fixed positional statement for this exact corpus,
verified TLS/hostname policy, a two-connection pool, explicit session reset,
UTF8/UTC/sql_mode setup, session readback and streamed prepared results. It omits
framework immutable capture, compilation/fingerprinting, admission, cancellation
and lifecycle policy. Both paths verify that tracked checkouts and pending
acquisitions are drained with no observer/cleanup failures. `mysql2` has no stable
public total/idle/queue counters; unavailable values are not invented.

`--verify` records functional evidence without samples. `--smoke` measures at
least 100 actual query completions after 20 warmups per profile, with concurrency
one. Reports and SDK exports exclude binding values, credentials and connection
paths. Healthy controls precede wrong-hostname certificate rejection tests for
both native and framework startup.

Reports retain `releaseGate: false`. This read-only SELECT corpus does not prove
transaction behavior, write outcomes, cross-driver normalization, database-server
CPU, dedicated-runner budgets, five paired repetitions or one-hour soak acceptance.

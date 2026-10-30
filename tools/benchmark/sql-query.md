<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Actual PostgreSQL query comparison

Build the workspace, load the owned disposable TLS fixture environment and choose
a fresh absolute external report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation sql-query --verify /private/sql-query-verification
```

Four isolated profiles compare native `pg`/`pg-cursor` with the actual public SQL
service, including standard and detailed telemetry. Real PostgreSQL 17 or 18
returns integer/text rows, repeated bound values and a bigint above the safe
JavaScript integer range. Quotes and SQL punctuation remain bound text. Native
pool inspection verifies that every checkout has been released. Actual SDK exports
and reports must exclude connection details and binding values.

The native baseline uses fixed positional statements corresponding to this exact
read-only named-bind corpus. It resets sessions, enforces UTF8 and verified TLS,
and reads at most two rows through a cursor before closing it. It does not replace
the framework bind compiler with text substitution. Framework capture, admission,
fingerprinting, cancellation and lifecycle policy remain additional work.

`--verify` records functional checks without samples. `--smoke` measures at least
100 actual query completions per profile after 20 warmups, with concurrency one
and a pool capped at two connections. Child CPU and sampled memory include the
measurement machinery; database-server CPU is not measured.

Both modes retain `releaseGate: false`. This small SELECT corpus does not establish
transaction correctness, write outcomes, all-driver equivalence, dedicated-runner
performance budgets, five paired repetitions or one-hour soak acceptance.

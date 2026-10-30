<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native MongoDB BSON and transaction verification

Build the workspace and load the private environment for the
[owned MongoDB TLS/SCRAM replica sets](../../packages/database-mongodb/test/fixtures/README.md):

```sh
python3 packages/database-mongodb/test/fixtures/run.py /private/mongodb-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation mongodb --verify /private/mongodb-verification
```

Four isolated profiles compare the same pinned native MongoDB driver with the
public document service and actual standard/detailed SDK instrumentation. The
valid corpus checks all seven document operations: reads, insertion, exact
modification/deletion counts, unchanged aggregation and native transactions.
Long, Decimal128, Binary, Date and Int32 values retain their native BSON types;
custom string IDs use the driver's actual lossless EJSON representation.

Both paths capture CA material before constructing verified-TLS/SCRAM clients,
use the same pool bounds and disable automatic read/write retries. Read cursors
use matching non-promoted BSON options and close explicitly. The caller supplies
an explicit aggregation result limit; the wrapper never inserts one silently.
Transaction callbacks execute once. A separate native observer verifies actual
commit and rollback effects and confirms native session retirement. This does
not claim exactly-once business effects or safe replay of unknown outcomes.

Random collection names are checked absent before ownership is claimed. Workers
remove only that exact collection, and an independent parent verifies absence
after all profiles. Parent cleanup also covers a failed worker. Healthy native
and public controls precede wrong-hostname certificate rejection tests. Actual
SDK exports and reports exclude documents, namespaces and connection credentials.
A collection prefix is not tenant authorization.

The native baseline omits framework complete hostile-input capture, command/frame
admission, response bounds, unknown-outcome classification, cancellation and
lifecycle policy. The owned fixture has one-member replica sets; multi-member
discovery/failover is a separate workload.

Only `--verify` is supported. Sampling is rejected before fixture access until
complete client/server resource accounting is available. Reports retain
`releaseGate: false`; dedicated-runner budgets, five paired repetitions and
one-hour soak acceptance remain separate work.

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

`--verify` preserves that verification without measured samples.

## Explicit bounded read smoke

Run only in the owned QEMU VM or an explicitly disposable CI runner:

```sh
ARKENIVA_MONGODB_BENCHMARK_DISPOSABLE=1 \
python3 packages/database-mongodb/test/fixtures/run.py /private/mongodb-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation mongodb --smoke /private/mongodb-smoke
```

Both the existing owned-fixture guard and the separate benchmark opt-in are
required. Unsupported `--full` and unmarked smoke fail before fixture access or
evidence creation. Each of four isolated profiles executes 20 warmup callbacks
and 100 measured callbacks of one real `findOne` scenario. Actual Tinybench raw
latency samples retain only the measured iterations. Every callback verifies the
complete known document with native BSON Int32/Long/Decimal128/Binary/Date types
and exact canonical EJSON. The latency includes consumer type/EJSON validation
and BSON byte-size calculation; it is not just the unobserved server query time.

The original CRUD/BSON/aggregation/commit/abort verification remains a separate
prelude in every profile. A different random owned collection is then seeded
outside the timed callback, using a separate native client. Independent native
`countDocuments` and exact readback must observe one document before and after
sampling. Only that exact seed collection is dropped; an independent parent
also verifies absence of both declared collection names. Failed workers remain
covered by exact parent cleanup. No unrelated collection or database is dropped.

Passive event listeners on the actual pinned `MongoClient` count matching
`find` command starts/successes/failures and unexpected `getMore`, retaining at
most one private outstanding request ID. They never retain command documents,
credentials, IDs or namespace names in reports or telemetry. Every actual
callback must correspond to one successful observed find, with zero failed or
outstanding commands and no getMore. Read/write retries remain disabled. BSON
result byte counts describe the decoded document only; `wireBytes` stays null.
Listeners are removed before final independent readback. No transaction/write
timing or exactly-once business claim is made.

All profiles require complete supervised client process-tree resource discovery,
physical child waits and zero remaining owned processes, under the unchanged
30-second whole-profile bound. Lifecycle CPU/RSS includes worker/bridge and its
own native setup/readback clients, including verification, warmup, sampling,
exports and cleanup. The narrower ordinary worker resource window excludes the
earlier seed and later readback. The Python observer, parent native observer and
collector, and external mongod/server processes are excluded. Sampled RSS sums
may repeat shared pages and miss short peaks; this is not exact peak RAM or a
whole-pipeline/server resource budget. TLS CA material is captured explicitly
from the owned file by both adapters; no ambient trust override is introduced.
STANDARD and DETAILED both force diagnostic trace sampling to one.

This valid-corpus read component smoke sets `measured: true` and
`releaseGate: false`. Full hostile-input policy equivalence, multi-member
failover, calibrated latency/throughput/memory budgets, five paired repetitions
and one-hour soak acceptance remain separate work.

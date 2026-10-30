<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native Redis portable-operation comparison

Build the workspace and use the private environment runner for the
[owned Redis fixture](../../packages/database-redis/test/fixtures/README.md):

```sh
python3 packages/database-redis/test/fixtures/run.py /private/redis-environment.json \
  pnpm --filter @arkenivajs/benchmark-foundation redis --verify /private/redis-verification
```

Four isolated processes compare native `redis` with the public provider and
actual standard/detailed SDK profiles over verified authenticated TLS. They
check exact UTF-8 including a leading BOM, both NX outcomes, native TTL/expiry,
counter state and actual deletion counts. A separately connected native
subscriber must observe the published message; the returned subscriber count
must be one. This is ephemeral Pub/Sub, not durable processing acknowledgement.

Every invocation owns a random namespace. Shutdown deletes only its four exact
keys and closes the controlled subscriber. An independent final client uses
permitted native GET commands to prove absence before reporting zero remaining
keys. The application ACL is never widened for the comparison. Reports and
exports exclude values, keys/channels, credentials, CA paths and endpoints.

`--verify` emits no latency/resource samples. `--smoke` exercises 20 warmup and at
least 100 completed sequential set/get/increment/delete sequences per profile.
Each recorded roundtrip is four portable operations, not four separately timed
samples. An independent native read verifies the counter against the actual
acknowledged invocation count, including warmup. Control reads and Pub/Sub setup
remain outside sampling. Whole child CPU and sampled memory describe the client
process; Redis server CPU is not measured.

The valid-corpus baseline uses small UTF-8 values and safe integer operands.
It does not duplicate the wrapper's Lua byte/UTF-8/integer guards, admission,
cancellation or lifecycle policy. Both modes retain `releaseGate: false`.
Dedicated-runner budgets, five paired repetitions and a one-hour soak remain
separate acceptance work. The Redis CI job also tests wrong-SAN rejection in
the native path and through the framework comparison.

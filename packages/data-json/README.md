<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Bounded native JSON and declarative mappings

This private package defines the general JSON workflow contracts. Its internal
codec uses Node's JSON parser/writer and immutable bounded snapshots. Its schema
catalog uses Ajv 8.20.0 in Draft 2020-12 mode with ajv-formats 3.0.1. It shares
the reviewed dependency versions with the framework's existing validation stack;
Fastify request and response compilation remains independent.

`dataJsonPlugin(settings)` explicitly registers `JSON_CAPABILITY`. The frozen
`JsonService` exposes synchronous `parse`, `stringify`, `validate` and `transform`
methods. The [compiled public example](../../examples/json/README.md) exercises
the complete workflow through real workers and independently installed archives.

`JsonMappingRegistry.ids` is a finite immutable deployment manifest. It permits
complete mapping validation before readiness, while `get()` retrieves each
declared mapping. Duplicate IDs and ID/body mismatches must fail initialization.
An unenumerated dynamic registry cannot satisfy startup-only approval.

The native codec preserves JSON strings, finite IEEE-754 numbers, booleans and
null. It rejects unsafe integer values, invalid Unicode, dangerous property
names, cycles, accessors, proxies, exotic objects and non-JSON values. Objects
have null prototypes and immutable owned descendants. Standard JSON duplicate
member parsing follows Node's last-member behavior; deployment catalogs are
supplied as already constructed records, not unverified text. Pretty-printing
is explicit and its complete UTF-8 output remains bounded.

Schema catalogs contain at most 128 opaque IDs and 1 MiB of JSON metadata.
Schemas are trusted deployment assets, snapshotted before native compilation.
Only exact preregistered schema IDs and local JSON Pointer references resolve;
remote loading, asynchronous validation and recursive dependencies are forbidden.
Nested resource IDs, anchors and dynamic references are unsupported. Data is
never coerced, defaulted or stripped. Native errors expose only stable instance
paths and fixed English messages, without rejected values or schema internals.

The packaged exact-version compatibility diff preserves the native equality
backend while requiring method-like properties to be callable before invocation.
JSON `valueOf` and `toString` fields remain ordinary data, including in `const`
and `enum`. A native startup probe rejects an uncorrected equality backend.
The package carries the upstream MIT notice alongside its own license.

## Deployment catalogs and mapping semantics

Only the registered `JsonMappingV1` operators are accepted: `copy`, `literal`,
`coalesce`, `concat`, `to-string`, `to-number`, `to-boolean` and `array-map`.
The complete versioned document is validated by a fixed native Ajv grammar.
Unknown fields/operators, malformed RFC 6901 pointers, duplicate IDs, dangerous
keys, missing schema IDs and statically incompatible output fields fail startup.
Each mapping is compiled into bounded interpreter closures, without evaluating
JavaScript expressions. The registry provider is never called during a request.

An optional missing copy omits its output property. Existing null remains null.
Coalesce selects the first existing non-null result and propagates errors.
Concat requires strings; scalar conversions never coerce arrays, objects or null.
Numbers accept JSON decimal grammar only, rejecting unsafe integers, overflow
and nonzero underflow. Booleans accept booleans or exactly `true` and `false`.
Array mapping uses item-relative pointers, preserves order and rejects missing
item results. Output properties follow declaration order and use safe prototypes.

Mapping limits are cumulative: at most 16 expression/output levels, 2048 compiled
and evaluated expression nodes, 100000 expanded array items and 8 MiB output.
Each deployment chooses positive values within those bounds. Native input and
output schemas remain authoritative for every call, including constraints that
cannot be decided from static operator types. Errors never return partial data.

## Runtime limits and lifecycle

Required `policy` has positive `maxConcurrent` (at most four workers) and
`timeoutMs` (at most 30000). Omitted byte limits use `defaults.maxBytes`, which
defaults to 1 MiB; input/output ceilings are at most 8 MiB each. Document depth
defaults to 64, with a maximum of 128. Each snapshot admits at most 100000 JSON
nodes. Pretty indentation accepts integers 0..10. Call options may narrow the
captured document bounds. Unknown fields, null and invalid deadlines fail closed.

Native schemas and mapping interpreters are compiled before readiness in a
finite application-owned worker pool. Workers have 96/16 MiB old/young V8 heap
limits, a 4 MiB stack and no inherited application environment or preloads.
Configured input/output admission totals cannot exceed 64 MiB; these byte budgets
do not claim exact V8 heap, structured-clone or IPC memory accounting.

The public API is synchronous: it blocks its calling JavaScript thread until a
bounded native result or deadline. It uses a fixed shared output mailbox per
worker; there is no waiting-job queue. Even non-cooperative native regex/schema
work is terminated on deadline. A failed/timed-out worker is retired, with no
automatic request replay or unbounded respawn; restart the application to restore
retired capacity. Shutdown terminates and awaits every owned thread and clears
its output memory. Calls after shutdown fail `EK_RESOURCE_CLOSED`.

Logging records fixed operation/outcome fields and approved mapping ID/version
on transformation events. Metric labels remain fixed operation/outcome sets;
payloads, invalid caller IDs and schema details are excluded. Measurements cover
durations, actual UTF-8 byte counts, worker heap samples and aggregate Node RSS.
Heap samples are not memory high-water measurements. Comparative performance
and peak profiling are separate validation campaigns.

## Verification

Run native tests after building:

```sh
pnpm --filter @arkenivajs/data-json build
pnpm --filter @arkenivajs/data-json test:unit
pnpm --filter @arkenivajs/data-json test
pnpm test:packed:examples --example json
```

Tests cover actual Draft 2020-12 decisions, offline references, malicious data,
every mapping operator, cumulative limits, deployment immutability, native
deadline interruption, worker failure/cleanup and private standard/detailed SDK
exports. No database or external service is needed.

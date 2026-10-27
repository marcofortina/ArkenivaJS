<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# JSON data contracts and native foundations

This private package defines the general JSON workflow contracts. Its internal
codec uses Node's JSON parser/writer and immutable bounded snapshots. Its schema
catalog uses Ajv 8.20.0 in Draft 2020-12 mode with ajv-formats 3.0.1. It shares
the reviewed dependency versions with the framework's existing validation stack;
Fastify request and response compilation remains independent.

The application plugin and mapping runtime are not available in this revision.
Public exports currently contain types only.

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

Run the native foundation tests after building:

```sh
pnpm --filter @arkenivajs/data-json build
pnpm --filter @arkenivajs/data-json test:unit
```

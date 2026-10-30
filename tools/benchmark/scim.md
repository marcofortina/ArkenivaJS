<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native SCIM schema and durable provider verification

Build the complete workspace and load the owned disposable verified-TLS
PostgreSQL fixture environment:

```sh
pnpm --filter @arkenivajs/benchmark-foundation scim --verify /private/scim-verification
pnpm --filter @arkenivajs/benchmark-foundation scim --smoke /private/scim-smoke
```

Four isolated profiles compare native SCIMMY schema/filter/PATCH handling with
the public SCIM service, including actual standard/detailed SDK instrumentation.
Both paths use the same existing application PostgreSQL provider. An independent
parent verifies actual signed identities and passes its own authenticated tenant
context into each provider operation. Workers receive four distinct tenant
grants, never SQL credentials or a trusted context serialized from the parent.

Every profile creates a user, retries creation concurrently without duplicating
the resource, reads an exact filtered page and applies a Unicode PATCH. Two
updates using the same ETag produce one successful update and one precondition
failure. Readback confirms the winner, then deletion removes the user from both
individual reads and lists. Independent SQL readback verifies four distinct
owner namespaces, four tombstones and version four for every resource.

Separate negative tests reject forged application tenant objects and missing or
invalid bearer credentials before provider dispatch. A known foreign resource
identifier cannot be read from another tenant. A provider outage returns a
sanitized failure and recovery preserves the previous resource and version.
Production configuration rejects the explicit test-only provider/authority ports.

The native path is a valid-request reference at the service boundary, not a
complete SCIM server. It shares application provider/authentication infrastructure
and omits the public service's full hostile-input, context provenance,
authorization, cancellation and uncertain-outcome policy. This fixed User corpus
does not establish Group, complete HTTP server or production federation parity.
Existing module integration suites cover the broader public SCIM contract.

The bounded bearer-authenticated loopback bridge authorizes each provider call
from a verified JWT. Reports and actual SDK exports must exclude tokens, private
resource values, tenant identifiers and SQL schema names. Shutdown settles parent
provider work, closes the issuer/bridge and removes only the owned SQL schema.

`--verify` preserves the existing CRUD, pagination, idempotency and ETag-race
corpus without latency sampling. `--smoke` prepares one additional User per
tenant after that verification and outside timing. Its username and external ID
are distinct from the original deleted resource because the actual provider's
immutable unique mappings include tombstones. The seed is committed at version
one with ETag `"1"`.

The sole timed scenario is `GET /Users/{id}` at the authenticated service
boundary: 20 warmup callbacks and exactly 100 retained Tinybench samples per
profile. Every sequential callback awaits the actual signed-identity checks,
provider bridge, PostgreSQL transaction and SCIMMY User representation. There is
no harness retry or waiting queue. At most 120 response objects are captured
privately, within an explicit retention ceiling of 128, and released after
completion. Every returned body and ETag must equal the original seed. Failed
responses, changed bodies or changed versions reject the entire campaign.

The parent independently counts exactly 120 seed-specific provider reads per
tenant (480 overall), excluding the existing verification reads. SQL readback
then proves four original version-four tombstones and four additional live
version-one resources, with exact immutable bodies and independently derived
issuer/subject/tenant ownership hashes. The owned schema is dropped in cleanup;
seed creation and schema cleanup are not measured CRUD operations. Parent work
settles before its auth service, issuer and SQL application close.

The measured service boundary excludes real HTTP ingress, initial seed setup,
CRUD verification and independent SQL readback. Worker resource observations
exclude the separate parent provider, issuer, SQL client and PostgreSQL server;
those resource costs remain unknown (`null`). This is a bounded read scenario,
not CRUD performance, a complete SCIM HTTP benchmark or end-to-end federation
equivalence. Reports retain `releaseGate: false`; complete resource accounting,
dedicated-runner budgets, five paired repetitions and one-hour soak acceptance
remain separate work. Unsupported modes reject before fixture allocation.

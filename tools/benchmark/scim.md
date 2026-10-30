<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native SCIM schema and durable provider verification

Build the complete workspace and load the owned disposable verified-TLS
PostgreSQL fixture environment:

```sh
pnpm --filter @arkenivajs/benchmark-foundation scim --verify /private/scim-verification
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

Only `--verify` is supported. Sampling is rejected before fixture allocation
until complete provider/server resource accounting is available. Reports retain
`releaseGate: false`; dedicated-runner budgets, five paired repetitions and
one-hour soak acceptance remain separate work.

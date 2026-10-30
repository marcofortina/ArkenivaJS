# Native HTTPS GraphQL verification

```sh
pnpm --filter @arkenivajs/benchmark-foundation graphql --verify /absolute/private/new-directory
```

The directory must be fresh and outside the source tree. Run a current workspace
build first. The controller owns an actual synthetic signing authority and private
HTTPS certificate; all requests verify that certificate. No external issuer,
database, container or host trust change is required. Four independent processes
use the locked Fastify, Mercurius, GraphQL and JOSE versions.

The native reference and framework profiles perform twelve actual requests each:
anonymous, tampered and foreign-tenant credentials fail before mutations; an
alias/fragment/variable query returns its own row while denying the private getter;
a known foreign row remains absent. Read-only credentials cannot mutate. Retrying
one application idempotency key changes the counter once, and another verified
tenant has its own receipt and counter. Invalid syntax cannot change business
state. The controller independently observes four real JWKS fetches.

`FRAMEWORK` retains all GraphQL guards. `STANDARD` and `DETAILED` additionally
enable actual telemetry and JSONL technical metering. Each GraphQL usage child
must point to its actual HTTP parent and verified tenant, without HTTP byte
counters repeated on the child. SDK exports are checked for private fixture
inputs. Temporary JSONL files, TLS material, issuers and listeners are closed
and removed after every profile, including failures.

This is a functional verification corpus. Reports set `measured:false`,
`releaseGate:false` and provide no latency, CPU or throughput claims. The native
reference retains explicit signature/scope/field/row checks but does not implement
all framework provenance, complexity, admission, cancellation and output guards.
It therefore cannot establish a policy-equivalent overhead result. Business
counters and idempotency receipts remain bounded process memory. Shared storage,
SQL-loader and subscription comparisons, sustained concurrency, complete resource
accounting, repeated measurements and the long soak remain separate acceptance
work.

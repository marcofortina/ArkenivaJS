# @arkenivajs/graphql

Optional GraphQL query and mutation integration on the existing Fastify HTTP or HTTPS listener. Register `graphqlPlugin({ schema, resolvers, security })` at application construction, alongside the API adapter. `GRAPHQL_CAPABILITY` resolves an administrative service exposing only `stats()`, `health()` and `schemaSdl()`.

The implementation uses Mercurius 16.12.1 and GraphQL 16.14.2 over Fastify 5.12.7. Core and REST-only applications do not import this package. The plugin requires explicit application HTTP configuration and, by default, an authentication provider. SDL, field mappings and startup declarations are validated before listener activation. It never creates another listener.

Anonymous policy requires an explicit list of public `Query.<field>` roots and a reason. Every resolved field needs an application authorization decision; a tenant argument is never authentication evidence. Batch results retain order, length and null entries. Subscription delivery requires verified tenant provenance and a shared production backend, with bounded transport and periodic revalidation.

POST accepts one JSON operation. GET queries require explicit opt-in; mutations through GET are rejected. Documents, variables, depth, expanded aliases, list complexity, resolved fields, returned collections, elapsed time and encoded results have finite limits. Field policy must return exactly `true` before explicit resolution or default property access. Application services still own row-level authorization and tenant filtering.

Cookie-bearing and cross-site browser requests are rejected. No cookie authentication is enabled. A declared anonymous operation never accepts a forged bearer assertion as a public fallback. Error responses omit exception causes, documents, variables and backend diagnostics. Timeout never implies rollback: an admitted mutation may still commit, and the adapter retains ownership until its underlying work settles. There are at most 128 physically outstanding operations per instance; new admissions are rejected while that capacity is occupied.

Loaders use Mercurius's native scheduler. Each batch contains at most `maxBatchSize` requests, default 100 and maximum 1000. The ordered result must be an array with exactly the same length, including null entries. Per-item failures become sanitized field errors. Parent objects remain opaque to cache-key construction, so private getters are not evaluated as a side effect of batching.

Result caches exist only inside one authenticated request and use parent identity and coerced arguments. Authorization still precedes every lookup, including a cache hit. `cache: false` preserves distinct alias requests. Caches are invalidated between serial mutation root fields. Application loaders must apply the verified tenant and row-level policy to their database reads; batching does not authorize records.

Schema introspection is disabled by default. `introspection: 'authenticated'` requires a trusted authentication provider and an explicit `introspectionScope`; every introspection request must prove that scope. Metadata fields, including `__typename`, also pass ordinary field authorization with their actual parent and response path. Large administrative introspection queries remain subject to the configured budgets; enabling introspection never relaxes limits automatically.

The upstream GraphQL package shares its built-in metadata definitions across schemas. Their resolver guards dispatch only through an internal map of owned request contexts, preserving unrelated native schemas. Separate framework applications retain separate identity and field policies. Replacing an installed guard causes owned requests to fail closed before executing fields.

This package remains under development. Subscriptions, developer IDE, GraphQL-specific telemetry, HTTP/2 acceptance and complete release evidence are pending. Their configuration is rejected at startup until implemented and verified. Do not treat this intermediate query/mutation transport as a completed GraphQL release.

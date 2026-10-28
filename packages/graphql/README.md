# @arkenivajs/graphql

Optional GraphQL query and mutation integration on the existing Fastify HTTP or HTTPS listener. Register `graphqlPlugin({ schema, resolvers, security })` at application construction, alongside the API adapter. `GRAPHQL_CAPABILITY` resolves an administrative service exposing only `stats()`, `health()` and `schemaSdl()`.

The implementation uses Mercurius 16.12.1 and GraphQL 16.14.2 over Fastify 5.12.7. Core and REST-only applications do not import this package. The plugin requires explicit application HTTP configuration and, by default, an authentication provider. SDL, field mappings and startup declarations are validated before listener activation. It never creates another listener.

Anonymous policy requires an explicit list of public `Query.<field>` roots and a reason. Every resolved field needs an application authorization decision; a tenant argument is never authentication evidence. Batch results retain order, length and null entries. Subscription delivery requires verified tenant provenance and a shared production backend, with bounded transport and periodic revalidation.

POST accepts one JSON operation. GET queries require explicit opt-in; mutations through GET are rejected. Documents, variables, depth, expanded aliases, list complexity, resolved fields, returned collections, elapsed time and encoded results have finite limits. Field policy must return exactly `true` before explicit resolution or default property access. Application services still own row-level authorization and tenant filtering.

Cookie-bearing and cross-site browser requests are rejected. No cookie authentication is enabled. A declared anonymous operation never accepts a forged bearer assertion as a public fallback. Error responses omit exception causes, documents, variables and backend diagnostics. Timeout never implies rollback: an admitted mutation may still commit, and the adapter retains ownership until its underlying work settles. There are at most 128 physically outstanding operations per instance; new admissions are rejected while that capacity is occupied.

This package remains under development. Loader execution, subscriptions, authenticated introspection, developer IDE, GraphQL-specific telemetry, HTTP/2 acceptance and complete release evidence are pending. Their configuration is rejected at startup until implemented and verified. Meta fields are currently denied. Do not treat this intermediate query/mutation transport as a completed GraphQL release.

# Changelog

## 0.1.0

- Add optional GraphQL contracts and administrative capability identity.
- Pin the selected Mercurius and GraphQL engines without changing REST-only dependencies.
- Validate immutable startup declarations, finite budgets and schema field mappings before transport registration.
- Bind guarded queries and mutations to the existing listener, with verified identities, field authorization, finite execution limits and safe errors.
- Add bounded native request loaders, opaque parent correlation, isolated caches and serial mutation invalidation, verified against actual PostgreSQL query counts.
- Protect upstream metadata fields with per-request field policy and explicitly scoped administrative introspection while preserving unrelated native schemas.

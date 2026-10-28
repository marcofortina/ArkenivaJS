# Changelog

## 0.1.0

- Add consistent startup SQL registry reads through injected named pools and an explicit identifier allowlist.
- Add a bounded private file registry provider with production ownership checks, offline validation and optional durable activation admission.
- Validate bounded registry syntax, offline schemas and RFC 8785 content checksums before publishing immutable snapshots.
- Add readonly routing, registry, transformation, credential and capability contracts with explicit activation generations and response limits.
- Export version/default literals and an administrative capability identity without loading HTTP or database engines.

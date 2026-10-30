# Changelog

## 0.1.0

- Capture tenant verification with its original receiver without executable metadata, and observe invalid asynchronous failures without trusting promise method overrides.

- Register the tenant routing operation count as a standard technical quantity without changing the event envelope.
- Register HTTP request bytes and GraphQL operation, field, loader and subscription technical usage dimensions with fixed units.

- Isolate background consumers from publisher request scopes with `withoutScope`.
- Register messaging publication, elapsed time and application payload dimensions.
- Preserve verified tenant provenance, independent event export and bounded accounting.

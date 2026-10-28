# @arkenivajs/tenant-routing

Optional tenant operation routing contracts. The current package exposes its
readonly public types, version constants, resource defaults and administrative
capability identity. Registry providers and routing factories are not yet exposed;
this package does not register a listener or claim an executable dispatcher.

The internal startup validator checks bounded strict JSON, duplicate decoded
keys, referential integrity, route collisions and offline operation schemas.
Content checksums use the upstream RFC 8785 implementation over the four content
fields, preserving array order and excluding activation metadata. Loaded objects
are copied and deeply frozen before use. Provider I/O and durable activation
history checks belong to the forthcoming provider layer.

Active registry content uses schema 1.1.0. Immutable content revisions and
monotonic activation generations are separate. SQL options require the existing
application SqlProvider, and HTTP implementations separate request/response
transformers and trusted service credentials. Activation is startup-only.

Capability limits count authorized visible entries in one requesting principal's
response, with default 1000 and integer range 1..5000. Discovery never grants
execution permission, and an over-limit response must fail rather than truncate.
Tenant provenance, scopes, assurance and field-independent operation policy
remain runtime obligations of the forthcoming provider and dispatcher layers.

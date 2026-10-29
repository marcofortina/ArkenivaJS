# GraphQL queries and mutations

`@arkenivajs/graphql` registers on the existing API listener. Construct
`graphqlPlugin({schema,resolvers,security})` alongside logging, security and API
plugins before `app.start()`. Core and REST imports do not load GraphQL or React.
The [complete HTTPS example](../examples/graphql/README.md) compiles and tests
signed requests, mutations, row isolation and default-field denial through
public package exports.

POST accepts one JSON object `{query,variables?,operationName?}`. Native
Mercurius and GraphQL own parsing, schema validation and execution. GET is
opt-in for queries only. Cookie-bearing, cross-site and foreign-Origin requests
are rejected. Authentication defaults to required; headers, variables, IDs and
tracing baggage never establish a tenant. Public Query roots need an explicit
allowlist and reason. Anonymous mutations and subscriptions are not allowed.

The required field authorization callback must return exactly true. It runs
before explicit resolvers, default property reads, nested fields and metadata.
Root permission does not grant descendant access. Application data access must
also bind and filter by the verified tenant. Nullable field errors can accompany
HTTP 200; inspect `errors[].extensions.code` and business data together.

| Default limit                      |      Value |
| ---------------------------------- | ---------: |
| Document UTF-8 bytes               |     65,536 |
| Variables JSON bytes               |     65,536 |
| Encoded result bytes               |  1,048,576 |
| Depth / estimated complexity       |    8 / 500 |
| Expanded aliases / executed fields | 20 / 2,000 |
| Items per collection               |        100 |
| Total operation time               | 30 seconds |

Overrides are positive safe integers. Preflight includes fragments, directives
and variable pagination before side effects. Oversized lists fail explicitly.
Encoding rejects excessive output without truncating a successful response.
Forward resolver AbortSignals to downstream adapters. A mutation may commit
after timeout if application work ignores cancellation; it stays physically
owned until settlement. Do not retry blindly. There are at most 128 outstanding
operations per instance. Secure HTTP/2 retains HTTP/1.1 fallback and independent
stream cancellation on the same application listener.

Loaders use native request-scoped batching. Return exactly one ordered result
per input, preserving nulls for missing authorized rows. Maximum batch size
defaults to 100 and cannot exceed 1,000. Authorization precedes cache hits;
caches never cross tenants or requests and are invalidated between mutation
roots. Do not serialize private parent properties into keys. SQL loaders must
bind tenant and IDs, filter rows and reconstruct input order. The package's real
PostgreSQL integration proves two business SQL statements for 100 customer/order
parents; the in-memory guide does not substitute for that test. See the
[PostgreSQL guide](../examples/postgres/README.md) for trusted TLS and data types.

Introspection defaults to disabled. Enabling it requires a current verified
identity and configured administrative scope. `developerIDE:true` permits
authenticated local GraphiQL only in development/test; production rejects it.
The host must supply Authorization headers, never credentials in HTML or URLs.
Workers and fonts are local, with discarded persistent query/header storage.

The existing telemetry plugin exports fixed operation/outcome dimensions. Add
the endpoint to its finite route catalog. Operation spans are W3C-propagated HTTP
children; detailed mode enables grouped field timing. Complexity is a derived
policy estimate, and overlapping wall durations are not independent CPU usage.
Verified tenant metering has one HTTP parent and one GraphQL child. Observed
bytes belong only to HTTP; GraphQL records operations, successful fields and
actual loader batches/items. Anonymous work creates no synthetic tenant. A
timeout marks unfinished downstream work incomplete and retains its child until
settlement. Inspect quality, unknown outcomes and dropped-event diagnostics;
these events do not calculate prices or billing.

Safe errors distinguish authentication/field denial (`EK_GQL_AUTH`,
`EK_GQL_FORBIDDEN`), invalid operations (`EK_GQL_VALIDATION`), input/work refusal
(`EK_GQL_INPUT_LIMIT`, `EK_GQL_COMPLEXITY`), uncertain timeout (`EK_GQL_TIMEOUT`)
and an unsendable result (`EK_GQL_RESPONSE_LIMIT`). Log normalized metadata,
never raw documents, variable values, credentials or backend exception causes.
Administrative capability lookup does not register routes after startup.

Subscriptions use authenticated `graphql-transport-ws` on the same HTTPS
listener. Their provider must independently verify tenant provenance and isolate
event namespaces. Production requires explicit `distribution: 'shared'` and
`securityLevel: 'production'` declarations on that trusted application-owned
provider. Undeclared providers remain test-only; development requires an explicit
distribution. These deployment declarations never replace authentication or
verification of the real shared broker. Never add production labels to memory
fixtures or derive them from client input.

Configure finite connection, operation and event queue caps, explicit browser
origins and periodic identity revalidation. Failed revalidation closes the
connection. Client tenant hints cannot select a namespace. Return each iterator
on cancellation and close the application's provider after application shutdown.
Transport health does not certify broker connectivity; inspect its owning
plugin separately. Delivery is best effort without separately configured backend
durability, and an uncertain publication must not be replayed automatically.

See the [package reference](../packages/graphql/README.md) for exact contracts
and the isolated production integration command. Federation, remote SDL,
automatic database exposure and GraphQL file uploads are outside the approved
public scope. Functional example success does not complete benchmark or release
gates.

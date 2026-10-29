# Authenticated GraphQL beside REST

This executable application uses only public framework imports. A disposable
issuer creates actual ES256 assertions, and GraphQL shares a certificate-verified
HTTPS listener with a REST status route. The two tenant datasets are explicitly
demonstration memory; they do not establish database or production persistence
readiness.

Use a supported Node version, the pinned pnpm version and OpenSSL. From the root:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm --filter @arkenivajs/example-graphql test
node scripts/check-packed-examples.mjs --example graphql
```

The last command installs real framework archives in a private temporary
consumer, recompiles the example and executes all three tests through public exports.
No database, container engine, external identity provider or environment values
are required. Temporary keys, files and listeners close in `finally`; bearer
assertions and private keys are never printed.

An authenticated query with variable `id: "1"` selects a customer through an
alias and fragment. It returns `id: "1"` and `label: "First customer"`.
Selecting `privateNote` returns null with `EK_GQL_FORBIDDEN`; its getter is never
evaluated. Missing or forged assertions return HTTP 401, and an untrusted HTTPS
client rejects the fixture certificate.

`mutation { increment }` requires `example:read` and `example:write`. The first
authorized call returns `{"data":{"increment":1}}`. A read-only identity is
denied without changing the counter. Tenant-b still reads its own zero counter
and receives null for tenant-a's known customer ID. Default GET cannot execute
mutations. The same listener's `GET /status` returns `{"ready":true}`.

Adapt `createGraphqlExample()` with explicit service, HTTP/TLS, issuer and
audience settings. Its loopback issuer exception is test-only and explicitly
enabled by the fixture. Deploy approved HTTPS identity and shared business
storage while retaining verified tenant predicates, per-field permissions and
cancel propagation. Register routes before startup and always await `app.stop()`.
See the [GraphQL guide](../../docs/graphql.md) for limits and operational policy.
Subscriptions are disabled unless `createGraphqlExample()` receives explicit
`subscriptions` settings. The subscription test supplies a bounded local provider
with `distribution: 'process'` and `securityLevel: 'test-only'`. It verifies every
publish and subscribe against the actual application's `AuthService`; copying a
tenant object cannot create trusted provenance. This memory fixture is unsuitable
for production or cross-pod delivery.

With subscriptions enabled, connect a certificate-verified WSS client to
`/graphql` using the exact `graphql-transport-ws` subprotocol and the configured
browser origin. Send `{"type":"connection_init","payload":{"authorization":"Bearer ..."}}`
and wait for `connection_ack` before sending an operation:

```json
{
  "type": "subscribe",
  "id": "counter",
  "payload": {
    "query": "subscription { counterChanged(tenantHint: \"tenant-b\") }"
  }
}
```

The hint is deliberately ignored. An authorized tenant-a `mutation { increment }`
returns `{"data":{"increment":1}}` and delivers
`{"type":"next","id":"counter","payload":{"data":{"counterChanged":1}}}`
only to tenant-a subscribers. Tenant-b receives its own event after its own
mutation. Answer protocol `ping` messages with `pong`; heartbeat responses do not
replace identity revalidation. Disconnect returns the owned iterator, and
application shutdown retires all remaining iterators before the fixture closes
its provider.

The demonstration counter update and publication are separate operations. A
publication error can occur after the counter changes; never blindly retry the
mutation. A real application must choose its own transactional/outbox and delivery
guarantees. For production, supply an independently reviewed shared provider with
explicit shared/production classification and real tenant enforcement. Labels
cannot turn this local fixture into a shared broker. See the
[package reference](../../packages/graphql/README.md) for production policy and
native mTLS NATS interoperability checks.

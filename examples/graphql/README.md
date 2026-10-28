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
consumer, recompiles the example and executes both tests through public exports.
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
Subscriptions stay disabled in this application.

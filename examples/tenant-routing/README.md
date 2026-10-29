# Tenant quote routing and controlled registry rollout

This application uses public framework exports to serve one authenticated
`POST /api/quotes/calculate` contract. Tenant A selects a deployed local handler;
Tenant B selects a fixed approved partner and registered request/response
transforms. The client sends the same amount payload and never selects a backend.
An existing REST `/status` endpoint shares the certificate-verified HTTPS listener.

Run with a supported Node version, pinned pnpm and OpenSSL:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm --filter @arkenivajs/example-tenant-routing test
node scripts/check-packed-examples.mjs --example tenant-routing
```

The test owns an ES256 issuer/JWKS server, two HTTP partner fixtures, temporary
private TLS/registry files and actual application child processes. Those fixtures
are restricted to the controlled test environment and removed after the run.
No external identity, customer service, container or production credential is
required. The fixture's plain loopback issuer/partners are not production policy.

## Bootstrap a real application

Import `createTenantRoutingExample` from `src/main.ts` (or its built module) and
supply trusted service/HTTP settings, issuer, audience, absolute registry file and
approved upstream catalog. Call `app.start()` and stop the application on the
owning process's termination signal. Production defaults remain in the underlying
providers: a private root-owned deployment registry, HTTPS, approved hostnames and
networks, verified TLS and a separate service credential provider when configured.
Keep registry/catalog changes and secret-provider ownership outside public APIs.

The fixed code catalog contains `quotes.standard`, `orders.status` and separate
partner request/response transforms. A new tenant or compatible declared operation
can reference that already deployed code. A missing business handler cannot be
created by configuration and blocks startup. A new conversion still requires
deploying its implementation before the registry refers to it.

The test registries are authored in `test/registry.ts`
using the pinned upstream RFC 8785 canonicalizer and native SHA-256. The checksum
includes exactly schema version, operations, implementations and bindings;
activation metadata is excluded. Deployment JSON is created outside the repository
and outside all public static roots.

## Validate, activate, roll back

The package installs the offline validator used by the test:

```sh
pnpm exec arkenivajs-tenant-registry validate --file /run/config/tenant-registry.json
```

Use the explicit `--environment test` option only for controlled application-owned
fixtures; production ownership checks are the default. The command checks bounded
strict JSON, schemas, declarative references and checksum. Application startup also
checks the deployed catalogs, authorization authority and existing listener.

The process test first activates `content-blue`, generation 1. It then writes
`content-green`, generation 2, without changing the application binary or trusted
upstream catalog. The new data onboards Tenant C to the existing local quote
handler, selects the second already approved partner for Tenant B and declares
`orders.status` using its existing handler. A newly started process sees those
changes while the old process continues serving its blue snapshot. Capabilities
identify each process's revision and activation generation during the rollout.

Rollback reuses the exact blue content/revision/checksum under generation 3.
A restarted process serves that snapshot while a still-running green process
remains green. This is startup activation; file edits never hot-reload a process
or promise instantaneous convergence across pods. Operators must separately
enforce durable historical admission and audited/atomic file or SQL promotion.

## Generic frontend discovery

Use the application's existing bearer/session mechanism to obtain authorization;
never embed a credential in a frontend bundle. A browser can fetch the same-origin
capability endpoint and find the logical action without testing tenant IDs:

```js
const authorization = await applicationSession.getAuthorization();
const response = await fetch('/api/tenant/capabilities', {
  headers: { Authorization: authorization, Accept: 'application/json' },
});
if (!response.ok) throw new Error('Capabilities unavailable');
const { revision, capabilities } = await response.json();
const action = capabilities.find((entry) => entry.operationId === 'quotes.calculate');
if (action) {
  const result = await fetch(action.path, {
    method: action.method,
    headers: { Authorization: authorization, 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: 125 }),
  });
  if (!result.ok) throw new Error('Operation unavailable or no longer authorized');
}
```

Treat 401/403/404 and capacity failures as authoritative even after discovery.
The endpoint is private/no-store, reveals no implementation/upstream identifiers,
and cannot be used to select another tenant. Different pod revisions may expose
different compatible capability sets during a rollout.

## Evidence and boundaries

Tests use real signatures, TLS verification, native HTTP, installed CLI invocation
and separate processes. They reject forged assertions, spoofed tenant headers,
tenant fields outside the request contract, missing scopes, unknown bindings,
invalid payloads, missing deployed code and tampered checksums. A valid declarative
registry with an unavailable handler fails before readiness; a corrected registry
can start normally. Read-only discovery, local/partner normalization, stable old
snapshots, restart and higher-generation rollback are asserted through public APIs.
Another case introduces a compatible operational partner through the separately
approved startup catalog; the same registry first fails without that approval.

Supplementary events use a controlled IPC exporter in the child fixture and are
checked for the selected verified tenant/implementation. Production exporters
must independently implement their required durable delivery and access controls.
See the [package reference](../../packages/tenant-routing/README.md) for precise
provider, network, metering, event-queue, error and resource contracts. Performance,
final security coverage and release acceptance remain separate gates.

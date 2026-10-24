# Verified tenant metering with independent JSONL events

Run the complete disposable example from the workspace root with Node.js 24:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-metering start
```

Expected final output:

```json
{
  "statuses": {
    "permittedA": 200,
    "permittedB": 200,
    "spoofed": 404,
    "head": 200,
    "missing": 401,
    "wrongAudience": 401,
    "missingScope": 403,
    "lowAssurance": 403
  },
  "events": 8,
  "tenants": ["tenant-A", "tenant-B"],
  "tracesSampled": false
}
```

The program creates a private temporary workspace, a real RSA-signed OIDC test issuer, a public HTTP fixture and an authenticated API. It installs independent logging, security, telemetry, metering and HTTP adapters with explicit dependencies. No external account, persistent credential, container or database is required for this example. All files/listeners are closed and removed before the command exits. The issuer is a disposable assertion fixture, not a login or factor implementation.

Root metering selects `enabled:true`, `exporter:'jsonl'` and `path:'events.jsonl'`. `meteringPlugin({workspace,dependencies:['telemetry'],usageDefinitions:{'orders.lookup':'operations'}})` owns the file exporter; the API declares `security`, `metering` and `telemetry` dependencies. The outbound client declares `metering` and `telemetry` dependencies too. This explicit wiring supplies abstract ports without embedding concrete adapters in core or the API.

The protected route requires `orders:read` and `mfa`. Its issuer-specific resolver accepts only the fixture's exact issuer, expected authentication context/method and an authentication time within 60 seconds. Missing/unrecognized assurance remains single-factor. These signed test assertions demonstrate IdP policy enforcement; no local TOTP/WebAuthn proof or session token is issued. An arbitrary claim named `mfa` or an unsigned header would not establish assurance.

Only after signature/audience/time, scope, assurance and tenant authorization does the API start its usage session. Four authenticated requests produce four parent events and four `orders.lookup` child events. Three parents succeed; the authenticated tenant-A attempt to read tenant-B's row produces a 404 and error events under tenant-A. Request headers and baggage cannot select tenant-B. Missing credentials, wrong audience, missing scope and insufficient assurance fail before trusted usage begins and create no tenant event.

Each parent records one logical HTTP request, observed serialized response bytes and one real outbound client invocation with measured elapsed milliseconds and an 18-byte response body. HEAD records an observed zero response body. Each child records one actual in-memory lookup, with a predicate on the verified tenant. This is not a SQL query or database benchmark. Parent and child operation IDs differ, parent links and request IDs match, and each event carries its own UUIDv4 deduplication key.

Telemetry is off throughout, yet all eight events are fsynced to independent JSONL and validated before readback. Missing trace IDs are expected; metering does not depend on sampled spans. `runMeteringExample()` returns immutable validated events for inspection, while the command prints only the status/count summary. CPU/RSS are not invented per tenant. Local completeness covers the instrumented work, not all work of the public upstream fixture or a distributed service graph.

Run `pnpm --filter @arkenivajs/example-metering test` for the exact output, tenant isolation, event DAG, byte/unit semantics and cleanup checks. The [metering package](../../packages/metering/README.md) documents queue/byte limits, strict double-end behavior, pressure/property tests, retry IDs, explicit loss statistics and the separate real collector integration job. Actual SQL/RLS and authenticated service-to-service data access require their own adapter-specific integration examples.

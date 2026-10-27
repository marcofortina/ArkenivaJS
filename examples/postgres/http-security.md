# Cookie sessions, HTTP headers and CSRF

This executable consumer uses actual signed OIDC authentication, `SessionService.validate()` and the PostgreSQL security-state adapter. It starts two independent HTTP applications backed by separate PostgreSQL pools and checks persistence across an application restart. The owned disposable database connection requires verified TLS; no production credentials or laptop container installation are required.

The reusable composition is [src/http-security.ts](src/http-security.ts). `cookieSecuritySettings()` receives the existing session service, a complete shared store, an independently verified HMAC provider, exact frontend origins and an application authorization callback. The callback resolves the verified session's current account, tenant and permissions. Neither a caller-supplied identity nor a bare session ID is accepted as proof.

Register `securityHttpPlugin(settings)` with the existing API and logging plugins before `app.start()`. Mount the selected `POST /protected` business route and enforce its business authorization independently. Obtain the CSRF capability after READY. The token endpoint validates the actual authenticated session, then calls `csrfToken({sessionId})`; the response carries the secure host-only nonce cookie and the opaque JSON token. The frontend sends that token in `x-csrf-token` for state-changing requests, with the existing session cookie and approved Origin.

The integration fixture deliberately includes a client session hint to prove that runtime cookie validation rejects a mismatched ID. A normal application should obtain the ID from its session validation result. Its optional non-HTTP authentication callback is a private server-owned context, not a request-body adapter. The disposable account/issuer implementation is test-only; production uses the application's reviewed identity and secret authorities.

After supplying an owned disposable PostgreSQL fixture through the existing test environment:

```sh
pnpm --filter '@arkenivajs/example-postgres...' build
node --test dist-test/integration/http-security.integration.test.js
```

Run the second command from this example directory with `ARKENIVA_POSTGRES_DISPOSABLE=1` and the existing verified-TLS `DATABASE_URL`. Keep connection credentials in the external test runner or secret provider. From the workspace root, the full suite and packed consumer are:

```sh
pnpm --filter @arkenivajs/example-postgres test:integration
pnpm test:packed:examples --integration postgres
```

The tests cover real OIDC-issued session credentials, two pools sharing CSRF state, secure nonce cookies, native CSRF verification, foreign tenants, manually constructed contexts, durable primary-session revocation, unavailable HMAC keys and a missing owned CSRF table. They inspect persisted records to ensure no token, nonce, session cookie, session ID or primary bearer is stored. Every schema and listener belongs to the fixture and is closed afterward.

The standalone module tests additionally exercise verified direct HTTPS, hostile Origin/Referer cases, exact proxy peer policy, incomplete-provider shutdown, cancellation and actual Pino/OpenTelemetry privacy. See the [module reference](../../packages/security-http/README.md) for exact limits, key-rotation behavior and failure semantics. The reference SQL adapter remains a disposable demonstration, not an automatically provisioned production persistence layer.

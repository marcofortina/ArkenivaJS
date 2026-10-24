# OIDC, scopes and tenant isolation

This executable guide requires Node.js 24 and the pinned pnpm version. It creates a disposable RSA key pair and an OIDC discovery/JWKS fixture on loopback, then starts a protected framework service. Keys exist only in process memory; no credential, certificate or external account is required.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-oidc-tenants start
pnpm --filter @arkenivajs/example-oidc-tenants test
```

The CLI prints exactly `{"permitted":200,"spoofed":404,"missing":401,"wrongAudience":401,"missingScope":403}` and closes both listeners and the private JWKS HTTP agent. It signs an assertion for tenant A, requests A's record successfully, then attempts B's record with forged tenant headers and baggage. The tenant-filtered predicate denies B. Missing credentials and wrong audience reject with 401; an authenticated identity without the route scope receives 403. Tests execute both the exported demonstration and the built CLI with a cleanup deadline.

The application explicitly registers logging, security and API plugins. API dependencies include `security`; route authentication is mandatory before middleware/handler execution. `ctx.auth.tenantId` comes from the verified single-valued `tenant_id` claim. A shared namespace, caller string, trace id or TypeScript cast cannot create trusted provenance. Include the verified tenant in every repository predicate, cache key and authorization check.

This proof uses in-memory records and demonstrates the authorization boundary and application predicate. Production databases need tenant-scoped SQL or row-level security with independent negative integration tests. The framework does not add row isolation automatically.

Replace the loopback fixture with a trusted production OIDC issuer, register a destination-specific API audience and load nonproduction access tokens through an approved secret mechanism. Remove `allowInsecureLoopback`; HTTPS verification is mandatory in production. Match the issuer's access-token type (`JWT` by default, `at+jwt` where supported), algorithm allowlist and tenant entitlement policy. Never print or commit bearer tokens. Cross-service callers require a token for the destination audience; diagnostic headers never authorize another service.

If a selected local test port becomes occupied, the example fails safely and closes initialized resources. Retry with available ports; do not stop unrelated services. Invalid issuer metadata, missing signing keys or unavailable discovery endpoints fail with safe errors. See the [security reference](../../packages/security/README.md) for refresh limits, cancellation and verifier ownership.

# @arkenivajs/security-http

Install native Fastify/Helmet security headers and session-bound CSRF controls on the existing ArkenivaJS API listener. Cookie-authorized routes are selected explicitly; ordinary bearer routes do not acquire an implicit CSRF requirement. No additional listener, database pool, authentication authority or signing key is created automatically.

```typescript
import { securityHttpPlugin, SECURITY_HTTP_CAPABILITY } from '@arkenivajs/security-http';
import type { SecurityHttpService } from '@arkenivajs/security-http';

// Register securityHttpPlugin(settings) alongside the existing API/logging plugins before startup.
// settings supplies independently verified session authorization, HMAC and shared storage providers.
const security = app.resolve<SecurityHttpService>(SECURITY_HTTP_CAPABILITY);
const token = await security.csrfToken({ sessionId: authenticatedSession.sessionId });
await security.verifyCsrf(
  { sessionId: authenticatedSession.sessionId, origin: approvedBrowserOrigin },
  token,
);
```

The [PostgreSQL cookie-session consumer](../../examples/postgres/http-security.md) provides an executable composition using real OIDC authentication, the existing session service and two independent verified-TLS PostgreSQL pools. It compiles through the public package exports and is also tested from private packed artifacts.

## Configuration and headers

`SecurityHttpPluginSettings` requires `policy`, `csrfStore`, `csrfHmac`, `csrfKeyRef` and `authority`. The policy contains `contentSecurityPolicy`, `hstsMaxAgeSeconds`, `csrfEnabled` and `frameAncestors`. Providers are explicit application-owned dependencies; TypeScript objects, claimed tenant IDs and session identifiers do not prove authentication.

Provider methods retain their captured implementation and original receiver.
Callable `bind`, `name` and `length` properties are never evaluated. Proxy providers
or callbacks, accessors and prototype traversal beyond 64 levels fail configuration
validation; later method replacement does not alter captured ports.

The captured policy is immutable. `getEffectivePolicy()` returns that snapshot; `installHeaders(policy)` atomically replaces validated header settings for subsequent responses. CSP uses explicit native directives, requires a nonempty `default-src`, and rejects wildcards, injection and unsafe evaluation. `frameAncestors` is a separate explicit policy, limited to `'none'`, `'self'` and exact HTTPS origins. No report-only fallback is installed. HSTS max-age is an integer 1–63,072,000 seconds and is never disabled automatically. `nosniff` and `Referrer-Policy: no-referrer` are always applied, including error responses. Frontend script/style policy must be chosen by the application.

`allowedOrigins` contains up to 32 distinct canonical origins and is mandatory when CSRF is enabled. No origin is inferred from Host or forwarded headers, and wildcard credential origins are rejected. Production requires HTTPS origins; explicit insecure loopback origins and test-only providers are usable only in the core `test` environment.

`cookieRoutes` contains at most 128 distinct `{method, path}` selectors for POST, PUT, PATCH or DELETE. Every selected route must exist before listener activation. `cookieSession.resolve(request, options)` is required for these routes and must validate the actual session cookie through the existing `SessionService`. The authority independently rechecks the authenticated session, tenant membership and operation permissions. The module supplies an immutable actual-request projection to the authority; callers cannot add that projection to the public CSRF context. CSRF validation does not replace application business authorization.

The native cookie parser and CSRF plugin are owned by this adapter; do not register competing instances on the same Fastify scope. The adapter uses the actual native `csrfProtection` hook after authorization and durable binding checks. Native `generateCsrf` alone does not create an approved durable application binding; use the service's `csrfToken` method.

## Browser flow and durable state

Authenticate the primary user, issue the framework session using the prescribed secure cookie policy, and derive the CSRF session ID from `sessions.validate()` rather than from a request field. The practical consumer's `cookieSecuritySettings()` demonstrates the runtime verification and current-account policy callbacks.

On an actual token-issuance request the adapter sets `__Host-arkeniva-csrf` with `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` and a maximum age of 900 seconds, without Domain. Return the opaque token only to the authenticated frontend, and send it in `x-csrf-token` on selected requests. Native protection requires a matching nonce cookie, exact approved Origin, or exact-origin Referer fallback when Origin is absent. `Origin: null`, hostile sibling domains, mixed origins, missing cookies and malformed tokens are rejected. Do not log response tokens or cookie headers.

The versioned opaque token wraps the native SHA256 CSRF token with a random 32-byte nonce. Native HMAC material comes from the configured domain-separated `KeyedDigestProvider`, not a per-pod random production key. Acknowledged shared-state creation is required before releasing a token. Persistence contains only HMAC-derived owner/session/nonce identifiers and expiry metadata, never raw session IDs, session cookies, CSRF nonces/tokens or HMAC keys.

Tokens are reusable, not one-time credentials. They remain valid only for the same verified issuer, subject, tenant and session, with a maximum 15-minute lifetime and live session authorization on every verification. A browser's existing live nonce is reused after checking its durable binding, so another tab's token remains valid and repeated issuance does not create additional records. Issuance does not extend an existing binding's original expiry. After expiry a new binding is required. Non-HTTP callers receive a token but must provide an independently authenticated server-owned authority context; supplying a session ID alone is denied.

The backing store must implement the complete shared transactional contract and enforce retention/cleanup for expired records. Apply the application's approved issuance-rate policy through the trusted authority. There is no process-local persistence fallback. Revocation, provider unavailability, corrupt state and failed/ambiguous writes never produce a verified result. The initial HMAC derivation is owned by a lifecycle support resource even if initialization is canceled. Every operation rechecks the configured key derivation; rotation invalidates the old key and requires an application restart before issuing tokens with the new key. No fallback to a retired key occurs.

## TLS, lifecycle and limits

Direct HTTPS uses the existing API listener and verified TLS policy. A TLS-terminating proxy requires explicit `trustedProxyCidrs` (at most 32). Only a matching immediate peer and exactly `X-Forwarded-Proto: https` establish HTTPS awareness. Arbitrary forwarded headers and untrusted peers do not. The core test environment's owned loopback fixtures are the only plaintext testing exception.

Public operations require READY state and reject after close. Timeouts are positive integer milliseconds, bounded by the store operation timeout and 5,000 ms; at most 16 native/provider operations are retained concurrently, with no unbounded queue. A canceled public waiter does not release capacity until actual private work settles. Client disconnect and application shutdown abort their owned scopes. A failed shutdown deadline explicitly reports retained work rather than claiming cleanup succeeded. HMAC buffers are erased after owned work drains.

Policies accept at most 64 CSP directives, 32 sources per directive, 8 KiB of source text and 16 frame ancestors. Context identifiers, tokens, cookies and origins are bounded and validated before provider access. Null, unknown configuration fields and accessors are rejected. Return values and policy snapshots are immutable.

Optional Pino/OpenTelemetry observations contain only fixed operation/outcome labels, rejection counts and operation durations. No session, tenant, cookie, token, key or provider exception becomes a metric label, log field or trace attribute. Observer failures cannot authorize an operation or replay work.

Invalid configuration uses `EK_HTTP_SECURITY_POLICY`; rejected verification uses `EK_HTTP_CSRF` (HTTP 403). Common `EK_ABORTED`, `EK_TIMEOUT`, `EK_BACKEND_UNAVAILABLE`, `EK_LIFECYCLE_STATE` and `EK_RESOURCE_CLOSED` retain their normal meanings. An interrupted persistence attempt is explicitly marked `details.outcome = 'unknown'`. Functional tests do not imply completion of the deferred performance, remote CI and release gates.

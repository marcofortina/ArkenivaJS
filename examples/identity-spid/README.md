# SPID SAML/OIDC application and browser transaction examples

Run `pnpm --filter @arkenivajs/example-identity-spid build` and `pnpm --filter @arkenivajs/example-identity-spid test` from the workspace root. `node scripts/check-packed-examples.mjs --example identity-spid` additionally installs actual package archives into an independent consumer and compiles and executes this example there.

The executable tests configure the public `loggingPlugin`, `securityPlugin`, `cryptoPlugin` and `spidPlugin` APIs with explicit application-owned registration, external ephemeral keys, pinned federation roots and a test-only transactional store. They use real JOSE signatures, OpenID Client JAR and PKCE, live signed RP/OP mark status, private-key JWT exchange, signed unencrypted SPID ID Tokens, signed/encrypted UserInfo and an actual canonical AuthService over HTTPS. All framework imports use documented package entry points. ID Token encryption belongs to the distinct CIE profile and cannot be enabled on this SPID registration.

`src/browser-flow.ts` supplies application handlers around the selected public `SpidService`. Call `beginBrowserLogin` with a server-selected `forProfile(profileId)` view and an approved issuer/assurance. Apply its 303 status, response headers and empty body. It binds the service-issued state to a `__Host-spid-flow` cookie with `Secure`, `HttpOnly`, `Path=/` and `SameSite=Lax`. The cookie lifetime is the shorter of five minutes and the actual transaction lifetime. Responses disable caching and referrers. Starting another login in the same browser replaces that cookie, so this example supports one active browser ceremony at a time.

For the registered top-level GET callback, build the absolute callback URL from the application's fixed configured HTTPS origin, rather than an untrusted forwarded host. Set `clearBrowserCookie` on the response before verification so it is cleared on success and error. Pass the Cookie header, callback URL and exact configured callback URI to `consumeBrowserLogin`. It rejects absent, foreign or duplicate cookies, duplicate/missing state, foreign callback origins/paths and altered fixed query parameters before invoking the federation service. The framework then independently validates the entire callback, current trust, protocol evidence and shared atomic one-use state. `SameSite=Lax` is intended for this OIDC top-level GET flow; this example does not enable cross-site POST callbacks.

The HTTPS driver performs a real application begin request and callback, rejects a foreign cookie before token exchange, accepts the canonical identity once, clears the cookie and rejects replay without another exchange. It also verifies explicit profile/provider selection, readiness, revoked RP trust, key changes, concurrent callback acceptance and privacy in both standard and detailed SDK telemetry. These are native HTTPS fixtures, rather than a browser-engine or official provider certification run.

The returned identity is the approved canonical account and verified tenant. It does not automatically create a local application session or grant MFA. Authorize the intended local action and apply the application's session policy explicitly. Never use callback attributes, a tenant hint or a manually constructed TypeScript object as tenant authority.

The fixture's in-memory store, ephemeral CA, keys, federation and canonical accounts are test-only. Production and development reject test-only providers. Deployments require a durable shared transactional provider, secure external key management, actual administrative RP registration and accreditation, approved organization/metadata endpoints, current federation pins and mandatory revocation. The configured federation resolve endpoint is a deployment prerequisite; this example does not host one. TLS trust is scoped to the isolated child process and all HTTPS exchanges validate certificates and hostnames. Temporary credentials, collectors and listeners are closed after each test.

Official interoperability, browser certification, release acceptance and deferred performance/duration campaigns remain separate gates. See the [SPID package guide](../../packages/identity-spid/README.md).

## SAML Redirect and POST ACS

`src/saml-browser-flow.ts` supplies separate `beginSamlBrowserLogin` and
`consumeSamlBrowserLogin` handlers for a selected SAML profile. The Redirect sets
`__Host-spid-saml-flow` with `Secure`, `HttpOnly`, `Path=/`, `SameSite=None` and a
maximum five-minute lifetime, bounded by the actual login expiry. This policy
permits the IdP's cross-site POST; keep the distinct OIDC GET cookie unchanged.

At the application's exact configured HTTPS ACS, set `clearSamlBrowserCookie`
before verification so all error responses clear it too. Bound incoming form bytes
while reading the request and pass `{ method, url, contentType, body }` together with
the fixed configured ACS and selected approved issuer to `consumeSamlBrowserLogin`.
The example requires POST, URL-encoded form data, unique SAMLResponse/RelayState
fields and a valid host cookie. It rejects extra fields, including a submitted
transaction ID, duplicate cookies, wrong destinations and malformed encoding before
calling the service. The service independently compares the cookie transaction's
encrypted native request ID to signed correlation; swapping two browsers' cookie
and response never authenticates either as the other account. No local session is
created by this handler.

The standalone HTTPS driver uses independent ephemeral SP/IdP signing keys, pinned
root-signed metadata, fresh registry state, real signed Redirect/POST messages and
actual AuthService tenant provenance. It exercises readiness, health failure, replay,
browser swaps, IdP withdrawal, downgrade, cross-tenant mapping, authority/storage
denial and private logs through public package imports. The same driver compiles
and executes against installed package archives. It is a protocol HTTP test driver;
it does not claim official IdP accreditation or a browser engine conformance result.

The SAML fixture explicitly permits levels 2 and 3. A request for level 2 followed
by an actually signed level 3 response returns `federationAssurance: 'spid-l3'`
through the canonical mapper, without creating MFA evidence or a local session.

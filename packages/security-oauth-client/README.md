<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Outgoing OAuth2 and OpenID Connect client

`@arkenivajs/security-oauth-client` uses pinned `openid-client@6.8.8` for Authorization Code with PKCE S256, signed OIDC ID-token checks, Client Credentials, refresh and revocation. Install `loggingPlugin`, `cryptoPlugin` and `oauthClientPlugin(settings)` before startup, then resolve `OAUTH_CLIENT_CAPABILITY` as `OAuthClientService`. No inbound callback route or local session is created automatically. Imports and plugin factories perform no network or provider I/O; bounded trusted discovery occurs at startup.

The five public methods are `beginAuthorization({subject?,audience,scopes,returnPath}, options?)`, `exchangeCode({stateRef,code,issuer,redirectUri}, options?)`, `clientCredentials(audience,scopes,options?)`, `refresh(refreshRef,options?)` and `revoke(refreshRef,options?)`. Authorization starts return `{authorizationUrl,stateRef,expiresAt}`. Grants return `{accessToken,tokenType:'Bearer',expiresAt,scopes,audience,refreshRef?}`. Access tokens and refresh references are secrets. A grant supplies no local identity, session or MFA assurance.

## Registration and authorization policy

Settings require a `clients` catalog, external `secretProvider`, complete distributed `stateStore`, runtime `authority`, `maxStateTtlMs`, `stateEncryptionKeyRefs` and `stateMacKeyRefs`. The separately installed crypto capability must approve the same encryption and MAC references. State encryption uses native AES-256-GCM and reference proofs use native HMAC-SHA256 through that existing capability; no proprietary cryptographic algorithm or raw database key exists.

Each registration has `id`, exact trusted `issuer`, `clientId`, optional `clientSecretRef`, exact `redirectUri`, `allowedAudiences` and `allowedScopes`. A configured client secret uses native `client_secret_basic`; a registration without one supports a public interactive client. Machine grants require client authentication. Optional private-key JWT and mTLS authentication profiles are not exposed by this registration contract. Unsupported provider revocation/interactive capabilities fail explicitly.

At most 32 registrations, 16 distinct audiences per registration, 64 scopes and 16 endpoint origins are accepted. Audiences must identify one registration unambiguously. Endpoint origins default to the issuer origin; `allowedEndpointOrigins` explicitly permits a separate trusted token/JWKS/revocation host. Discovery issuer and all discovered endpoints must match this deployment policy. Credentials, URL fragments, dynamic request URLs and reserved callback query parameters are rejected. Production uses verified HTTPS. Only core `environment:'test'` can enable `allowInsecureLoopback:true`, restricted to literal loopback/localhost HTTP URLs. Test-only marked stores and providers are rejected outside test.

Every grant operation calls `authority.require` against server-owned authentication and account/tenant policy. Its optional typed `context.oauth` contains approved client ID, audience, scopes and local return-path hints. A supplied subject, copied tenant object, callback state or refresh reference is never independent authentication proof. The authority returns the actual canonical subject/tenant, which must match the saved grant owner on exchange, refresh and revocation. Provider errors deny the operation. Background machine grants still require an independently authorized service principal; there is no cross-tenant token cache.

## Interactive and refresh state

Interactive state contains cryptographically random state, nonce and PKCE verifier, exact issuer/redirect and authorized owner. PKCE S256 is always used. The upstream engine validates signed OIDC ID tokens, nonce, audience, issuer and expiry when `openid` is requested; ROPC and implicit grants have no exposed method. Registered redirect query components are retained by the upstream SDK's documented custom-fetch hook. `returnPath` is a local path hint, never an automatic redirect.

The state store must implement all seven transactional methods. Authorization and refresh references are opaque versioned identifiers with 32 random secret bytes. Database rows retain keyed proofs and authenticated encrypted payloads, not reference secrets, PKCE verifier, nonce or raw refresh token. Minimal canonical account metadata remains necessary to enforce ownership. Access tokens and client secrets are never persisted by this adapter.

State is consumed atomically before a code or refresh request. An exchange cannot be retried with the same state. Refresh requires a new upstream refresh token and atomically advances its durable family head. A verified spent-reference replay invalidates the family epoch and attempts revocation of the latest recorded upstream token. Wrong reference proofs cannot revoke another user's family. Every successful refresh rechecks the family epoch before acknowledging a grant. Provider/DB failures produce no success and no in-memory fallback. Upstream token issuance and local SQL persistence are not one distributed transaction; a lost acknowledgement or persistence error may leave an unknown remote outcome requiring provider-side reconciliation.

`maxStateTtlMs` is a positive integer up to ten minutes. Optional `refreshTtlMs` defaults to 24 hours, maximum 30 days; refresh never extends the original family's deadline. Retain old approved encryption/MAC references through their active record lifetime. Changing a provider's key behind a reference does not enable silent fallback. The secret provider must ensure key entropy, immutable version identifiers, access and expiry. The adapter erases owned temporary byte copies and leaves provider buffers untouched; JavaScript strings do not promise physical memory erasure.

## Bounds, lifecycle and observations

The shared operation deadline comes from `stateStore.operationTimeoutMs`, a positive integer up to 120000; per-call `timeoutMs` can only tighten it. Genuine native AbortSignals are supported. Each instance admits 32 operations with no queue, and a shared durable technical budget permits at most 1000 grant operations per minute. Uncooperative providers retain capacity until actual settlement. Shutdown aborts public work and drains private work before closing the HTTP agent; an uncooperative provider can produce an explicit core shutdown deadline failure. Service calls require application READY and fail after shutdown.

Native HTTP limits include eight connections, 64 KiB request forms and 256 KiB response buffering. Discovery has finite tree depth/node/string bounds. Redirect responses are never followed, and token requests have one transport attempt. No credential is forwarded to a foreign destination. Cancellation does not promise that an upstream provider rolled back a token issue or revocation; safe errors report an unknown outcome where appropriate.

Pino and OTel observations contain fixed operation/outcome and duration only. No token, subject, tenant, issuer, reference, arbitrary scope or native response body is included. Errors use `EK_OAUTH_STATE`, `EK_OAUTH_EXCHANGE`, `EK_OAUTH_PROVIDER`, `EK_OAUTH_POLICY` and the common bounded-operation codes, with generic messages and no native causes.

The declaration-only compatibility patch admits explicit `undefined` in two upstream optional properties under strict TypeScript. It changes no SDK JavaScript, protocol or cryptography. Public consumer checks install the original registry SDK through packed artifacts. See [third-party notices](THIRD_PARTY_NOTICES.md) and [the complete PostgreSQL consumer](../../examples/postgres/oauth-client.md). Comparative performance, soak, final security coverage and remote/release acceptance remain separate gates.

# @arkenivajs/identity-spid

Optional SPID SAML 2.0 and OIDC federation plugin using the existing native SAML,
HTTP, Crypto and security services, JOSE and OpenID Client. Both profiles verify
current relying-party and provider participation before returning a login or
canonical identity. Local technical tests do not establish official interoperability,
accreditation or production certification.

For SAML, configure `samlRegistration.signingCertificateRef` separately from private
signing and state-key references. `samlRegistration.registrySources` must associate
the RP and every configured IdP with exact `metadataEndpoint` and `statusEndpoint`
URLs already listed in `metadata.approvedMetadataEndpoints`. Unknown fields,
executable values, incomplete catalogs and OIDC/CIE use of this registration fail.
Capture reads no secret material. Bootstrap verifies live registration and a matching
external SP key/certificate before readiness; no listener is installed by this plugin.

The bounded native XML worker verifies the exact configured role/entity and root
signature. Fresh approved HTTPS XML and registry JSON must agree on current RSA
signing certificates and explicitly active membership; the status origin must match
the authority that verified the XML. RP metadata must register the configured POST
ACS. Evidence expires at the earliest document, root, certificate or refresh boundary.
Failed refresh retires earlier evidence, including concurrent verification; no cached
status fallback or arbitrary discovery can grant participation. Unsupported signature
representations fail closed. Official registry-format interoperability remains an
independent conformance gate.

SAML Redirect initiation reuses the signed native request and checks every external
SP certificate read against current registration, including rotation between reads.
Its native request ID stays inside encrypted single-use eID state, while the generic
SAML replay record retains only public protocol correlation and a fixed safe return
path. Signed RelayState is preserved exactly. Private application return paths and
tenant hints remain in the encrypted payload.

POST acceptance consumes that protected state before native response/assertion
verification, with exact issuer, requested SPID class, transient NameID qualifiers,
request, audience, destination and replay checks. Only this protocol owner's live
evidence can enter canonical AuthService tenant mapping and explicit authorization.
Manually reconstructed objects confer no authority. An alternate `subjectClaim`
requires exactly one verified attribute; asserted tenant attributes grant no local
membership. Generic SAML assurance is never promoted to MFA.

The documented `@arkenivajs/identity-spid/support` entry exports
`createItalianFederationPlugin(system, capability, settings)` for trusted adapter
composition over this native backend. The separate CIE package uses it with its
own fixed system and unique capability. It creates no SPID registration when
composing CIE. Application code should use the owning package's `spidPlugin` or
`ciePlugin`; never select the support factory's system, capability or settings
from a request. The native configuration, cryptographic and lifecycle logic is
shared; activated profiles, authority actions and state remain independent.

## Explicit application composition

Install `loggingPlugin`, `securityPlugin`, `cryptoPlugin` and `spidPlugin` explicitly. The SPID plugin depends on the current application's security and Crypto plugins; it does not install routes, open an application listener or create a session. The application's configured environment controls provider and network restrictions. Test-only stores, secrets, authorities and mappers are rejected in production and development, including labels captured before a caller mutates the original object.

```typescript
import type { ApplicationOptions, Plugin } from '@arkenivajs/core';
import { spidPlugin, SPID_CAPABILITY } from '@arkenivajs/identity-spid';
import type { ItalianEidPluginSettings, SpidService } from '@arkenivajs/identity-spid';

export function installSpid(
  options: ApplicationOptions,
  logging: Plugin,
  security: Plugin,
  crypto: Plugin,
  registration: ItalianEidPluginSettings,
): ApplicationOptions {
  return { ...options, plugins: [logging, security, crypto, spidPlugin(registration)] };
}

export async function beginSpid(service: SpidService, profileId: string, issuer: string) {
  return service
    .forProfile(profileId)
    .beginAuthentication({ returnPath: '/private', issuer }, 'spid-l2', { timeoutMs: 5000 });
}

// After application.start():
// const service = application.resolve<SpidService>(SPID_CAPABILITY);
```

Supply the actual configured dependency plugins above, rather than constructing them from request input. Registration is application-owned immutable data, never callback metadata. `SPID_CAPABILITY` resolves only after successful bootstrap; operations additionally require application readiness. Shutdown aborts work and retains physical ownership until providers and native operations settle. Profile views share the same admission pool and lifecycle.

## Registration and trust

Each versioned profile pins its entity/client identifier, callback, approved issuers, allowed SPID assurance, signing reference, trust anchors and their validity, metadata destinations, mandatory revocation, stale-metadata rejection, mapping version and session lifetime. Automatic OIDC registration requires `clientId === entityId`.

Operational OIDC additionally requires `oidcRegistration`: organization metadata, approved authority hints, received RP trust marks, explicit signature/encryption policy, a distinct external decryption key reference, requested UserInfo claims and exact `approvedProtocolEndpoints` for token, UserInfo and remote JWK-set access. Metadata discovery permissions do not grant permission to send credentials to protocol endpoints. Keys and administrative registration values are supplied externally; the package never invents them.

SPID ID Tokens are signed and unencrypted; `idTokenEncryption` is rejected for a SPID profile, and an unexpected encrypted ID Token is rejected after one-use state consumption. UserInfo remains signed and encrypted with the explicitly configured policy. Optional ID Token encryption belongs to CIE registration under the [official SPID/CIE profile differences](https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/differenze_spid_cie.html). Application assurance labels retain their own identity system even though both OIDC profiles use the standard Italian `SpidL1`/`SpidL2`/`SpidL3` wire references.

Both RP and OP chains must reach a current pinned anchor using superior-delegated and currently published keys. Every required intermediary and leaf needs its own authorized role-specific accreditation mark and fresh signed live status. Metadata policies and inherited path, naming and role constraints remain in force. Superior policies cannot silently replace the RP's approved callback, client, keys or protocol algorithms. Publishing a signed self-configuration alone does not establish membership.

Inline protocol JWKS takes precedence over explicitly approved signed or JSON remote sets. Signed sets require the current delegated federation signing key and exact issuer, subject and token type. Keys must be public, sufficiently strong and compatible with approved algorithms. Metadata and protocol requests use bounded native HTTPS with exact destinations, no redirects or automatic exchange retries. Production and development reject private-network destinations.

## Public operations

The bullets below describe OIDC wire inputs. For a SAML profile, initiation returns
the same typed Redirect result. `consumeAuthentication` instead accepts the strict
object `{ transactionId, issuer, relayState, samlResponse }`: obtain `transactionId`
from the application's own Secure, HttpOnly browser cookie and pass the posted
RelayState and encoded SAMLResponse separately. Never obtain the expected transaction
from a submitted form field or infer it from XML. `issuer` selects only an already
configured issuer and must match the encrypted transaction. The same canonical
mapping and `spid.consume_authentication` authority follow native verification.

SAML `metadata()` returns the exact original currently registered RP XML, retaining
its verified root signature after checking the local SP key/certificate.
`verifyFederationTrust(xml)` requires valid native root verification and authenticated
reference bytes matching freshly registered current metadata for that entity and
role. A signature without current participation is insufficient. Use the
[POST ACS example](../../examples/identity-spid/README.md) for browser correlation.

- `forProfile(profileId)` returns a cached immutable view of one configured profile. The root service remains usable directly when exactly one profile exists. Multiple profiles require explicit selection; unknown or ambiguous selections fail closed.
- `beginAuthentication({ returnPath, tenantId?, issuer? }, assurance, options?)` checks the trusted `spid.begin_authentication` authority, current RP/OP membership and requested assurance, then creates protected single-use state and a signed PKCE authorization request. No existing authenticated session is required to begin a ceremony; the trusted authority explicitly decides whether to permit it. Multiple approved issuers require explicit selection. An issuer selector cannot supply new endpoints or metadata. `tenantId` is only an untrusted hint.
- `consumeAuthentication(response, options?)` accepts the complete callback URL matching the registered destination and fixed query. It atomically consumes state before exchange, verifies signatures, encryption, issuer, nonce, PKCE, audience, Access Token binding and assurance, then invokes the configured canonical mapper and `spid.consume_authentication` authority. Replays and ambiguous persistence fail closed.
- `metadata()` returns the exact signed RP Entity Configuration whose current keys and live participation were verified in that operation. Mount an appropriate application-owned federation metadata route if needed. The configured organization resolve endpoint must be supplied by the deployment; this package does not implement or advertise a resolver route automatically.
- `verifyFederationTrust(entityStatement, options?)` verifies current OP membership for the selected profile. Rejected federation evidence returns `trusted: false` with a bounded generic reason; timeout, cancellation, lifecycle and operational failures remain errors. Trust verification alone authenticates no user.

Original calls without profile or issuer selectors remain valid when unambiguous. No operation chooses the first entry of an ambiguous catalog.

## State, keys and canonical identity

Configure separate `stateEncryptionKeyRefs` and `stateMacKeyRefs` catalogs, each with one current reference followed by retained old references, at most eight. State encryption, MAC, federation signing and response decryption references are disjoint. The existing Crypto service supplies AES-256-GCM state envelopes and HMAC-SHA256 indexes. State and nonce contain 32 random bytes encoded as 64 hexadecimal characters. Nonce, PKCE verifier, return path and tenant hint remain encrypted; no keys are persisted in application tables.

The transactional state provider must support atomic shared one-use claims across processes. Lost write/claim acknowledgements never produce success and are not retried automatically. Bootstrap and readiness probe storage read availability and current RP participation without creating a login transaction. These probes cannot prove future write availability; every actual write and claim must independently succeed.

The mapper catalog is keyed by `tenantMappingId`. It receives only current verifier-owned upstream evidence and must return an account bound to a tenant recognized by this application's actual `AuthService.isVerifiedTenant`. Clones, foreign contexts, substituted canonical identities, changed assurance and mismatched tenant hints are rejected. Authorization is checked at runtime and proof lifetime is rechecked after asynchronous policy work. Federation assurance is returned separately from MFA assurance; it does not create an MFA factor or application session.

External PEM/PKCS#8 keys are imported as non-extractable native CryptoKeys. Public metadata exposes only public JWKs and RFC 7638 identifiers. Key material expiry and rotation are checked around use; a key changing between participation verification and protocol signing/decryption fails closed. Provider byte copies are erased without mutating provider-owned bytes. Errors retain no sensitive upstream causes.

## Verification and deployment

The [executable application and browser transaction example](../../examples/identity-spid/README.md) uses public package imports, a first-party cookie bound to protected login state, actual HTTPS callbacks and an independent packed consumer. It rejects a foreign cookie before token exchange and leaves local session creation to application policy.

If the application explicitly installs telemetry or logging, the plugin borrows those existing services. SPID telemetry is limited to `spid.handshakes` and `spid.trust.failures`, with closed `spid.operation` and `spid.outcome` labels. Begin and consume attempts are counted once, including rejections; a negative public trust verdict records a failure without changing the returned result. Internal federation HTTP/JOSE steps do not duplicate handshake counts. Debug logs contain only the operation and bounded outcome. No profile, tenant, subject, endpoint, attribute, statement, OTP, token, key reference or provider error is exported. Diagnostic sink errors cannot change authentication or state-consumption outcomes. Native SDK tests inspect actual standard and detailed telemetry exports and captured log output.

Tests exercise real JOSE signatures, native SDK request/token processing, signed SPID ID Tokens and encrypted UserInfo, actual HTTPS federation and canonical JWKS, two independent canonical security services, replay and concurrent claims, revocation, key changes, profile isolation, lifecycle and production restrictions. CIE-profile engine tests cover optional ID Token encryption and CIE assurance; the separately installed [CIE adapter](../identity-cie/README.md) owns its public registration and capability. Shared-store tests reject cross-system transaction and encrypted-record substitution while preserving the correct owner's one-use state. PostgreSQL integration tests exercise shared atomic consumption and ambiguous acknowledgements. HTTPS fixtures trust their ephemeral CA only inside an isolated child process.

Administrative accreditation, official interoperability suites, current technical-rule review and independent release acceptance remain external requirements. Consult the [Italian SPID/CIE OIDC rules](https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/index.html) and [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html).

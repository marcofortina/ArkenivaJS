# @arkenivajs/security-saml

SAML 2.0 Service Provider integration using the pinned `@node-saml/node-saml@5.1.0` backend. Supports HTTP-Redirect and HTTP-POST login requests, signed POST authentication responses, metadata and correlated logout responses for both bindings.

Configure `entityId`, `acsUrl`, `expectedAudience`, pinned offline `trustedIdpMetadata`, a secure `secretProvider` and a durable shared `replayStore`. `binding` defaults to `redirect`, `clockSkewSeconds` to zero (maximum 120), and `environment` to `production`. Test-only providers are rejected outside test. Supply `signingKeyRef` and matching `signingCertificateRef` for signed requests and SP metadata; signing is mandatory when pinned IdP metadata requires it. Keys are fetched afresh from the versioned provider, never persisted in replay records. Both references must resolve to a matching RSA key and X.509 certificate with at least 2048-bit strength and current validity.

```typescript
import { createSamlService } from '@arkenivajs/security-saml';
import type { SamlSettings } from '@arkenivajs/security-saml';

export async function begin(settings: SamlSettings) {
  const saml = createSamlService(settings);
  const transfer = await saml.beginLogin({ returnPath: '/app' }, { timeoutMs: 4000 });
  if (transfer.binding === 'redirect') return { redirect: transfer.redirectUrl };
  return { action: transfer.actionUrl, fields: transfer.fields };
}
```

`samlPlugin(settings)` provides `SAML_CAPABILITY` after application startup. It shares readiness, shutdown and optional logging/telemetry ownership with the application. A plugin definition can be reused by independent application instances. Standalone calls own temporary native workers and leave no listener or background timer after completion.

Trusted framework adapters can import `createManagedSamlAdapter` from
`@arkenivajs/security-saml/support`. Supply captured `SamlSettings`, a genuine owner
`AbortSignal` and a synchronous readiness predicate. `bootstrap()` checks external
signing material before readiness; normal service calls require readiness exactly
`true`. Invalid lifecycle inputs and callback failures deny work without retaining
provider diagnostics. The returned service uses the same native workers, durable
state and admission bounds as the ordinary factory.

`close()` stops admission immediately and waits at most five seconds. A deadline
failure does not prove that an external provider has settled. `drain()` also stops
admission irreversibly and returns the actual provider/worker settlement promise,
without a public deadline. Composing adapters must retain physical capacity until
that promise settles, including after returning a timeout to their callers. Closing
one adapter never aborts its owner's signal or another adapter. These deployment
lifecycle inputs must never come from protocol callbacks or request objects.

An optional application-owned `requestedAuthnContext` contains `classReferences`, the native SAML `comparison` (`exact`, `minimum`, `maximum` or `better`) and an explicit `acceptedClassReferences` catalog. Node-SAML places the requested classes and comparison in the signed AuthnRequest. After native signature validation, exactly one returned authentication class must belong to the captured acceptance catalog. URI text does not establish class ordering; a scheme adapter must define its approved higher/lower classes explicitly. For `exact`, the requested and accepted sets must be equal. Each catalog is nonempty, unique and limited to eight absolute HTTPS or URN references, each at most 2048 bytes. Missing or unexpected classes fail closed. The policy is immutable and contributes to the durable transaction namespace, so a different context policy cannot consume an older request. Omission preserves existing generic SDK behavior. This option supplies protocol policy, not SPID federation registration, trust or certification.

An optional `authenticationRequestProfile: { kind: 'spid', attributeConsumingServiceIndex? }`
formats authentication requests for the SPID protocol rules. It requires explicit
distinct signing key/certificate references and exactly one requested SPID L1/L2/L3
class with `exact` or `minimum` comparison. With `minimum`, the explicit acceptance
catalog must contain the requested class and only equal or higher known SPID classes;
lower or unknown classes fail configuration. `exact` retains its equal-catalog policy.
Entity and ACS identifiers must use HTTPS, and the audience must equal
the entity identifier. The native SDK supplies transient NameID and ForceAuthn for L2/L3;
the bounded adapter qualifies the issuer and removes AllowCreate before delegating
POST XML signing or Redirect query signing to that same SDK. An optional attribute
index must be an integer in 0..65535 matching registered SP metadata; the consuming
federation adapter must independently verify that registration and current membership.
The captured profile and index contribute to the replay namespace. Omission preserves
generic SAML behavior. Request formatting alone neither enables the public SPID
adapter nor establishes AgID participation, revocation status or accreditation.

For example, a scheme adapter requiring SPID level 2 or 3 can request `classReferences: ['https://www.spid.gov.it/SpidL2']`, use `comparison: 'minimum'` and explicitly accept both `https://www.spid.gov.it/SpidL2` and `https://www.spid.gov.it/SpidL3`. It must still validate all remaining scheme-specific registration, metadata, assurance and tenant requirements before returning a canonical identity. Returned generic SAML identity assurance remains `single-factor`; this option does not promote it to MFA.

The ACS must obtain its expected request ID from its own one-use browser transaction, bound to a Secure, HttpOnly cookie. Never take that expected value solely from a submitted `InResponseTo` or RelayState. Pass `{ inResponseTo: expectedId, relayState: postedRelayState }` and the encoded response to `consumeResponse`. RelayState is an opaque request locator, never a caller-selected redirect URL. The application owns return-path handling. See the [HTTPS transfer example](../../examples/saml/README.md) and [PostgreSQL authorization example](../../examples/postgres/saml.md).

Every response and assertion requires its own valid signature from a currently valid certificate in the offline IdP pin set. Verification binds the signed XML elements, issuer, request ID, audience, ACS destination, bearer recipient and time conditions. Duplicate XML IDs, DTDs, entity declarations, wrapping, unsupported signature algorithms and malformed messages fail closed. RSA-SHA256/384/512 and SHA256/384/512 digests are allowed; new SHA1 signatures are rejected. A response cannot choose its own keys or trigger a metadata fetch. Certificate rollover uses an explicitly configured overlapping pin set; removed pins cease to validate new responses. Expired metadata or an exhausted valid pin set rejects operations.

Returned identities prove an upstream issuer and subject only. Attributes remain untrusted for local authorization until the application applies its own account and tenant mapping. No canonical tenant, scope or MFA assurance is inferred. The application must authorize membership before issuing a local session. `beginLogout` additionally requires a configured `TrustedSecurityAuthority` authorizing `saml.logout` against the actual current local session, plus a matching receipt from a successful SAML login. Constructing a TypeScript object does not grant this authorization. Logout consumes protocol correlation; the application separately revokes its own local session.

`claims.saml.verificationExpiresAt` retains the earliest checked response, assertion,
bearer confirmation, session and request deadline as an ISO timestamp, with the
configured native clock skew. Composing identity adapters must recheck this deadline
before accepting downstream mapping. The service checks it again after durable
replay and session writes; expiration during persistence returns no identity and
does not make the consumed response reusable. This assertion deadline does not
replace the separate authorization and session receipt required for later logout.

`claims.saml.profile` retains bounded facts from the actually verified protocol
elements: optional assertion/response issuer formats, whether Conditions supplied
its checked NotBefore, and whether Advice was present. Generic SAML does not infer
a federation policy from these facts. A composing scheme adapter must apply its
own normative checks before mapping identity. Older persisted logout identities
without this optional metadata remain subject to the same independent authority
and exact durable session receipt; stripping it from a newer identity fails.

Replay state uses durable atomic `claimOnce` and compare-and-set calls across pods. Records contain correlation data and a digest of the verified session, without raw assertions, NameID, session index or signing keys. The native SDK cache is only an operation-local view of an already loaded durable request; it never replaces shared replay protection. Storage failures return no identity. A late persistence failure may consume the transaction and require a fresh login; it cannot authorize a retry. This is fail-closed one-use acceptance, not an exactly-once response-delivery guarantee.

Operations default to a five-second deadline, with a 30-second maximum and eight physically outstanding operations per service. Aborts terminate native XML workers; a provider ignoring cancellation retains its capacity until it settles. Plugin drain waits up to five seconds for actual work. Shared quota claims limit verification attempts to at most 1000 per profile and minute; bounded random slot contention may reject earlier. Five-minute requests and additional replay retention prevent a delayed duplicate from reusing a live transaction. There is no automatic retry of authentication work.

Input bounds: 64 KiB offline metadata, 256 KiB decoded protocol XML, depth 32, 8192 nodes, 32 attributes per XML element, eight pinned certificates, 128 SAML attributes, 32 values per attribute and 32 KiB aggregate attribute content. The supported profile uses one plaintext signed assertion, one bearer subject confirmation and one authentication statement. Encrypted assertions and IdP-initiated unsolicited authentication are not enabled by this API. Native XML signature generation and validation remain delegated to Node-SAML and its pinned dependencies.

Telemetry records aggregate `saml.operations`, `saml.operation.duration.ms` and `saml.operations.active`, with closed operation/outcome labels. Native worker output is discarded, and errors omit native causes. Assertions, names, session indices, endpoint URLs, key references and provider exceptions never become diagnostic fields.

Errors: `EK_SAML_CONFIGURATION`, `EK_SAML_SIGNATURE`, `EK_SAML_ASSERTION`, `EK_SAML_REPLAY`, plus standard cancellation, timeout, lifecycle and backend-unavailable errors. The tests exercise both bindings with actual HTTPS and native signatures, key rotation, tampering, replay, negative logout, actual PostgreSQL races between independent processes, and privacy through the actual telemetry SDK. Performance campaigns and external IdP/browser certification remain separate acceptance work.

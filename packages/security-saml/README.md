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

The ACS must obtain its expected request ID from its own one-use browser transaction, bound to a Secure, HttpOnly cookie. Never take that expected value solely from a submitted `InResponseTo` or RelayState. Pass `{ inResponseTo: expectedId, relayState: postedRelayState }` and the encoded response to `consumeResponse`. RelayState is an opaque request locator, never a caller-selected redirect URL. The application owns return-path handling. See the [HTTPS transfer example](../../examples/saml/README.md) and [PostgreSQL authorization example](../../examples/postgres/saml.md).

Every response and assertion requires its own valid signature from a currently valid certificate in the offline IdP pin set. Verification binds the signed XML elements, issuer, request ID, audience, ACS destination, bearer recipient and time conditions. Duplicate XML IDs, DTDs, entity declarations, wrapping, unsupported signature algorithms and malformed messages fail closed. RSA-SHA256/384/512 and SHA256/384/512 digests are allowed; new SHA1 signatures are rejected. A response cannot choose its own keys or trigger a metadata fetch. Certificate rollover uses an explicitly configured overlapping pin set; removed pins cease to validate new responses. Expired metadata or an exhausted valid pin set rejects operations.

Returned identities prove an upstream issuer and subject only. Attributes remain untrusted for local authorization until the application applies its own account and tenant mapping. No canonical tenant, scope or MFA assurance is inferred. The application must authorize membership before issuing a local session. `beginLogout` additionally requires a configured `TrustedSecurityAuthority` authorizing `saml.logout` against the actual current local session, plus a matching receipt from a successful SAML login. Constructing a TypeScript object does not grant this authorization. Logout consumes protocol correlation; the application separately revokes its own local session.

Replay state uses durable atomic `claimOnce` and compare-and-set calls across pods. Records contain correlation data and a digest of the verified session, without raw assertions, NameID, session index or signing keys. The native SDK cache is only an operation-local view of an already loaded durable request; it never replaces shared replay protection. Storage failures return no identity. A late persistence failure may consume the transaction and require a fresh login; it cannot authorize a retry. This is fail-closed one-use acceptance, not an exactly-once response-delivery guarantee.

Operations default to a five-second deadline, with a 30-second maximum and eight physically outstanding operations per service. Aborts terminate native XML workers; a provider ignoring cancellation retains its capacity until it settles. Plugin drain waits up to five seconds for actual work. Shared quota claims limit verification attempts to at most 1000 per profile and minute; bounded random slot contention may reject earlier. Five-minute requests and additional replay retention prevent a delayed duplicate from reusing a live transaction. There is no automatic retry of authentication work.

Input bounds: 64 KiB offline metadata, 256 KiB decoded protocol XML, depth 32, 8192 nodes, 32 attributes per XML element, eight pinned certificates, 128 SAML attributes, 32 values per attribute and 32 KiB aggregate attribute content. The supported profile uses one plaintext signed assertion, one bearer subject confirmation and one authentication statement. Encrypted assertions and IdP-initiated unsolicited authentication are not enabled by this API. Native XML signature generation and validation remain delegated to Node-SAML and its pinned dependencies.

Telemetry records aggregate `saml.operations`, `saml.operation.duration.ms` and `saml.operations.active`, with closed operation/outcome labels. Native worker output is discarded, and errors omit native causes. Assertions, names, session indices, endpoint URLs, key references and provider exceptions never become diagnostic fields.

Errors: `EK_SAML_CONFIGURATION`, `EK_SAML_SIGNATURE`, `EK_SAML_ASSERTION`, `EK_SAML_REPLAY`, plus standard cancellation, timeout, lifecycle and backend-unavailable errors. The tests exercise both bindings with actual HTTPS and native signatures, key rotation, tampering, replay, negative logout, actual PostgreSQL races between independent processes, and privacy through the actual telemetry SDK. Performance campaigns and external IdP/browser certification remain separate acceptance work.

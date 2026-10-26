# @arkenivajs/security-mtls

Optional application-owned TLS credential preparation, explicit Node TLS conversion and asynchronous peer-certificate policy verification. It uses `node:tls` and `node:crypto`, with `@arkenivajs/core` as its only runtime package dependency. Importing it creates no connection, listener or global credential store.

## Explicit setup

```typescript
import { mtlsPlugin, MTLS_CAPABILITY } from '@arkenivajs/security-mtls';
import type { MtlsService, TlsProfile } from '@arkenivajs/security-mtls';

const profile: TlsProfile = {
  trustRootsRef: 'internal-ca',
  certRef: 'service-certificate',
  keyRef: 'service-private-key',
  allowedIdentities: ['spiffe://internal.example/partner'],
  minTlsVersion: 'TLSv1.3',
  alpnProtocols: ['h2'],
  revocation: 'crl-required',
};
const plugin = mtlsPlugin({
  profiles: { service: profile },
  credentialProvider: approvedCredentialProvider,
  trustProvider: approvedTrustProvider,
  reloadMode: 'explicit',
  policy: { maxConcurrent: 8, timeoutMs: 3000 },
});
// Register plugin in createApplication, then await app.start().
const mtls = app.resolve<MtlsService>(MTLS_CAPABILITY);
const material = await mtls.createClientOptions(profile, 'partner.internal.example');
const native = mtls.toNodeClientOptions(material);
```

This snippet uses application-owned providers and bootstrap references. `MtlsCredentialProvider.load` resolves only approved profiles through secure secret infrastructure. Missing providers or unknown settings fail at construction; unavailable credentials, empty or invalid CA sets, expired material, chain-linkage errors, mismatched keys and weakened TLS/ALPN settings prevent readiness. Provider-owned buffers are copied and never cleared by the adapter.

All twelve public interfaces, `mtlsPlugin`, `MTLS_CAPABILITY` and the core `OperationOptions` type are exported. `TlsMaterial` is a byte-material contract, not a native Node options object. `toNodeClientOptions` and `toNodeServerOptions` explicitly produce the prescribed PEM fields, `rejectUnauthorized: true`, a client `servername`, and server `requestCert: true`. Strict positive and negative fixtures compile these actual converter results against the pinned `node:tls` `ConnectionOptions` and `TlsOptions` declarations.

## Two mandatory trust stages

Use the converted options with an actual Node TLS connection/server. After native certificate verification and proof of key possession succeed, obtain the peer DER from that authenticated socket and await `verifyPeer` before granting application identity or processing authorized payloads. The peer bytes must come from that trusted transport boundary, never a request body or unchecked proxy header. Verifying a public certificate alone proves neither current key possession nor ownership of an application request.

```typescript
const verified = await mtls.verifyPeer(socket.getPeerCertificate().raw, {
  trustRootsRef: profile.trustRootsRef,
  allowedIdentities: profile.allowedIdentities,
  hostname: 'partner.internal.example',
  revocation: profile.revocation,
});
// Only now map verified SANs through the application's service authorization policy.
```

The policy must match an approved profile's root reference, exact allowed-identity list and mandatory revocation mode. Native SAN-only hostname/IP checks and exact URI identities reject CN fallback and foreign peers. Configured DNS identities must be concrete hostnames, while a certificate's standard DNS wildcard is checked by the native matcher. The independent trusted provider validates the complete chain, purpose and configured CRL/OCSP/approved checker status using its approved root catalogue and issuer resolver. Its response must match the actual leaf's SHA256 fingerprint, issuer, expiry and full DNS/URI SAN metadata. Provider failure, malformed response, revocation outage, certificate expiry or mismatch rejects with `EK_MTLS_INVALID_PEER`. No provider exception message or cause is exposed.

The provider receives only the leaf DER and trusted policy, as the public contract prescribes. Its issuer catalogue or bounded resolver must be configured independently; certificate URLs are not permission for arbitrary network discovery. A provider label or TypeScript object is not proof that it verifies PKI correctly. Providers explicitly labelled `usage: 'test-only'` are rejected outside the test environment.

`allowedIdentities` authorizes certificate identities, not tenants, user sessions or arbitrary network destinations. The caller owns endpoint allowlisting and the mapping into application authority. With a service mesh, use an explicitly authenticated mesh boundary; a forwarded certificate header by itself is unsupported. Native options passed to external libraries remain sensitive escape-hatch material: mutating them or skipping the asynchronous policy check bypasses the supported flow.

## TLS, ALPN and rotation

TLS 1.3 is the default; a profile can explicitly select TLS 1.2. Older versions are rejected. A supplied ALPN list is nonempty, finite and copied exactly into native options. The adapter never selects an implicit fallback protocol. An omitted list advertises no ALPN; an application that requires negotiation must configure the list and check the socket's negotiated protocol before processing application data. The real handshake tests verify successful negotiation and native rejection of an incompatible advertised protocol.

Bootstrap loads every profile into a complete validated generation. `reloadCertificates` prepares a fresh generation with the same approved references, and publishes it only after all loads, validation and the operation deadline succeed. Failure preserves every previous profile. Overlapping reload is rejected instead of queued; a cancelled late provider cannot replace active material. Prior issued byte options become invalid for conversion after a successful reload; obtain fresh material. Already-created native options and established TLS connections are owned by their consumers and retain their previous native state. New handshakes require those consumers to install fresh options or secure contexts explicitly. Reload does not disconnect existing sessions or replace the application's revocation policy.

Converters accept only unchanged material issued by the same active service generation, rejecting manually constructed or copied objects, modified bytes and cross-role conversion. This is a runtime check, independent of TypeScript types. Every service method rejects after shutdown; cleanup clears owned cached key buffers and aborts pending provider I/O. Immutable PEM strings returned to consumers and OpenSSL's internal key copies cannot be securely erased by JavaScript; the adapter makes no stronger erasure claim.

## Bounds, privacy and verification

| Resource                            | Bound                                                                              |
| ----------------------------------- | ---------------------------------------------------------------------------------- |
| Configured profiles                 | 1–64                                                                               |
| CAs / certificates per chain        | 1–16                                                                               |
| CA or private-key input             | 64 KiB each                                                                        |
| `maxInputBytes`                     | Default and maximum 1 MiB per credential snapshot or peer input                    |
| `maxOutputBytes`                    | Default and maximum 1 MiB per operation/conversion                                 |
| Complete cached generation          | At most 16 MiB of owned credential buffers                                         |
| `maxConcurrent`                     | Required positive integer through 1024; input budget × concurrency at most 128 MiB |
| `timeoutMs`                         | Required positive integer through 120,000; caller may only reduce it               |
| Allowed identities / ALPN protocols | At most 64 / 16 per profile                                                        |

Saturation is immediate `EK_BACKEND_UNAVAILABLE`; there is no hidden queue. A provider ignoring cancellation keeps its slot until it actually settles. Byte and output limits reject rather than truncate. Credential/configuration failures use safe `EK_MTLS_CONFIGURATION`; deadlines, abort and lifecycle closure retain their common error codes.

When a telemetry plugin is explicitly installed, the existing scoped support SPI records a `mtls.verify_peer` span and fixed verification duration/status metrics. It excludes secret references, keys, PEM, SANs, subjects and fingerprints. Diagnostics cannot change a policy result or replay work.

Tests use private ephemeral CA/server/client keys, actual mutual TLS, SNI/ALPN, native mismatch rejection and an independently executed OpenSSL chain/purpose/CRL verifier. They prove that native success alone does not process authorized payloads before asynchronous verification, and cover revocation, provider outage, malformed input, runtime forgery, strict bounds, cancellation, failed rotation rollback, late reload and independent applications. No production credentials or generated certificate files are committed.

Run `pnpm --filter @arkenivajs/security-mtls build` and `pnpm --filter @arkenivajs/security-mtls test`. A production provider, executable packed consumer, measured overhead and remote release evidence require their own applicable gates; local TLS fixture success does not certify an external PKI or service mesh deployment.

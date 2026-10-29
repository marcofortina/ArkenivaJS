# @arkenivajs/security-x509

Optional certificate parsing and explicit trust verification using Node.js `crypto.X509Certificate` and `tls`. The only runtime package dependency is `@arkenivajs/core`. Certificates, subjects and SANs can contain private application information; the adapter does not log them.

```typescript
import { x509Plugin, X509_CAPABILITY } from '@arkenivajs/security-x509';
import type { X509Service } from '@arkenivajs/security-x509';

// Configure approvedTrustProvider and caDer through trusted application bootstrap.
const plugin = x509Plugin({
  trustRoots: { internal: [caDer] },
  trustProvider: approvedTrustProvider,
  policy: { maxConcurrent: 8, timeoutMs: 3000 },
});
// Include plugin in createApplication({service, plugins: [plugin]}), then start.
const certificates = app.resolve<X509Service>(X509_CAPABILITY);
const info = certificates.parse(certificatePem);
const remainingDays = certificates.daysUntilExpiry(info);
const digests = certificates.getFingerprints(info);
const validation = await certificates.inspectChain(leafFirstDerChain, {
  trustRoots: [caDer],
  expectedHostname: 'service.example',
  requireRevocationCheck: true,
});
if (validation.status !== 'trusted') throw new Error('Certificate trust was not established');
```

The snippet illustrates application-owned inputs; it is not a complete secret/trust provider. `X509PluginSettings`, all four `X509Service` methods, `OperationOptions`, `MtlsTrustProvider`, `TlsTrustVerificationPolicy` and `VerifiedPeerIdentity` are exported types. No native private-key extraction or application identity creation is exposed.

## Parsing and metadata

`parse` accepts exactly one PEM or DER certificate. Extra certificates, trailing DER data, malformed input and shared backing memory are rejected with `EK_X509_PARSE`. Node's quoted SAN representation is decoded without splitting embedded commas into forged DNS names. Metadata and SAN arrays are frozen. Parsing an expired certificate is permitted: parsing itself proves no trust. Fingerprints are lowercase hexadecimal without separators. SHA256 is always returned; SHA512 is additionally available for the same metadata object returned by this service's `parse`. Copied or externally constructed metadata has no cached SHA512 and confers no trust.

`daysUntilExpiry` returns the floor of the remaining milliseconds divided by 86,400,000, including negative values after expiry. Its optional `at` is a canonical UTC ISO instant used only for arithmetic. Trust validation uses the host clock and a monotonic operation deadline; requests cannot override that clock.

## Trust and revocation

Bootstrap snapshots and validates named nonempty CA sets. An expired or future configured root prevents readiness. Each request must name the same exact set of roots, with no duplicates; arbitrary caller roots cannot establish trust. Chain input is leaf first, followed by all required intermediates, with the root optionally included. Preliminary native linkage, signature, time and SAN hostname checks reject incomplete chains and CN-only hostname fallback. These checks do not replace complete path validation.

The configured `MtlsTrustProvider.verifyChainAndRevocation` independently verifies the entire path, key purpose and revocation against `policy.trustRootsRef`, binding the returned fingerprint, issuer, expiry and SANs to the supplied leaf DER. The provider receives the leaf only, as prescribed by the public contract: it must already have a trusted, bounded issuer-chain resolver or configured issuer catalogue. Caller intermediates and certificate URLs are not instructions to perform arbitrary network discovery. Configure the provider's root catalogue consistently with this plugin's CA sets. The application must review the provider implementation; a TypeScript object or a `production` label is not evidence of PKI verification.

The trust method retains its captured implementation and original receiver.
Callable `bind`, `name` and `length` properties are never evaluated. Proxy providers
or callbacks, accessors and prototype traversal beyond 32 levels fail configuration
validation; later method replacement does not alter the captured verifier.

This adapter always requests `approved-online-checker`, including when `requireRevocationCheck` is false; that flag never weakens the configured verifier. An omitted hostname requests chain verification only, with an empty allowed-identity list. It does not authorize an application peer or tenant. Supplying a hostname also requires a matching DNS/IP SAN. mTLS application authorization remains a separate responsibility.

Only an exact `trusted` result establishes success. Expired certificates return `expired`; invalid CA, incomplete chain, identity mismatch or mismatched provider metadata return `untrusted`. Provider denial, revocation-check outage or malformed provider output return `indeterminate`. The provider port does not expose a typed revocation-denial reason, so this adapter does not invent a definitive `revoked` classification from an exception message. Native TLS/CRL rejection is tested and never returns `trusted`. Reasons are fixed English classifications without certificate or backend details.

## Bounds and lifecycle

| Resource                   | Limit                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------- |
| Certificate PEM/DER input  | 64 KiB per certificate                                                                  |
| Chain / roots per set      | 16 certificates each                                                                    |
| Named configured CA sets   | 64                                                                                      |
| `maxInputBytes`            | Default and maximum 1 MiB; aggregate request chain plus roots, and configured DER roots |
| `maxOutputBytes`           | Default 64 KiB, maximum 1 MiB                                                           |
| `maxConcurrent`            | Required integer 1–1024; input budget × concurrency cannot exceed 128 MiB               |
| `timeoutMs`                | Required integer 1–120,000; per-call override may only reduce it                        |
| Parsed DNS/URI SAN entries | At most 256 total native SAN entries, 2048 characters per DNS/URI value                 |

Limits are validated before listeners open. Saturation fails immediately with `EK_BACKEND_UNAVAILABLE`, without a queue. Abort and timeout propagate to the provider. A provider ignoring cancellation retains its slot until it actually settles; late success is discarded. Startup and shutdown follow the owning application; reused plugin factories create independent services, and retained handles reject after close. Providers explicitly labelled `usage: 'test-only'` cannot initialize outside the test environment. Provider errors never disclose their native cause.

If a telemetry plugin is explicitly installed, the existing scoped support SPI records one `x509.inspect_chain` span, validation duration and completion status, plus a configured-CA expiry-threshold gauge. There are no subject, SAN, fingerprint, root-reference or request labels. Diagnostic failures cannot change trust outcomes. The configured-root gauge does not claim to monitor arbitrary remote endpoints.

The duration histogram uses milliseconds. Completion classes use fixed metric names such as `x509.validation.completed.trusted` and `x509.validation.completed.untrusted`; no custom label policy is needed. The CA gauge has certificate units and a fixed 30-day threshold. The actual SDK/OTLP regression test checks units, exported spans and counters, privacy and zero diagnostic drops.

## Verification and limitations

The package tests generate an ephemeral root, intermediate, leaf certificates and actual CRLs with existing OpenSSL, then verify a localhost Node TLS handshake using the pinned CA and CRLs. They cover revocation, missing intermediate, foreign CA, DNS/IP mismatch, CN-only rejection, expiry, future validity, SAN quoting, malformed/accessor input, bounded concurrency, cancellation, shutdown and cross-application isolation. No keys or generated certificates are stored in source.

Run `pnpm --filter @arkenivajs/security-x509 build` and `pnpm --filter @arkenivajs/security-x509 test`. Runtime compatibility targets the workspace's pinned Node 22, 24 and 26 versions. These local tests do not certify every external CRL/OCSP provider, public CA programme or remote service. Release campaigns and broader compatibility gates remain separate.

The [complete certificate example](../../examples/certificates/README.md) executes all public methods, a real TLS handshake and actual CRL denial, then repeats the same workflow against packed public artifacts.

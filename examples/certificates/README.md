# Certificate inspection and native revocation verification

This disposable example executes all four public operations from `@arkenivajs/security-x509`: bounded PEM/DER parsing, expiry arithmetic, SHA256/SHA512 fingerprints and explicit chain verification. It opens one loopback TLS endpoint, verifies an ephemeral leaf against its private test CA and actual CRL, rejects a foreign hostname, revokes the leaf through OpenSSL's CA database, and proves the next native TLS verification cannot return trusted.

Use the workspace's pinned Node and pnpm versions and an existing OpenSSL binary. It requires no container, external network service, operating-system installation or production credential.

```sh
pnpm install --frozen-lockfile
pnpm --filter @arkenivajs/example-certificates... build
ARKENIVA_X509_DISPOSABLE=1 pnpm --filter @arkenivajs/example-certificates start
pnpm --filter @arkenivajs/example-certificates test
pnpm test:packed:examples
```

Expected CLI output:

```json
{
  "parsed": true,
  "fingerprints": true,
  "trustedBeforeRevocation": true,
  "wrongHostnameDenied": true,
  "revokedCertificateDenied": true,
  "closed": true,
  "trustChecks": 2
}
```

`.env.example` documents the single explicit authorization flag; files are not automatically loaded. The provider is labelled `test-only`, the application environment is explicitly `test`, and the package rejects this provider in production and development. The example is a complete executable fixture, not a production PKI provider or a claim about an external OCSP responder.

Certificates and keys are created in an owner-only temporary directory. Only public certificate bytes leave the fixture closure. CA signing keys stay in that private directory; the application passes symbolic trust-set configuration and a trusted provider. Client connections pin the ephemeral root, require `rejectUnauthorized: true`, use TLS 1.2 or newer and load the actual CRL. There is no ambient system-root fallback or certificate-supplied URL discovery. The provider binds its successful response to the peer DER observed in the TLS handshake. Requests cannot choose an arbitrary endpoint, CA or identity.

The application prints only fixed outcomes and a bounded verification count. It does not print subjects, SANs, certificate fingerprints, PEM, private keys or backend errors. A revoked certificate produces a non-trusted `indeterminate` result because the provider contract deliberately exposes no typed revocation-denial reason. Parsing alone never grants trust or application identity.

Both application and fixture cleanup run in `finally`: close the capability, destroy owned TLS sockets, stop the listener, clear the application-owned private-key buffer and remove temporary files. The retained service handle rejects after shutdown. Production key erasure depends on the chosen native backend and secret provider; this example makes no stronger claim about OpenSSL's internal key copies.

The packed check installs actual `.tgz` packages outside the repository, recompiles this source and its tests against their public declarations, and executes the same native TLS and CRL workflow. See the [adapter contract and bounds](../../packages/security-x509/README.md) and [learning path](../../docs/learning-path.md).

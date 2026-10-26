# Native cryptography with externally resolved secrets

This complete disposable example exercises all six `CryptoService` operations
through the public package, using actual verified HTTPS to obtain ephemeral keys.
It requires a supported Node version, the pinned workspace dependencies and
OpenSSL for one temporary loopback certificate. Nothing is published or persisted
in the repository. The fixture is test-only and rejects implicit authorization.

```sh
pnpm build
ARKENIVA_CRYPTO_DISPOSABLE=1 pnpm --filter @arkenivajs/example-cryptography start
pnpm --filter @arkenivajs/example-cryptography test
pnpm test:packed:examples
```

The program creates a private temporary directory, certificate and HTTPS endpoint
on an ephemeral loopback port. A closed-origin `SecretProvider` trusts only that
certificate, sends an ephemeral bearer authorization and bounds binary responses
to 16 KiB. It rejects redirects, failed TLS, unknown references and aborted I/O.
The adapter obtains fresh bytes and version identifiers through that provider;
its configuration contains approved references rather than plaintext keys.

The application registers `cryptoPlugin` with explicit concurrency, deadline and
byte budgets, starts, and resolves `CRYPTO_CAPABILITY`. It encrypts with a
tenant/purpose AAD, decrypts, verifies an HMAC and an Ed25519 signature, then
rotates the encryption key. The former envelope rejects the new current key and
decrypts only through the explicitly approved previous-version reference.
The retained service rejects after shutdown. Output contains booleans and an
aggregate request count; no secret, envelope, MAC, signature or AAD is printed.

The example always closes connections/listeners, clears owned binary key and
plaintext buffers and removes its own temporary files. Its in-process reference
server and authorization token are exclusively a test fixture, not a production
secret-management system. The provider is explicitly marked `test-only`, which
the adapter rejects outside the test environment. For production, inject an
independently reviewed external secret provider with strong access control,
verified TLS, version retention, revocation and bounded cancellation. A label
alone provides no security guarantee.

Handle `EK_CRYPTO_AUTH_FAILED` as authenticated-decryption failure with no usable
plaintext. `EK_CRYPTO_KEY_UNAVAILABLE` denies missing/expired/unapproved versions.
`EK_CRYPTO_FORMAT` rejects malformed inputs and unsupported algorithms. Aborts
and timeouts return `EK_ABORTED`/`EK_TIMEOUT`; provider saturation uses
`EK_BACKEND_UNAVAILABLE`. Do not retry non-idempotent application work on those
failures. See the [adapter contract and envelope format](../../packages/security-crypto/README.md).

CI also compiles and runs this guide against actual packed framework archives,
so private source imports or workspace symlinks cannot satisfy its acceptance.

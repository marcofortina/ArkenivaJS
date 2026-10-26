# @arkenivajs/security-crypto

Experimental optional adapter for Node's native AES-256-GCM, HMAC-SHA256,
Ed25519 and P-256 implementations. This package is private and has not completed
its release acceptance gates.

Configure `cryptoPlugin(settings)` explicitly and obtain `CryptoService` with
`app.resolve<CryptoService>(CRYPTO_CAPABILITY)` after startup. The factory rejects
unknown fields, accessors, missing providers, invalid references and unbounded
policies before opening resources. Each application owns separate admission and
shutdown state, even when a plugin factory is reused.

`secrets.get(ref, options)` must be an independently reviewed external secret
provider. Its returned bytes have a nonempty immutable `keyVersion` and optional
canonical ISO expiry. No key is embedded in configuration, retained in an
application database or logged. Startup checks every configured reference;
operations resolve fresh material so revoked or expired keys fail closed.
Providers explicitly marked `usage: 'test-only'` reject outside the test
environment. A production label is not proof of provider security or review.
Encryption references resolve exactly 32 bytes. Signing/HMAC references resolve
32–16,384 bytes. Signing uses DER PKCS#8 private keys; verification accepts DER
SPKI public keys. Only Ed25519 and P-256 are accepted, with 64-byte Ed25519 or
IEEE-P1363 ECDSA signatures. HMAC is always SHA256 with a full 32-byte result.
Use independent references for encryption, HMAC and asymmetric signing.

Encryption produces an envelope containing version 1, algorithm AES-256-GCM,
the provider's key version, a fresh 12-byte CSPRNG nonce, ciphertext and a 16-byte
authentication tag. Supply authenticated tenant/purpose bytes as AAD on both
encryption and decryption. GCM additionally authenticates envelope metadata:
two unsigned 32-bit big-endian lengths for the metadata and caller AAD, followed
by UTF-8 `JSON.stringify([1,'AES-256-GCM',keyId])` and the caller AAD. Persist
every binary field losslessly. Tampering returns `EK_CRYPTO_AUTH_FAILED` and no
plaintext; malformed versions/algorithms use `EK_CRYPTO_FORMAT`.

The envelope's `keyId` is a version, never an instruction to fetch an arbitrary
reference. To decrypt an old version, select an explicitly allowed version-specific
reference whose provider result has that exact `keyVersion`. Keep required old
versions available for the retention window. Missing, expired, denied or mismatched
versions use `EK_CRYPTO_KEY_UNAVAILABLE`. This adapter does not export or emulate
non-exportable KMS/HSM operations; those require their dedicated provider.

`policy` requires integer `maxConcurrent` (1–1024) and `timeoutMs` (1–120,000).
`maxInputBytes` defaults to one MiB, maximum 16 MiB; combined plaintext/ciphertext
and caller AAD must fit. Configured concurrency times input allowance must not
exceed 128 MiB. `maxOutputBytes` defaults to input allowance plus the 28 nonce/tag
bytes, maximum 16 MiB plus 28. Encryption counts those 28 bytes; decryption counts
plaintext; MAC/signature output budgets are checked before secret retrieval.
Provider keys and public keys are independently limited to 16 KiB.

Operations accept positive integer deadlines up to the configured timeout and
native `AbortSignal`. Zero, null and unknown options fail before I/O. Saturation
rejects immediately with `EK_BACKEND_UNAVAILABLE`, with no queue. An uncooperative
provider retains its slot until it settles; timeout/abort never authorizes late
cryptographic success. Shutdown aborts owned work and retained handles reject
with `EK_RESOURCE_CLOSED`. Providers must honor the supplied signal/deadline.
Bounded synchronous native cryptography cannot be preempted; elapsed deadlines
are checked before returning a result.

Inputs are copied before awaiting providers, shared backing memory is rejected,
and owned temporary key/plaintext buffers are cleared. Native key-object memory
remains under Node/OpenSSL management; JavaScript does not promise complete
secure-heap erasure. No operation logs plaintext, key material, AAD, MACs or
signatures. Protect returned secret bytes and clear them when no longer needed.

Native API reference: [Node.js cryptography](https://nodejs.org/docs/latest-v22.x/api/crypto.html).
Known MAC vectors: [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html).
Run all six operations with verified HTTPS secret retrieval using the
[complete disposable example](../../examples/cryptography/README.md).

# Changelog

## 0.1.0

- Bind fresh SAML registry state to the exact entity, current pinned XML signing
  authority and matching native X.509 certificates. Validate RP POST registration,
  bound freshness and retire older evidence after failed refresh or withdrawal,
  including concurrent verification. Public SAML authentication remains incomplete.
- Verify bounded SAML metadata signatures in owned native workers, retaining shared
  admission until physical termination and rejecting copied or expired signature
  evidence. Signature validation does not establish current registry participation.
- Retrieve explicit SAML registry JSON locations through the existing bounded HTTPS
  transport with strict media types, fresh requests and shared admission. Reading
  a status document does not establish active participation or enable SAML.
- Capture federation provider functions without inspecting executable `name`,
  `length` or `bind` properties; preserve the original receiver and method snapshot.
- Capture explicit metadata/status sources for the SP and every configured SAML
  IdP, restricted to approved HTTPS destinations and without provider I/O or discovery.
- Retrieve bounded SAML metadata through the existing exact-approved HTTPS transport,
  without credentials, redirect discovery, caching or stale fallback. Retrieval
  alone grants no federation trust or protocol activation.
- Add a bounded native XML signature primitive for SPID SAML metadata, with pinned
  current RSA roots, verified-reference extraction and wrapping/downgrade defenses.
  Current participation and the SAML authentication flow remain independently gated.
- Capture an explicit SPID SAML signing certificate reference, separate from
  private/state keys and unavailable to OIDC or CIE profiles. SAML runtime remains gated.
- Expose trusted Italian adapter composition through the documented support entry while retaining the fixed SPID facade and independent CIE registration.
- Keep CIE duration/check/failure observations separate from SPID counters and prevent executable error properties from entering diagnostic classification.

- Separate SPID/CIE application assurance and protected-state families while reusing the native Italian OIDC wire references; reject CIE-only ID Token encryption in SPID configuration and callbacks.
- Verify signed SPID ID Tokens in public HTTPS consumers and optional encrypted ID Tokens in private CIE-profile engine tests, including cross-system state and encrypted-record substitution denial.

- Borrow explicitly installed observation services and export only bounded SPID handshake/trust-failure counters, with safe operation outcomes and real SDK privacy tests in both telemetry modes.

- Define versioned federation profiles, approved mapping and provider contracts, with immutable policy capture and safe configuration validation.
- Verify bounded signed federation statements using JOSE, with issuer/subject/kid checks, temporal and public-key restrictions, without treating signature evidence as a complete federation trust decision.
- Merge and apply bounded federation metadata policies with standard operator order, conflict rejection, entity-type isolation and Italian object-valued JWKS rules.
- Retrieve approved HTTPS entity statements and signed trust-mark status documents through the existing bounded HTTP client, with exact paths, native TLS, safe errors and credential isolation.
- Verify owned signed trust marks and fresh signed status bound to the exact mark, reject inactive or ambiguous evidence, and exercise the checks over actual HTTPS.
- Apply metadata parameter policies only within existing entity types, preventing defaults from creating unrelated roles or bypassing type constraints.
- Own federation provider and native work through physical settlement, with shared admission, one deadline, readiness enforcement and bounded shutdown.
- Verify explicit pinned federation paths, delegated key rotation, inherited expiry, independent path/name/type constraints and ordered metadata resolution, returning owned signature/policy evidence for subsequent live membership validation.
- Resolve approved federation configuration graphs within cumulative discovery budgets and a shared deadline, with operation-local document caches, full pinned verification for every selected path and actual HTTPS fixtures.
- Validate role-specific live federation participation, exact anchor authorization of trust-mark issuers, same-anchor external issuer chains and current delegated keys, with bounded fresh signed status and owned expiry-limited evidence.
- Protect single-use login state with the existing native Crypto service, separate explicit external encryption/MAC references, immutable profile binding, shared atomic consumption and cleanup of late plaintext; test actual PostgreSQL races and ambiguous acknowledgements.
- Encode login state and nonce as 64 hexadecimal characters from 32 random bytes, satisfying the Italian alphanumeric requirement while preserving URL-safe PKCE verifiers.
- Load approved external signing keys as non-extractable native CryptoKeys, enforce expiry and algorithm/key compatibility, and verify JOSE signatures and actual OpenID Client JAR generation with RFC 7638 public key identifiers.
- Bind raw and policy-resolved OpenID Provider/OAuth issuer metadata to the verified Entity Identifier, rejecting missing, replaced or foreign issuers despite otherwise valid signatures.
- Capture typed application-owned OIDC RP registration metadata, current subject-bound mark candidates, explicit algorithms and separate external decryption references without inventing registration values or claiming accreditation.
- Import separate external RSA response-decryption keys as non-extractable native CryptoKeys, reuse guarded key import and verify prescribed JWE combinations and signed encrypted UserInfo with the selected OpenID Client.
- Sign bounded RP Entity Configurations with native JOSE, exact immutable registration, public signing/encryption key roles and expiry limited by received marks, external key material and metadata refresh policy.
- Compose fresh federation membership and protected transactions with native OpenID Client JAR initiation, exact issuer/assurance, S256 PKCE, matching outer request parameters and configured UserInfo claims; deny revoked trust and failed persistence before returning redirects.
- Require exact approved protocol endpoints and adapt native OpenID Client fetch requests to bounded HTTPS without credential forwarding, redirects, code-exchange retries, streaming bodies or malformed UTF-8; verify actual TLS and production private-network rejection.
- Verify native OIDC callbacks after atomic state consumption, fresh federation trust and private-key JWT exchange, with independent ID Token/UserInfo encryption, signatures, nonce, PKCE, Access Token binding, assurance and expiring verifier-owned upstream evidence.
- Resolve inline, approved remote and federation-signed protocol JWK sets with current delegated keys, exact issuer/type, exchange-local caches, private-material rejection and bounded optional signed-set timestamps without relaxing other federation token requirements.
- Map owned OIDC evidence through the captured policy, actual application AuthService tenant provenance and explicit canonical authorization, rejecting cloned or foreign contexts, altered identities/assurance and expired evidence without inferring MFA assurance.
- Verify the configured RP's own delegated federation keys, role-specific accreditation and live revocation independently from OP trust, and reject resolved security metadata that changes the approved registration.
- Expose the explicit application-owned SPID OIDC plugin, immutable profile and issuer selection, readiness/storage bootstrap and lifecycle cleanup; compose current RP/OP membership, native protocol verification and canonical tenant authorization through the public service.

# Changelog

## 0.1.0

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

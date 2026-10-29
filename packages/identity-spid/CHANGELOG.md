# Changelog

## 0.1.0

- Define versioned federation profiles, approved mapping and provider contracts, with immutable policy capture and safe configuration validation.
- Verify bounded signed federation statements using JOSE, with issuer/subject/kid checks, temporal and public-key restrictions, without treating signature evidence as a complete federation trust decision.
- Merge and apply bounded federation metadata policies with standard operator order, conflict rejection, entity-type isolation and Italian object-valued JWKS rules.
- Retrieve approved HTTPS entity statements and signed trust-mark status documents through the existing bounded HTTP client, with exact paths, native TLS, safe errors and credential isolation.
- Verify owned signed trust marks and fresh signed status bound to the exact mark, reject inactive or ambiguous evidence, and exercise the checks over actual HTTPS.
- Apply metadata parameter policies only within existing entity types, preventing defaults from creating unrelated roles or bypassing type constraints.
- Own federation provider and native work through physical settlement, with shared admission, one deadline, readiness enforcement and bounded shutdown.

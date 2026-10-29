# @arkenivajs/identity-spid

Optional Italian SPID federation contracts and validated profile policy. This package currently supplies the configuration foundation; it does not expose an operational authentication service or plugin yet. No login, federation verification, interoperability or accreditation is claimed.

Profiles pin registration, expected issuers, trust-anchor public keys and validity windows, metadata endpoints, required revocation and stale-metadata rejection, assurance levels, mapping identifiers and session lifetime. Configuration is captured as immutable data. The approved mapper catalog is keyed by `tenantMappingId`; each immutable profile binds its `identityMappingVersion` and profile ID to that configured mapping. Unmatched catalog entries are rejected.

The private policy capture rejects executable data properties, proxy inputs, malformed public keys, absent transactional store methods, insecure metadata URLs, cross-system assurance and missing providers. Parsing a public trust key does not establish federation trust. Cryptographic trust-chain, metadata-policy, dynamic revocation, protocol and identity checks belong to the authentication implementation and its independent tests.

Protocol integration uses the selected SAML/OIDC libraries. Technical rules and external conformance remain separate requirements: [Italian SPID/CIE OIDC rules](https://docs.italia.it/italia/spid/spid-cie-oidc-docs/it/versione-corrente/index.html).

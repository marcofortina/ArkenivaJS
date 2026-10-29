# Changelog

## 0.1.0

- Retain the native verified assertion deadline and reject expiry during durable
  persistence, preserving separately authorized logout after assertion expiration.
- Preserve canonical origin-only HTTPS EntityIDs exactly in SPID Redirect and POST
  signatures while validating their URL form independently of endpoint settings.
- Capture trusted provider functions without executing custom bind/name/length
  properties, while preserving their original receiver and implementation.
- Expose trusted adapter composition through the support entry, retaining native
  readiness/owner cancellation and a physical drain beyond bounded close deadlines.
- Add an explicit signed SPID authentication-request profile with transient NameID,
  qualified issuer, level-bound ForceAuthn and registered attribute indexes, applied
  before the pinned native SDK signs either binding. Federation participation and
  complete SPID authentication remain separate adapter checks.
- Capture explicit requested and accepted authentication-context policy, delegate signed request construction to Node-SAML, reject unapproved signed assertion classes and isolate durable requests across policy changes.

- Add native SAML Service Provider login, metadata and controlled logout for Redirect and POST bindings.
- Enforce pinned XML signatures, durable correlation and replay claims, independent logout authorization, bounded cancellable native workers and private aggregate diagnostics.
- Add executable HTTPS transfer examples and shared PostgreSQL concurrency tests.

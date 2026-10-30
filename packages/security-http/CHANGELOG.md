# Changelog

## 0.1.0

- Verify bounded header/provider policies, corrupted CSRF persistence, native
  registration and middleware failures, browser nonce renewal and operation ownership.
- Capture configured providers without evaluating callable metadata, retaining
  original receivers and rejecting proxies before classification or CSRF authorization.
- Add validated CSP, HSTS, framing and referrer headers through native Fastify/Helmet.
- Add runtime-authorized, tenant/session-bound CSRF through the native Fastify CSRF engine and shared state.
- Select cookie routes explicitly and retain normal bearer-only API behavior.
- Add exact-origin checks, trusted proxy awareness, finite deadlines and owned provider cleanup.
- Add real HTTPS, SDK privacy and PostgreSQL session/revocation consumers.

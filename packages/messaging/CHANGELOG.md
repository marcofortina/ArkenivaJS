# Changelog

## 0.1.0

- Capture the original error strategy without executable callable metadata and
  reject proxied or accessor-based policy inputs before opening resources.
- Add explicitly installed Core NATS messaging with verified TLS and scoped subjects.
- Bound operation admission, retained bodies, subscriptions and handler/error work.
- Preserve uncertain publication outcomes without automatic replay; restore future subscriptions through native reconnect.
- Validate immutable JSON envelopes without accepting wire tenant identity.
- Integrate startup health, graceful drain, processing spans and independent tenant accounting.
- Correct two upstream optional TypeScript declarations without modifying SDK runtime code.

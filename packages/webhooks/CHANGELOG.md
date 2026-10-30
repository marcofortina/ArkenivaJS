<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Changelog

## 0.1.0

- Verify malformed authority/key results, uncertain nonce acknowledgements, deployment bounds and JSON resource limits; include actual SDK export privacy and PostgreSQL replay protection after restart.
- Preserve configured secret, authority and nonce callbacks without executable
  function metadata; reject proxy callbacks and prototype inspection.
- Add native versioned tenant-bound HMAC, constant-time verification and atomic durable nonce ownership.
- Add fixed-destination HTTP delivery, connect-time CIDR enforcement, verified TLS, documented idempotency gating and bounded native DNS/provider ownership.
- Add explicit retained-key references and scoped runtime authorization metadata without changing core authentication or storage algorithms.

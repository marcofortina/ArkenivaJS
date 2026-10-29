<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Changelog

## 0.1.0

- Capture configured provider methods without evaluating callable metadata, and
  reject proxy callbacks and unbounded traversal before authorization or state work.
- Add native outgoing OAuth2/OIDC grants with PKCE, exact registration policy and runtime application authorization.
- Add encrypted distributed state, one-use references, refresh rotation, family revocation and bounded owned shutdown.
- Add signed-provider adversarial tests and verified-HTTPS PostgreSQL consumer scenarios.

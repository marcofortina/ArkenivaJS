<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Outgoing OAuth grants with durable PostgreSQL state

The [configuration composition](src/oauth-client.ts) keeps the external secret provider, exact issuer registration, PostgreSQL transactional state and trusted application authority explicit. Install the separate crypto and OAuth plugins alongside logging. No raw client secret, state key or refresh token belongs in configuration files, SQL plaintext, logs or telemetry.

The executable scenarios use an owned HTTPS authorization server and real PostgreSQL. A separate signed OIDC identity establishes the local account and tenant; `authority.require` revalidates that current primary session and its `oauth:manage` permission for every OAuth operation. The outgoing grant never authenticates a local session by itself. Two applications use independent SQL pools against one fresh disposable security schema and the same externally held keys.

After a frozen install and workspace build, run the existing private PostgreSQL environment loader around this fixture wrapper:

```sh
python3 packages/security-oauth-client/test/fixtures/run.py --test-only -- pnpm --filter @arkenivajs/example-postgres test:integration
python3 packages/security-oauth-client/test/fixtures/run.py --test-only -- pnpm test:packed:examples --integration postgres
```

The wrapper creates a private temporary CA, a verified HTTPS test server and mode-0600 registration metadata outside the checkout. It adds that CA through Node's startup trust setting, preserves the explicit PostgreSQL fixture variables and closes its owned server on completion. OpenSSL and the supported Node release must already be installed. Database containers run only in the dedicated integration VM or disposable CI runner. This test fixture is not a production authorization server.

The three scenarios verify one-use PKCE exchange across independent pools, encrypted state without plaintext grant secrets, refresh after application restart, competing refreshes, spent-reference family invalidation, foreign-tenant denial, primary-session revocation, external-key outage and actual SQL table unavailability. Run both supported PostgreSQL versions on every supported Node line. Missing OAuth or PostgreSQL infrastructure fails explicitly.

The complete PostgreSQL integration suite now needs the owned OAuth wrapper in addition to its database loader. Ordinary offline example tests remain service-independent. The [adapter reference](../../packages/security-oauth-client/README.md) describes all parameters, limits, errors and the distinction between local durable acknowledgement and an unknown upstream token outcome.

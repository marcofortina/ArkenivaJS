<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Verified enterprise directory consumer

`runLdapExample` composes the public LDAP plugin with core, Pino and the actual OpenTelemetry SDK. It looks up an employee, verifies a fresh isolated password bind and resolves nested groups. Its private loopback metric receiver checks that directory data and credentials do not appear in diagnostics. The example explicitly requires the test environment; directory certificate verification remains enabled.

The normal `pnpm --filter @arkenivajs/example-ldap test` includes the fail-closed provider scenario. With `ARKENIVA_LDAP_FIXTURE` pointing to private metadata from the owned OpenLDAP fixture, `test:integration` additionally verifies real authentication, group membership and exported metric names. The same suite runs against packed artifacts using `pnpm test:packed:examples --integration ldap`. Do not commit the metadata, passwords or private certificates. Run container commands only in the dedicated integration VM or an isolated CI runner.

The returned authentication boolean supplies no session, tenant authorization or MFA assurance. Bind the verified directory identity to the application's trusted account and tenant policy before creating a session. See [the adapter contract and limits](../../packages/security-ldap/README.md).

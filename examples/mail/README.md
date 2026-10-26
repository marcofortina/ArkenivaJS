<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Secure native SMTP example

Build the framework, then run `pnpm --filter @arkenivajs/example-mail build` and
`pnpm --filter @arkenivajs/example-mail start`. OpenSSL must be available for the
ephemeral fixture certificate. The program starts a disposable loopback SMTP sink
and SDK collector, verifies STARTTLS/authentication, sends one bounded message with
a binary attachment, parses its actual MIME, flushes safe logs/metrics and cleans
all owned processes, listeners and temporary private key files.

Expected output contains `transportVerified: true`, `accepted: 1`, `messages: 1`
and true attachment/HTML/observation/privacy flags. It never sends to an external
SMTP server, installs a system service or changes the laptop trust store. The
separate client process trusts only the fixture's added ephemeral startup CA;
certificate/hostname validation remains enabled. Disposable credentials are fixture
data and must be replaced by a production secret provider in an actual application.

Run `pnpm --filter @arkenivajs/example-mail test` for the public API and executable,
or `pnpm test:packed:examples --example mail` for a separate packed installation.
See the [package guide](../../packages/mail/README.md) for strict bounds, profiles,
stream ownership, secret rotation and uncertain SMTP delivery semantics. Performance
and remote compatibility remain independent release acceptance gates.

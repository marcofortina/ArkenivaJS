<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Authenticated streaming upload example

Run from the workspace with its pinned Node.js and pnpm toolchain:

```sh
pnpm --filter '@arkenivajs/example-upload...' build
pnpm --filter @arkenivajs/example-upload start
pnpm --filter @arkenivajs/example-upload test
pnpm test:packed:examples --example upload
```

The executable opens owned loopback OIDC, HTTP and OpenTelemetry collector fixtures. It creates an ephemeral ES256 signing key in memory, sends an authenticated multipart request containing one six-byte binary attachment, then verifies that an unauthenticated request receives 401. It does not persist the file. Its declared PDF MIME type is an unverified assertion, deliberately independent of the binary content.

Expected output:

```json
{
  "accepted": 200,
  "denied": 401,
  "files": 1,
  "bytes": 6,
  "wireBytesVerified": true,
  "tenantVerified": true,
  "logsPrivate": true,
  "metricsObserved": true,
  "metricsPrivate": true,
  "meterObserved": true,
  "meterPrivate": true
}
```

The forged tenant header cannot change the issuer-verified tenant. Pino output and real OTel exports exclude token, filename and field content. The real metering service produces one event under the verified tenant with actual multipart body bytes and a single request count; its disposable exporter acknowledges the batch in memory. These flags verify observed behavior rather than production persistence or exporter durability.

The example closes every owned listener and application resource on completion. It requires no external credentials, database or system service. Loopback HTTP is allowed only for this test fixture; configure trusted HTTPS/OIDC and scoped authorization for a deployed application. Independent package integration tests also exercise verified direct HTTPS and HTTP/2 without disabling certificate checks.

The packed check installs the framework archives outside the workspace and compiles/runs this consumer exclusively through public exports. It does not publish packages or execute performance campaigns.

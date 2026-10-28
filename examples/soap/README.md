<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# SOAP inventory consumer

Run `pnpm --filter @arkenivajs/example-soap start` after building the workspace.
The disposable example creates a local native SOAP server over verified HTTPS,
resolves Basic authentication and CA material through an explicitly test-only
provider, invokes the compiled public capability, and closes every owned resource.
It requires the existing OpenSSL executable and writes temporary private files
only beneath an owned directory that is removed on close.

For an application, call `runSoapExample` with trusted offline WSDL profiles and a
secure secret provider. The environment defaults to production; the disposable
provider is rejected in production. Keep precise per-WSDL application types and
business validation at the application boundary. A generic result type alone does
not validate an arbitrary business schema.

The tests also exercise the actual logging and OpenTelemetry SDK exporters.

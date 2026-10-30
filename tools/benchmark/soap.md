<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native verified-HTTPS SOAP interoperability

Build the complete workspace, including compiled SOAP conformance fixtures, make
OpenSSL available and choose a fresh absolute external report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation soap --verify /private/soap-verification
```

Four isolated profiles compare pinned node-soap/Axios with the public SOAP
service and actual standard/detailed SDK instrumentation. The tool reuses the
independently authored compiled conformance WSDL. An actual native SOAP server
runs over verified HTTPS with an ephemeral P-256 certificate in an owned private
directory. Trust is supplied only to each owned client; no global trust changes.

Each profile invokes the approved operation twice with distinct Unicode string
inputs retaining leading zeros. Checks verify actual native client identity,
operation description, decoded numeric result, actual HTTP status and distinct
correlation identifiers. The independent server must observe all eight expected
calls. Native wrong-hostname and public untrusted-CA tests follow healthy controls;
the server must receive no application calls from rejected connections. Foreign
endpoints and request transport overrides are rejected before I/O.

The native baseline uses the same reviewed upstream patches, native WSDL loader,
serializer, response decoder and explicit Axios HTTPS agent. It omits framework
immutable WSDL capture/import allowlists, complete input/scalar/fault policy,
bounded parser isolation, admission and lifecycle checks. This small
document/literal SOAP 1.1 workload does not establish SOAP 1.2, RPC, WS-Security
or arbitrary contract equivalence. Reports and SDK exports exclude payloads,
WSDL paths and endpoint data. Clients close before worker acknowledgment, and
the parent closes the server before removing its exact private directory.

Only `--verify` is supported. Sampling is rejected before fixture allocation
until complete parser/server resource accounting is available. Reports retain
`releaseGate: false`; dedicated-runner budgets, five paired repetitions and
one-hour soak acceptance remain separate work.

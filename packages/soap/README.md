<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# SOAP native foundations

This private package defines the optional SOAP client contracts and vets the
approved node-soap 1.14.0 backend. A runtime capability is not yet exported.
The adapter must retain actual native client identity, bounded offline WSDL
assets and explicit SOAP 1.1/1.2 profiles. Generic TypeScript result types do not
automatically validate arbitrary business schemas.

The internal compiler and decoder use the real node-soap implementation. A
separate native SAX admission check rejects DTDs, external entities, malformed
namespaces, prototype-sensitive names and collisions with native client methods.
The internal asset loader captures a trusted local WSDL and its bounded relative
WSDL/XSD imports beneath that file's directory. It rejects symlinks, writable
shared files, malformed UTF-8, external locations, path escapes and import cycles.
The graph allows at most 32 files, 1 MiB per file and 8 MiB in total. Relative
import names use ASCII letters, digits, underscores, dots, slashes and hyphens;
URL encoding, query strings and fragments are unsupported. Imports may traverse
parent directories only while remaining within the approved root.

The immutable captured documents populate the actual native cache in dependency
order. Native import hooks admit only already compiled captured entries. A cache
miss fails explicitly; neither URL fetches nor implicit filesystem includes are
allowed. Compilation still works after original source assets are removed.

The owned decoder worker enforces XML size, depth, element and attribute limits,
SOAP envelope version, finite deadlines and a fixed output ceiling. The worker
has bounded V8 memory, a restricted environment and captured diagnostic streams.
Timeout and shutdown terminate the actual thread; a retired worker is never
silently restarted. Native fault details and private response bodies are not
included in public errors. The worker checks SOAP XML before invoking the native
decoder, preventing its JSON fallback from admitting a non-SOAP response.

The internal HTTPS transport uses the same reviewed Axios version as node-soap,
through an isolated native client and Node HTTPS sockets. It owns one fixed HTTPS
endpoint, captures at most 16 startup DNS addresses and permits native connection
selection only among those addresses. It verifies TLS 1.2 or later, supports an
explicit CA and client certificate, disables proxies, redirects and automatic
response decompression, and applies finite body and concurrency limits. Absolute
deadlines cancel real work even during a continuously active slow response.
Close awaits physical socket cleanup; owned private-key copies are cleared.
Uncertain submitted failures report an unknown outcome and are never retried.
Native OS DNS lookup is not cancelable; lifecycle owners must retain initialization
reservations until that work actually settles.

These foundations have native document/literal, RPC/literal, SOAP 1.1/1.2,
malicious XML, real HTTPS/mTLS, cancellation and lifecycle tests. Managed service
wiring, secret-provider credentials and the plugin runtime remain in development;
this package does not yet provide a usable managed client service.

The compatibility patch changes only the obsolete `dev-null@0.1.1` license
metadata object to its existing MIT SPDX identifier. Upstream JavaScript and
license text remain unchanged; the complete MIT notice is retained in
`THIRD_PARTY_NOTICES.md`.

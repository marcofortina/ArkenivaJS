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
WSDL admission currently permits self-contained offline documents only; imports
fail explicitly until the registered asset graph is implemented. Neither URL
fetches nor implicit filesystem includes are allowed.

The owned decoder worker enforces XML size, depth, element and attribute limits,
SOAP envelope version, finite deadlines and a fixed output ceiling. The worker
has bounded V8 memory, a restricted environment and captured diagnostic streams.
Timeout and shutdown terminate the actual thread; a retired worker is never
silently restarted. Native fault details and private response bodies are not
included in public errors. The worker checks SOAP XML before invoking the native
decoder, preventing its JSON fallback from admitting a non-SOAP response.

These foundations have native document/literal, RPC/literal, SOAP 1.1/1.2,
malicious XML, cancellation and lifecycle tests. Managed HTTPS transport,
credentials, offline asset graphs and the plugin runtime remain in development;
this package does not yet provide a usable managed client service.

The compatibility patch changes only the obsolete `dev-null@0.1.1` license
metadata object to its existing MIT SPDX identifier. Upstream JavaScript and
license text remain unchanged; the complete MIT notice is retained in
`THIRD_PARTY_NOTICES.md`.

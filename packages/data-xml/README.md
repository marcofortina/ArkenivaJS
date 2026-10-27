<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Bounded native XML codec

`dataXmlPlugin(settings)` explicitly registers `XML_CAPABILITY`. Its XML 1.0
UTF-8 parser and writer use fast-xml-parser 5.11.2, with native SAX validation
before tree allocation. Construction captures settings without filesystem access
or worker creation. Calls require a ready application and execute in finite
workers; application stop terminates and awaits owned workers.

The external XSD adapter gate is not enabled in this component. For a registered
schema ID, `validateXsd()` returns `EK_UNSUPPORTED_CAPABILITY`; unknown IDs return
`EK_XML_SCHEMA`. XML well-formedness is never reported as XSD acceptance. Do not
treat this partial package as a production-ready XML/XSD integration.

## Configuration and document shape

Supply typed `defaults`, `policy` and optional `xsdSchemaFiles`, which maps trusted
schema IDs to normalized absolute offline paths. Defaults are 1 MiB input, depth
64, 4096 total attributes and preserved namespace prefixes. Limits are at most
16 MiB per input/output, depth 256, 65536 attributes, eight concurrent operations
and 30 seconds per call. The aggregate configured input/output admission budget
cannot exceed 128 MiB. Saturation fails immediately with `EK_XML_SECURITY`.
Unknown fields, null optional values, accessors and insecure parser options fail
before worker allocation. DTDs and external entity resolution cannot be enabled.

`XmlDocument.root` is one ordered native element node. Its element name maps to
an ordered array of child nodes. `:@` holds string attributes prefixed with `@_`;
`#text`, `#comment` and `#cdata` preserve mixed content without numeric coercion:

```typescript
const document = await xml.parse('<r id="001">before<c/>after</r>');
// document.root has the following shape:
// { r: [{ '#text': 'before' }, { c: [] }, { '#text': 'after' }],
//   ':@': { '@_id': '001' } }
const output = await xml.stringify(document);
```

With `namespaceMode: 'expanded'`, names use `{namespace-uri}local` while namespace
declarations remain explicit attributes. Unqualified attributes retain their own
unqualified names. The writer resolves expanded names through retained namespace
declarations; an unbound name fails instead of erasing its namespace. The snapshot
rejects unsafe object properties and the output must roundtrip through the actual
native parser before it is returned. Root-external declaration/whitespace metadata
is not part of the root element representation.

## Security, cancellation and fidelity

SAX preflight rejects DTD/XXE, undeclared entities, malformed namespace bindings,
invalid UTF-8, unsupported encodings, oversized inputs and depth/attribute
overflow. Comments and CDATA containing DTD-like literal text remain valid.
JavaScript prototype property names cannot be silently renamed. Constructed
trees cannot inject element markup through names, attributes, comments or CDATA.

Arbitrary processing instructions are explicitly unsupported because the native
ordered builder cannot preserve their data faithfully. Other values that cannot
roundtrip faithfully are rejected; there is no silent coercion or output truncation.
Only the root element and its ordered descendants are returned, with frozen owned
records/arrays and preserved strings.

Workers receive no inherited process preloads or application environment. Each
worker has fixed V8 heap/stack limits and bounded output. Positive deadlines and
genuine AbortSignals stop work; admission remains occupied until the worker
actually exits. Errors expose fixed English messages and codes rather than
document text or native diagnostics.

## Verification

Build before running tests:

```sh
pnpm --filter @arkenivajs/data-xml build
pnpm --filter @arkenivajs/data-xml typecheck
pnpm --filter @arkenivajs/data-xml lint
pnpm --filter @arkenivajs/data-xml test:unit
```

Tests use actual native parsers/builders and workers, including namespace
rebinding, ordered mixed content, malicious data, size boundaries, cancellation,
deadline, admission, environment isolation and explicit XSD unavailability.

<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Bounded native XML codec

`dataXmlPlugin(settings)` explicitly registers `XML_CAPABILITY`. Its XML 1.0
UTF-8 parser and writer use fast-xml-parser 5.11.2, with native SAX validation
before tree allocation. Construction captures settings without filesystem access
or worker creation. Calls require a ready application and execute in finite
workers; application stop terminates and awaits owned workers.

`validateXsd()` uses a separately vetted libxml2 engine for XSD 1.0. Without the
reviewed external backend it raises `EK_UNSUPPORTED_CAPABILITY`; unknown schema
IDs raise `EK_XML_SCHEMA`. XML well-formedness is never reported as schema
acceptance. The [compiled public example](../../examples/xml/README.md) exercises
actual validation, offline imports and SDK diagnostics through installed archives.

## Configuration and document shape

Supply typed `defaults`, `policy` and optional `xsdSchemaFiles`, which maps trusted
schema IDs to normalized absolute offline paths. Defaults are 1 MiB input, depth
64, 4096 total attributes and preserved namespace prefixes. Limits are at most
16 MiB per input/output, depth 256, 65536 attributes, 100000 ordered tree nodes, eight concurrent operations
and 30 seconds per call. The aggregate configured input/output admission budget
cannot exceed 128 MiB. Saturation fails immediately with `EK_XML_SECURITY`.
Unknown fields, null optional values, accessors and insecure parser options fail
before worker allocation. DTDs and external entity resolution cannot be enabled.

Input/output byte ceilings refer to UTF-8 XML strings and UTF-8 JSON encodings of
ordered document snapshots. They do not represent exact JavaScript heap or IPC
wire sizes. Workers additionally have native V8 resource limits.

## Optional native XSD backend

The reviewed Linux backend is Ubuntu 24.04's `libxml2` and `libxml2-utils`
`2.9.14+dfsg-1.3ubuntu3.10`, with root-owned executables at fixed system paths.
The gate checks vendor package versions, native schema support and actual schema
compilation. A binary identity or package version change requires a newly vetted
binding; validation fails closed instead of silently switching engines. See the
[vendor package](https://packages.ubuntu.com/noble-updates/libxml2-utils).

Register up to 32 normalized absolute schema paths. Startup reads regular,
non-symlink, non-group/world-writable assets, capped at 1 MiB each and 8 MiB total.
Native SAX metadata resolves relative include/import references only to other
registered assets. Unregistered files, external URLs, `xml:base` overrides and
dependency cycles are rejected. Every root is compiled by the actual engine.
The approved graph is copied into a private application-owned snapshot directory;
later changes to original files cannot change active validation. Snapshot assets
are removed after owned native processes finish on shutdown or initialization
failure. Documents themselves are passed through standard input, never temp files.

Instance `xsi:schemaLocation` and `xsi:noNamespaceSchemaLocation` hints are rejected:
requests select only a startup-registered schema ID. Validation uses `--nonet`,
`--nocatalogs`, no entity expansion or XInclude, a clean environment and fixed
argument arrays. Native processes have address-space/data ceilings of 256/128 MiB,
32 file descriptors, no file output and a finite CPU limit. The shared wall
deadline and cancellation kill owned processes and retain admission until actual
exit. Invalid documents return `valid: false` with safe messages; compiler,
resource, storage or process failures return explicit errors. Raw native
diagnostics are bounded, drained and never exposed in errors or telemetry.

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

## Native observations

Optional logging/telemetry records fixed operation/outcome labels, durations,
UTF-8 input/output counts and actual worker heap samples. Rejections distinguish
native invalid-schema decisions from operational errors. Node process RSS is an
aggregate gauge; worker heap samples are not peak RSS, and native child RSS is
not attributed to requests. Comparative throughput and peak-memory profiling
remain separate measurements. Schema IDs, file paths, XML values and native
diagnostics never become log fields or metric labels.

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
The native integration suite requires the owned disposable Linux fixture:

```sh
ARKENIVA_XML_DISPOSABLE=1 python3 examples/xml/test/fixtures/run.py -- pnpm --filter @arkenivajs/data-xml test:integration
```

It validates real positive/negative schemas, registered imports, immutable
snapshots, external/cyclic references, symlinks, DTD/XXE, missing storage,
actual native process cancellation/failure and cleanup. Run system-package and
network-namespace setup inside the integration VM or disposable CI runner.

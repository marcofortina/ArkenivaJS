<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Managed SOAP clients

`soapPlugin(settings)` registers the optional `SOAP_CAPABILITY`. Importing the
package opens no connection. Resolve the capability after application startup,
create a named client, call an approved operation and close the client lease.

```typescript
import { SOAP_CAPABILITY } from '@arkenivajs/soap';
import type { SoapService } from '@arkenivajs/soap';

const soap = app.resolve<SoapService>(SOAP_CAPABILITY);
const client = await soap.createClient('stock.v1');
try {
  const receipt = await client.call<{ quantity: number }>(
    'ReadStock',
    { sku: '0007' },
    { timeoutMs: 5000 },
  );
  console.log(receipt.status, receipt.data.quantity);
} finally {
  await client.close();
}
```

The backend is actual node-soap 1.14.0, with its native serializer and decoder.
Document/literal, RPC/literal and declared SOAP 1.1/1.2 profiles have real native
server tests. Generic TypeScript result types do not validate arbitrary business
schemas: maintain per-WSDL application types and business validation.

## Profiles and bounds

Settings contain `services`, `secretProvider` and `policy`. Every service supplies
`id`, an absolute trusted `wsdlFile`, fixed HTTPS `endpoint`, `allowedOperations`,
`protocol` and `maxResponseBytes`; optional `credentialsRef` and `trustedCaRef`
refer only to the configured provider. Request options cannot select another
endpoint, WSDL or credential reference.

The policy requires positive integer `timeoutMs` up to 60000 and
`maxConcurrent` up to 4. That limit bounds physical operations and retained client
leases. Input and output limits default to 1 MiB and cannot exceed 8 MiB.
Calls may tighten their timeout, never increase it. Zero is invalid. Startup
accepts at most 16 profiles and 128 approved operations per profile.

Startup captures a local WSDL and relative WSDL/XSD imports below its directory:
at most 32 files, 1 MiB per file and 8 MiB total. Symlinks, shared writable files,
malformed UTF-8, external locations, escaping paths and cycles are rejected.
Import names permit ASCII letters, digits, underscores, dots, slashes and hyphens;
URL encoding, query strings and fragments are unsupported. Parent traversal is
allowed only while remaining below the approved root.

Captured documents populate the actual native cache in dependency order. Cache
misses fail before native filesystem or network access. Namespace ambiguities,
duplicate native map keys, reserved method names and unsupported bindings fail
at startup.

## Credentials

`trustedCaRef` contains a PEM certificate bundle. `credentialsRef` contains UTF-8
JSON with this versioned shape; no credential is configured directly in a profile:

```typescript
type CredentialBundle = {
  version: 1;
  httpAuth?:
    { scheme: 'basic'; username: string; password: string } | { scheme: 'bearer'; token: string };
  tls?: { certificatePem: string; privateKeyPem: string; passphrase?: string };
  wsSecurity?: {
    mode: 'username-token-digest';
    username: string;
    password: string;
  };
};
```

At least one credential mode is required when `credentialsRef` is present.
Provider results require nonempty versioned bytes and an unexpired expiration
when supplied. Malformed data, unknown fields, invalid key/certificate material
and provider failures deny the operation. No cached credential fallback exists.
Owned byte copies are cleared after use. Disposable providers are rejected by
production application configuration.

Managed calls refresh credentials for every operation. Native calls also refresh
HTTP and TLS credentials; a native WS-Security call rejects a changed credential
version until a managed call refreshes the instance or the client is recreated.
UsernameToken uses the real library's digest, nonce and timestamp implementation.
Its provider-owned header cannot be removed, replaced or duplicated through the
native transport. Other WS-Security token, signature and encryption modes are
unsupported.

## Transport, fidelity and lifecycle

The isolated native Axios/Node HTTPS transport pins the fixed endpoint and at
most 16 startup DNS answers, verifies TLS 1.2 or later, and supports explicit CA
and mTLS credentials. It disables proxies, redirects, retries and automatic
decompression. Native OS DNS is not cancelable: initialization reservations remain
owned until it settles. Absolute deadlines cancel actual sockets, including slow
continuous responses. Close waits for physical cleanup. Failures after submission
may have an unknown business outcome; cancellation is not rollback.

Native SAX admission rejects DTDs, external entities, unsafe names, duplicate SOAP
bodies and mismatched qualified payloads. Native decoding runs in owned workers
with finite memory, XML depth, element, attribute, output and time bounds. Worker
death or timeout retires the client instead of silently restarting it. No JSON
response fallback is accepted.

Portable input supports ordinary data objects, arrays, finite safe numbers,
strings, booleans, null and valid Date values. Getters, proxies, cycles, sparse
arrays and native raw-XML/attribute control keys are rejected. Binary encodings
must be explicit application strings rather than guessed from a Buffer.
Native scalar hooks preserve `long`, `integer` and `decimal` lexical values as
strings, retain significant string whitespace and reject lossy numeric conversions.
Repeated HTTP header arrays, encoded bindings, ambiguous operations and one-way
operations are unsupported.

`native()` returns the actual approved `Client` instance as `unknown`; trusted
application code must import native types and narrow it explicitly. ArkenivaJS
retains transport, endpoint, authentication, parser and lifecycle ownership.
Native options support bounded `timeout` and a real `signal`; unknown overrides
are rejected. Direct native calls require application-owned instrumentation.

Fixed-label metrics cover duration, faults, known SOAP payload bytes and aggregate
resource counts. Logs and spans omit bodies, credentials, endpoint/WSDL paths,
private fault details and secret references. Correlation IDs appear in receipts
and safe events, never metric labels.

## Compatibility and example

The bundled native decoder patch preserves complete scalar text across CDATA and
comments and honors the declared whitespace option. A real native startup probe
rejects an unpatched decoder. The metadata-only `dev-null` patch normalizes its
existing MIT declaration without changing JavaScript. Full upstream MIT notices
are retained in `THIRD_PARTY_NOTICES.md`.

Packed consumers must preserve the reviewed dependency patches. The framework's
packed-example verifier copies the required patches into the isolated consumer;
no installation hook modifies dependencies. See [the executable SOAP
example](../../examples/soap/README.md) for real HTTPS, authentication and SDK
privacy checks.

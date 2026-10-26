# UUID identifiers

`@arkenivajs/data-identifiers` delegates UUIDv4 generation to
`node:crypto.randomUUID` and UUIDv7 generation, syntax validation and version
inspection to the prescribed `uuid@14.0.3` library. It provides a pure factory
and an optional application capability, without network or storage resources.

```typescript
import { createIdentifiersService } from '@arkenivajs/data-identifiers';

const ids = createIdentifiersService({ allowVersions: [4, 7] });
const value = ids.uuidV7();
const parsed = ids.parseUuid(value);
```

`allowVersions` is mandatory, contains one or two distinct values from `4 | 7`,
and is captured before use. Generation, parsing and validation enforce the same
policy. Unknown settings, accessors, holes and unsupported versions are rejected.

| Method                    | Result                                                             |
| ------------------------- | ------------------------------------------------------------------ |
| `uuidV4()`                | Cryptographically random lowercase UUIDv4                          |
| `uuidV7()`                | Timestamp-based lowercase UUIDv7 using the upstream CSPRNG         |
| `parseUuid(value)`        | Frozen `{canonical, version}` or `EK_IDENTIFIER_INVALID`           |
| `isUuid(value, version?)` | Boolean validity under the configured and requested version policy |

The framework's canonical-input policy requires exactly 36 lowercase characters
in the library-validated hyphenated form. Uppercase, URNs, braces, surrounding
whitespace, nil/max UUIDs and other versions are not silently normalized.
Runtime inputs are not coerced into strings. Invalid settings use
`EK_CONFIG_INVALID`; a stopped managed handle uses `EK_RESOURCE_CLOSED`.

UUIDv7 uses explicit upstream options to avoid a shared sequence counter between
application instances. Values are approximately ordered by wall-clock
milliseconds. No same-millisecond, clock-rollback or distributed monotonic order
is promised. No caller-controlled clock or random source is exposed.
Identifiers do not contain account data and are not passwords, bearer tokens
or proof of authorization.

For lifecycle management, explicitly install `dataIdentifiersPlugin(settings)`
and resolve `IDENTIFIERS_CAPABILITY` as `IdentifiersService`. Reusing a plugin
factory keeps application lifetimes separate; stopping one invalidates only
its own handle. Logging and telemetry are not prerequisites for these pure
synchronous operations.

Tests cover the [RFC 9562 Appendix A vectors](https://www.rfc-editor.org/rfc/rfc9562.html#appendix-A),
native-library interoperability, malformed data, policy isolation, bounded
collision sanity and lifecycle behavior. The
[utilities example](../../examples/utilities/README.md) runs through public
artifacts. Performance measurements remain a separate release gate.

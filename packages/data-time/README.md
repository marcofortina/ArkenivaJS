# Time and time zones

`@arkenivajs/data-time` delegates instant parsing, calendar arithmetic and DST
resolution to the prescribed `@js-temporal/polyfill@0.5.1`, and locale display to
native `Intl.DateTimeFormat`. The imported polyfill provides the same API across
supported Node lines without modifying globals. No current clock is read and no
process `TZ`, locale or timezone default is changed.

```typescript
import { createTimeService } from '@arkenivajs/data-time';

const time = createTimeService({ allowedZones: ['UTC', 'Europe/Rome'] });
const instant = time.parseInstant('2026-03-28T11:00:00Z');
const rome = time.toZoned(instant, 'Europe/Rome');
const calendarDay = time.add(rome, { days: 1 }, 'reject');
const elapsedDay = time.add(rome, { hours: 24 }, 'reject');
// Rome switches to summer time: calendarDay is 12:00; elapsedDay is 13:00.
const display = time.format(calendarDay, 'it-IT', { dateStyle: 'medium' });
```

| Method                            | Result                                                                |
| --------------------------------- | --------------------------------------------------------------------- |
| `parseInstant(text)`              | Branded canonical UTC string, preserving nanoseconds                  |
| `toZoned(instant, ianaZone)`      | Frozen `{iso,zone}` with the explicit allowed zone                    |
| `add(zoned, duration, policy)`    | New frozen value, using native calendar/elapsed semantics             |
| `format(zoned, locale, options?)` | Display string using the supplied supported locale and validated zone |

`allowedZones` is mandatory, accepts `1..256` distinct ICU-resolved IANA names,
and is captured before use. Numeric-offset zone identifiers are not an IANA zone
policy. Invalid, null, unknown, sparse or accessor settings fail with
`EK_CONFIG_INVALID`; an unavailable or unapproved runtime zone uses `EK_TIME_ZONE`.
Aliases are resolved by the installed runtime's ICU data.

Instant input requires an uppercase `T`, seconds, an explicit `Z` or `±HH:MM`
offset, and at most nine fractional digits. Four-digit or signed six-digit ISO
years are supported within Temporal's range. Local dates/times, annotations,
surrounding whitespace and leap-second `60` are rejected; leap seconds are not
silently clamped. Offsets and trailing fractional zeros normalize through
Temporal to canonical UTC. Runtime branded strings are revalidated; an unchecked
TypeScript cast is not parsing.

Zoned values are checked for actual calendar/offset/zone consistency before use;
the only calendar is ISO 8601. Unknown fields, accessors, unsafe integers,
unsupported duration fields and mixed-sign durations fail explicitly with
`EK_TIME_INVALID`. Inputs and native error contents never appear in diagnostics.

`add` requires `reject`, `earlier`, `later` or `compatible` on every call. Native
Temporal calendar months/days are applied first, retaining its constrained
month-end behavior. The resulting local time is resolved under that explicit
policy; `reject` reports missing/repeated wall time as `EK_TIME_AMBIGUOUS`.
Elapsed hours are then added on the instant timeline. An hours-only operation
preserves the existing instant's fold offset instead of reconstructing an
ambiguous local time. The [Temporal documentation](https://tc39.es/proposal-temporal/docs/zoneddatetime.html)
defines these calendar and elapsed-time distinctions.

Formatting requires a supported explicit locale; unsupported or malformed
locales fail instead of falling back to the host's default. `Intl` option fields
and primitive types are checked before native formatting. A supplied `timeZone`
must resolve to the value's own zone. Native formatting supports milliseconds;
the stored instant/zoned ISO strings retain finer precision. Native `Intl`
option combinations and range errors use `EK_TIME_INVALID`.

The TZDB/ICU version is supplied by Node and the deployment image. Pin the image
and ICU data when identical historical/future rules and locale strings are
required across pods. The package does not bundle a separate IANA database or
promise identical localized punctuation across runtime versions. It offers no
implicit current-time source or test clock override because every operation
takes explicit input values.

`createTimeService(settings)` is a pure factory. For application ownership,
register `dataTimePlugin(settings)` and resolve `TIME_CAPABILITY` as
`TimeService`. Logging, storage and telemetry are not prerequisites. Reused
plugins isolate application lifetimes; stopped handles use `EK_RESOURCE_CLOSED`.

The [utilities example](../../examples/utilities/README.md) exercises public
imports and is compiled/tested against packed artifacts. Tests cover Rome and
New York gaps/folds, leap days, month ends, explicit locales, malformed input,
runtime policy enforcement and shutdown. Performance measurements and remote
compatibility evidence remain separate release gates.

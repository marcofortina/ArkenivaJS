# Temporal and Intl time comparison

Build the workspace and choose a fresh absolute output directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation time --verify /private/time-verification
```

Four sequential isolated Node processes exercise native Temporal/Intl, the
public time plugin, and the actual standard/detailed diagnostic SDK profiles.
The fixed valid corpus checks normalized UTC nanoseconds, explicit zoned values,
locale formatting and 24 elapsed hours across Rome and New York DST transitions.
Every worker confirms that its process timezone remains unchanged.

The four operations are `parseInstant`, `toZoned`, `addElapsedHours` and `format`.
The bare baseline accepts this valid corpus only. It is not a replacement for
the public service's strict ISO, zone allowlist, ambiguity, lifecycle or safe
error policy. Calendar day/month arithmetic and ambiguous wall-time construction
remain covered by the runtime package's tests; they are not timed operations in
this comparison. Temporal 0.5.1 and native Intl provide all calendar and zone
semantics. No timezone algorithm is implemented by this tool.

`--verify` uses `measured: false`, no timing samples and null resource results.
`--smoke` tests the sampling path with 100 warmup iterations and at least 1,000
completed samples for each operation/profile. Reports always retain
`releaseGate: false`; this is not performance acceptance or a repeated campaign.

The owned collector and report encoder reject occurrence of the fixed input
values. Trivial time operations receive no artificial spans or counters. SDK
quality checks remain active. Process resource results cannot be attributed to
tenants or requests. No cross-image ICU/TZDB equivalence, five-repetition run,
one-hour soak or production overhead budget is claimed.

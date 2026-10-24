# @arkenivajs/diagnostics

`createDiagnostics({eventLoopUtilization?, eventLoopDelay?, resolutionMs?})` returns a native process collector with `snapshot()` and idempotent `close()`. Imports start no timer or histogram. Utilization is enabled by default; the event-loop delay histogram is opt-in, with a default sampling resolution of 20 ms. `diagnosticsPlugin(options?)` starts and closes one collector per application.

Snapshots are deeply immutable plain data with an ISO UTC timestamp and actual process id. CPU values are cumulative process user/system microseconds from `process.cpuUsage`; RSS and heap values are instantaneous bytes from `process.memoryUsage`. `DIAGNOSTIC_SOURCES` describes every measurement's source, unit, process scope and interval.

Event-loop utilization covers the interval since creation or the previous snapshot. The p99 delay is derived from the native histogram since the previous snapshot and converted from nanoseconds to milliseconds; collecting a snapshot resets that histogram. Disabled or not-yet-sampled measurements are omitted rather than filled with zero. These measurements never represent exact CPU or memory use by an individual concurrent request or tenant.

Invalid options use `EK_CONFIG_INVALID`. `snapshot()` after close uses `EK_RESOURCE_CLOSED`. Always close a standalone collector, preferably in a finally block:

```ts
import { createDiagnostics } from '@arkenivajs/diagnostics';

const collector = createDiagnostics({ eventLoopDelay: true, resolutionMs: 20 });
try {
  const snapshot = collector.snapshot();
  console.log(snapshot.memoryRssBytes);
} finally {
  collector.close();
}
```

`pnpm smoke` exercises the real snapshot. The unit suite also creates native event-loop activity, verifies unavailable fields, checks collector shutdown and runs an isolated process to detect leaked lifetime work.

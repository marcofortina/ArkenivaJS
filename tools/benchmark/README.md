# Local foundation measurements

This Tinybench workload measures errors, strict configuration reads/loads, an isolated application's start/stop, Pino logging and native process snapshots. It exercises the same public package entries used by applications. It requires a built workspace and Node.js 24; no server or database is needed.

Run from the workspace root:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --silent --filter @arkenivajs/benchmark-foundation start
```

Standard output is a measured JSON report. Redirect it to a protected location outside the checkout when retaining results. The script fails on task errors, missing samples, transport failure or dropped framework log lines. Raw measurements, profiles and reports do not belong in Git.

Each scenario warms up for 100 iterations, then measures 1,000 operations (100 for configuration loading and application lifecycle). Runs are sequential, with one independent repetition. Latencies use milliseconds and include the timer's overhead; p95 is interpolated from the retained sorted samples. CPU deltas include warmup and measurement, and RSS records only the interval's endpoints. Unsupported values use `null` or appear in the measurement coverage list. No environment-variable dump is collected.

The report records the commit, exact runtime, tool versions, CPU model, affinity, governor and container limits where available. Its `BASELINE` rows call underlying Node/Pino APIs directly; `FRAMEWORK` rows include the additional framework work. Error serialization and strict configuration validation perform extra work, and process snapshots also add timestamps and event-loop counters. These component measurements do not establish equivalent end-to-end overhead. Logging uses a synchronous in-memory sink with matching service context and credential redaction, excluding disk/network durability and realistic contention.

Every report has `measured:true` and `releaseGate:false`. Shared-host timing, brief warmup and one repetition cannot prove a regression budget. A release comparison requires equivalent HTTP, authentication and database workloads in baseline, framework, standard telemetry and detailed modes, a dedicated runner, at least 60 seconds of warmup, 180 seconds of steady load and five independent repetitions, with confidence analysis and retained raw evidence. Those workloads require their respective implemented modules. Do not infer request or tenant CPU/RAM from whole-process counters.

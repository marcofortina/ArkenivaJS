// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureComparison } from './pure-comparison.mjs';
import { lookupsPerBatch } from './core-workload.mjs';

const marker = 'owned-core-private-capability-value';
await runPureComparison({
  scenarioId: 'core-capability-resolution-comparison',
  fixture: { marker },
  privacyValues: [marker],
  privacyField: 'inputOccurrences',
  worker: new URL('./core-worker.mjs', import.meta.url),
  inputs: {
    nativeBackend: 'Native Map registry lookup',
    operations: ['resolve-256', 'try-resolve-256'],
    lookupsPerBatch,
    samplesPerOperation: 1000,
    warmupIterations: 100,
    concurrency: 1,
  },
  observationCoverage:
    'Actual public symbol capability lookup, identity, immutable values and missing-value behavior in four isolated profiles. Framework profiles independently check readiness and closed-state rejection. Lookup profiling adds no instruments; actual installed SDK counters remain observable.',
  limitations:
    'Fixed hot symbol lookup only; native Map omits framework lifecycle, scope/dependency and typed error policy. Latency and throughput describe batches of 256 lookups, not individual lookup samples. No lookup metrics/spans or exporter-delivery exercise is introduced. Whole child CPU/memory includes measurement overhead. No dynamic dispatch, full lifecycle workload, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureComparison } from './pure-comparison.mjs';
await runPureComparison({
  scenarioId: 'diagnostics-process-comparison',
  fixture: {},
  privacyValues: [],
  privacyField: 'inputOccurrences',
  worker: new URL('./diagnostics-worker.mjs', import.meta.url),
  inputs: {
    operations: ['snapshot'],
    nativeBackend: 'Node process.cpuUsage/process.memoryUsage/node:perf_hooks',
    eventLoopUtilization: true,
    eventLoopDelayHistogram: false,
    concurrency: 1,
  },
  observationCoverage:
    'Actual process snapshots in four isolated diagnostic profiles; no artificial per-call observations and no request/tenant resource attribution. No application input corpus is present.',
  limitations:
    'Process CPU is cumulative and RSS/heap are instantaneous. Interval event-loop utilization is not compared between different processes. Histogram collection, startup/shutdown, repeated campaigns, one-hour soak and release performance budgets are outside this functional comparison.',
});

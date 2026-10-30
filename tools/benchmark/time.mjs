// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureComparison } from './pure-comparison.mjs';
import { timeFixture } from './time-workload.mjs';
await runPureComparison({
  scenarioId: 'time-temporal-comparison',
  fixture: timeFixture,
  privacyValues: Object.values(timeFixture),
  privacyField: 'inputOccurrences',
  worker: new URL('./time-worker.mjs', import.meta.url),
  inputs: {
    operations: ['parseInstant', 'toZoned', 'addElapsedHours', 'format'],
    nativeBackend: '@js-temporal/polyfill0.5.1 and nativeIntl',
    fixedValidCorpus: true,
    elapsedHoursOnly: true,
    samplesPerOperation: 1000,
    warmupIterations: 100,
    concurrency: 1,
  },
  observationCoverage:
    'Pure clock-free conversions in four isolated modes; no artificial per-call spans or metrics. Actual SDK quality retained in standard/detailed profiles.',
  limitations:
    'Fixed valid inputs only; framework zone policy, strict ISO validation, error shaping and lifecycle remain additional work. Calendar day arithmetic and ambiguous wall-time disambiguation are not comparison operations. No cross-image TZDB equivalence, release budget, five-repetition campaign or soak claim.',
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { csvFixture } from './csv-workload.mjs';
assert.equal(
  process.argv[2],
  '--verify',
  'Only --verify is supported until streaming first-byte, backpressure and buffer accounting is available',
);
await runPureComparison({
  scenarioId: 'csv-native-functional-comparison',
  fixture: csvFixture,
  privacyValues: Object.values(csvFixture),
  privacyField: 'inputOccurrences',
  worker: new URL('./csv-worker.mjs', import.meta.url),
  inputs: {
    operations: ['parse', 'stringify'],
    nativeBackend: 'csv-parse7.0.3,csv-stringify6.9.0',
    fixedFiniteCorpus: true,
    samplingSupported: false,
    completedStreamsRequired: true,
    concurrency: 1,
  },
  observationCoverage:
    'Actual completed CSV/TSV byte streams in four isolated profiles. Native interoperability, fragmented UTF-8, BOM, quoting and text-only fields checked. Actual SDK exports checked without record contents.',
  limitations:
    'Functional valid-corpus evidence only. The native baseline omits framework schema, limits, encoding, formula and cancellation policies. Sampling is rejected pending first-byte, backpressure and buffer accounting. No throughput, memory budget, repeated campaign or soak acceptance.',
});

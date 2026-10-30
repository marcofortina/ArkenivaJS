// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { codesFixture } from './codes-workload.mjs';
assert.equal(
  process.argv[2],
  '--verify',
  'Only --verify is supported until codec-child resource accounting is available',
);
await runPureComparison({
  scenarioId: 'codes-native-functional-comparison',
  fixture: codesFixture,
  privacyValues: Object.values(codesFixture),
  privacyField: 'inputOccurrences',
  worker: new URL('./codes-worker.mjs', import.meta.url),
  inputs: {
    symbologies: ['QR', 'CODE128', 'EAN13'],
    outputs: ['png', 'svg'],
    nativeVersions: { qrcode: '1.5.4', bwip: '4.11.4', sharp: '0.35.5', zxing: '0.21.3' },
    fixedValidCorpus: true,
    samplingSupported: false,
    concurrency: 1,
  },
  observationCoverage:
    'Actual native encoders and decoders, owned framework codec processes, actual SDK metrics in standard/detailed profiles. Symbol contents must not enter telemetry or reports.',
  limitations:
    'Functional parity only; encoded image bytes and raster sizes need not match. Parent-only CPU/RSS would omit codec children, so sampling is rejected before workers start. No process-tree resource, throughput, performance budget, repeated campaign or soak evidence.',
});

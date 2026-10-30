// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { codesFixture, codesSettings } from './codes-workload.mjs';
import { codesPngBase64, codesPngDescriptor } from './codes-fixture.mjs';
assert.ok(
  ['--verify', '--smoke'].includes(process.argv[2]),
  'Only --verify and bounded --smoke are supported',
);
assert.ok(
  process.argv[2] !== '--smoke' || process.env.ARKENIVA_CODES_BENCHMARK_DISPOSABLE === '1',
  'Barcode smoke requires an explicitly disposable measurement environment',
);
await runPureComparison({
  scenarioId: 'codes-native-functional-comparison',
  superviseProcessTree: true,
  fixture: codesFixture,
  privacyValues: [...Object.values(codesFixture), codesPngBase64],
  privacyField: 'inputOccurrences',
  worker: new URL('./codes-worker.mjs', import.meta.url),
  inputs: {
    symbologies: ['QR', 'CODE128', 'EAN13'],
    outputs: ['png', 'svg'],
    nativeVersions: { qrcode: '1.5.4', bwip: '4.11.4', sharp: '0.35.5', zxing: '0.21.3' },
    fixedValidCorpus: true,
    samplingSupported: true,
    measuredIterationsPerScenario: 100,
    warmupIterationsPerScenario: 20,
    fixedDecodePng: codesPngDescriptor,
    rendering: { qrWidthPixels: 256, barcodeWidthPixels: 512, correction: 'M', margin: 4 },
    resourceLimits: codesSettings,
    retainedOutputByteLimit: 8388608,
    concurrency: 1,
  },
  observationCoverage:
    'Actual native encoders and decoders, owned framework codec processes, actual SDK metrics in standard/detailed profiles. Symbol contents must not enter telemetry or reports.',
  limitations:
    'Bounded closed-loop valid-corpus smoke only: no equivalent adversarial-image policy, calibrated observer/IPC cost, matched open-loop load, confidence intervals, production sampling budget, repeated campaign, soak or release gate. All measured profiles use the same supervision. Whole-lifecycle CPU includes startup, verification, independent completion decoding, warmup, measurement, export and cleanup; Python observer and external services remain excluded. Per-operation latency includes actual codec work and bounded capture/assertion cost; warmup samples are excluded. Standard/detailed samplingRatio=1 is diagnostic sampling, not a normal production budget claim.',
});

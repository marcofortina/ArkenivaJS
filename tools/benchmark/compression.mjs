// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { compressionFixture } from './compression-workload.mjs';
assert.equal(
  process.argv[2],
  '--verify',
  'Only --verify is supported until streaming first-byte, backpressure and buffer accounting is available',
);
await runPureComparison({
  scenarioId: 'compression-native-functional-comparison',
  fixture: compressionFixture,
  privacyValues: Object.values(compressionFixture),
  privacyField: 'inputOccurrences',
  worker: new URL('./compression-worker.mjs', import.meta.url),
  inputs: {
    operations: ['gzip', 'gunzip', 'createZip', 'iterateZip'],
    nativeBackend: 'Node zlib,fflate0.8.3,yauzl3.4.0',
    fixedFiniteCorpus: true,
    samplingSupported: false,
    completedStreamsRequired: true,
    concurrency: 1,
  },
  observationCoverage:
    'Actual completed GZIP/ZIP streams and native interoperability in four isolated profiles. Actual SDK operation metrics checked without contents or archive entry names.',
  limitations:
    'Functional valid-corpus evidence only. Bare ZIP creation buffers the finite fixture and omits framework archive safety policy. Sampling is rejected pending first-byte, backpressure and buffer accounting. No corrupt/untrusted archive equivalence, resource budget, throughput or soak acceptance.',
});

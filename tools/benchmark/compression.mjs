// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { compressionFixture } from './compression-workload.mjs';
const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full compression campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_COMPRESSION_BENCHMARK_DISPOSABLE,
    '1',
    'Compression smoke measurements require an explicitly disposable runner',
  );
await runPureComparison({
  scenarioId: 'compression-native-functional-comparison',
  superviseProcessTree: true,
  fixture: compressionFixture,
  privacyValues: Object.values(compressionFixture),
  privacyField: 'inputOccurrences',
  worker: new URL('./compression-worker.mjs', import.meta.url),
  inputs: {
    operations: ['gzip', 'gunzip', 'createZip', 'iterateZip'],
    nativeBackend: 'Node zlib,fflate0.8.3,yauzl3.4.0',
    fixedFiniteCorpus: true,
    samplingSupported: true,
    measuredScenarios: ['gzip-validated-byte-stream', 'gunzip-validated-byte-stream'],
    measuredSamplesPerScenario: measured ? 100 : null,
    warmupCallbacksPerScenario: measured ? 20 : null,
    zipTimingSupported: false,
    pressureProbeUncompressedBytesPerDirection: measured ? 8388608 : null,
    pressureConsumerHoldMs: measured ? 50 : null,
    traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
    completedStreamsRequired: true,
    concurrency: 1,
  },
  observationCoverage:
    'Actual completed GZIP/ZIP streams and native interoperability in four isolated profiles. Actual SDK operation metrics checked without contents or archive entry names. Explicit smoke retains actual Tinybench GZIP/GUNZIP stream samples, first byte and exact compressed/uncompressed byte/ratio/digest counters. Separate8MiB lazy pressure probes require actual stalled producers before EOF, resumed full semantic integrity and physical own-stream retirement. Own-readable queues remain distinct from unknown internal codec buffers. All profiles use supervised lifecycle resources; STANDARD and DETAILED both use diagnostic sampling1.',
  limitations:
    'Bounded valid-corpus component evidence only. Bare ZIP creation buffers the finite fixture and omits framework archive safety policy. Small stream observations and raw timing include explicitly disclosed fixture/validation overhead; probe upstream gzip or native post-pause decoder work is separate and included in lifecycle resources. Opaque internal buffer bytes remain null; sampled process RSS is not exact peak RAM. STANDARD uses diagnostic sampling1 rather than normal production sampling. ZIP timing remains explicitly unsupported. No corrupt/untrusted archive equivalence, full policy-equivalent overhead, calibrated throughput/memory budget, five repeats or soak acceptance.',
});

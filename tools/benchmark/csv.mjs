// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { csvFixture } from './csv-workload.mjs';
const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full CSV campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_CSV_BENCHMARK_DISPOSABLE,
    '1',
    'CSV smoke measurements require an explicitly disposable runner',
  );
await runPureComparison({
  scenarioId: 'csv-native-functional-comparison',
  superviseProcessTree: true,
  fixture: csvFixture,
  privacyValues: Object.values(csvFixture),
  privacyField: 'inputOccurrences',
  worker: new URL('./csv-worker.mjs', import.meta.url),
  inputs: {
    operations: ['parse', 'stringify'],
    nativeBackend: 'csv-parse7.0.3,csv-stringify6.9.0',
    fixedFiniteCorpus: true,
    samplingSupported: true,
    scenarios: ['parse-stream-256-rows', 'stringify-stream-256-rows'],
    measuredSamplesPerScenario: measured ? 100 : null,
    warmupCallbacksPerScenario: measured ? 20 : null,
    measuredCorpusRows: 256,
    pressureProbeEncodedBytesPerDirection: measured ? 8388608 : null,
    pressureConsumerHoldMs: measured ? 50 : null,
    traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
    completedStreamsRequired: true,
    concurrency: 1,
  },
  observationCoverage:
    'Actual completed CSV/TSV byte streams in four isolated profiles. Native interoperability, fragmented UTF-8, BOM, quoting and text-only fields checked. Actual SDK exports checked without record contents. Explicit smoke retains actual Tinybench samples, first input/output-byte or row observations, exact bytes/rows/digests and counter-derived throughput. Separate8MiB lazy pressure probes pause consumers and require observed producer plateaus before EOF, complete exact output and physical owned-source/stream retirement. Observed own-readable queue peaks remain distinct from unknown opaque codec internals. STANDARD and DETAILED both use diagnostic sampling1.',
  limitations:
    'Small valid-corpus component comparison only. The native baseline omits framework schema, limits, encoding, formula and cancellation policies. Measured-window worker resources describe the small corpus; supervised whole-lifecycle resources also include separate pressure probes. Sampled RSS is non-atomic, counts shared pages per process and can miss brief peaks; own-readable queue observations do not measure opaque codec internal memory, which remains unknown/null. Throughput and first-byte observations include benchmark digest/assertion overhead. STANDARD uses diagnostic sampling1 rather than normal production sampling. No full-policy equivalence, exact peak RAM, calibrated throughput/memory budget, five repeats or soak acceptance.',
});

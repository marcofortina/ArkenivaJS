// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
assert.ok(
  args[0] !== '--smoke' || process.env.ARKENIVA_XLSX_BENCHMARK_DISPOSABLE === '1',
  'XLSX smoke requires an explicitly disposable measurement environment',
);
const fixture = {
  firstSheet: 'Owned comparison data',
  secondSheet: 'Owned comparison other',
  marker: 'owned-xlsx-private-content',
  sampleReads: args[0] === '--smoke',
};
await runPureComparison(
  {
    scenarioId: 'xlsx-native-workbook-interoperability',
    fixture,
    privacyValues: Object.values(fixture).filter((value) => typeof value === 'string'),
    privacyField: 'inputOccurrences',
    worker: new URL('./xlsx-worker.mjs', import.meta.url),
    superviseProcessTree: true,
    profileTimeoutMs: 90000,
    inputs: {
      nativeBackend: 'exceljs@4.4.0 bounded object model',
      sheetsPerWorkbook: 2,
      rowsPerWorkbook: 5,
      sourceChunkBytes: 7,
      concurrency: 1,
      samplingSupported: true,
      measuredScenario: 'Fixed compressed workbook; ordered five-row validated read',
      samplesPerProfile: args[0] === '--smoke' ? 100 : 0,
      warmupReadsPerProfile: args[0] === '--smoke' ? 20 : 0,
    },
    observationCoverage:
      'Native/public XLSX interoperability, one-shot fragmented compressed input, awaited targets, exact scalar/date/formula data and supported styles in four isolated profiles. Optional read smoke uses identical fixed compressed bytes, validates every row/style/formula cache and records first-row/complete reader lifetime and throughput. Source and reader retire before callback completion; supervised resource observations include native child processes. Actual SDK exports exclude workbook contents and sheet names.',
    limitations:
      'Small fixed workbook read only; validation and physical reader closure are included in callback latency. Native baseline uses the bounded object model while the framework decodes ordered worksheet streams in fresh owned children; no equivalent streaming/isolation cost claim. The trusted90second whole-profile budget allows120cold reads and preserves public per-operation10second policy, concurrency/memory/permission bounds. Summed RSS is sampled aggregate, not exact peak/PSS; opaque native buffers remain unknown. No write timing, large-file/backpressure/peak-buffer/heap, arbitrary format fidelity, formula calculation, calibrated policy-equivalent overhead, dedicated-runner budget, five repetitions, one-hour soak or release acceptance.',
  },
  args,
);

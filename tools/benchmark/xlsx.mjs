// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete XLSX resource sampling remains separate',
);
const fixture = {
  firstSheet: 'Owned comparison data',
  secondSheet: 'Owned comparison other',
  marker: 'owned-xlsx-private-content',
};
await runPureComparison(
  {
    scenarioId: 'xlsx-native-workbook-interoperability',
    fixture,
    privacyValues: Object.values(fixture),
    privacyField: 'inputOccurrences',
    worker: new URL('./xlsx-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'exceljs@4.4.0 bounded object model',
      sheetsPerWorkbook: 2,
      rowsPerWorkbook: 5,
      sourceChunkBytes: 7,
      concurrency: 1,
      samplingSupported: false,
    },
    observationCoverage:
      'Native/public XLSX interoperability, one-shot fragmented compressed input, awaited targets, exact scalar/date/formula data and supported styles in four isolated profiles; actual SDK exports exclude workbook contents and sheet names.',
    limitations:
      'Small synthetic workbooks only. Native baseline uses the ordinary bounded object model while the framework decodes ordered worksheet streams in owned children; this is not equivalent streaming cost. No child CPU/RSS, first-row, peak-buffer, large-file heap, throughput, arbitrary format fidelity or formula calculation claim. Performance budgets, five repetitions and one-hour soak remain separate.',
  },
  args,
);

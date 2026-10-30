// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete PDF resource sampling remains separate',
);
const fixture = {
  first: 'owned-pdf-private-first',
  second: 'owned-pdf-private-second',
  added: 'owned-pdf-private-added',
  title: 'owned-pdf-private-title',
};
await runPureComparison(
  {
    scenarioId: 'pdf-native-document-interoperability',
    fixture,
    privacyValues: Object.values(fixture),
    privacyField: 'inputOccurrences',
    worker: new URL('./pdf-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'pdf-lib@1.17.1 and pdfjs-dist@6.4.299',
      operations: ['create', 'inspect', 'extractText', 'addText', 'merge'],
      mergedPages: 3,
      font: 'Helvetica',
      concurrency: 1,
      samplingSupported: false,
    },
    observationCoverage:
      'Native/public searchable document interoperability, actual metadata/text geometry, rotated text and merged page order in four isolated profiles; actual SDK exports exclude text and metadata.',
    limitations:
      'Small unsigned inactive synthetic documents and standard font only. Native baseline omits framework complete signature/active-content policy, child isolation, limits and lifecycle. No Unicode-font, hostile-PDF, OCR, rendering, signature-preservation, native child CPU/RSS, throughput, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
  },
  args,
);

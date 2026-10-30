// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { pdfFixture, pdfSettings } from './pdf-workload.mjs';
import { pdfInspectDescriptor, pdfInspectExpected, pdfInspectBase64 } from './pdf-fixture.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or bounded --smoke with a fresh absolute external report directory',
);
assert.ok(
  args[0] !== '--smoke' || process.env.ARKENIVA_PDF_BENCHMARK_DISPOSABLE === '1',
  'PDF smoke requires an explicitly disposable measurement environment',
);
await runPureComparison(
  {
    scenarioId: 'pdf-native-document-interoperability',
    superviseProcessTree: true,
    profileTimeoutMs: 90000,
    fixture: pdfFixture,
    privacyValues: [
      ...Object.values(pdfFixture),
      pdfInspectExpected.author,
      'owned-pdf-fixture',
      pdfInspectBase64,
    ],
    privacyField: 'inputOccurrences',
    worker: new URL('./pdf-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'pdf-lib@1.17.1 and pdfjs-dist@6.4.299',
      operations: ['create', 'inspect', 'extractText', 'addText', 'merge'],
      mergedPages: 3,
      font: 'Helvetica',
      concurrency: 1,
      samplingSupported: true,
      measuredOperation: 'inspect-fixed-one-page-pdf',
      fixedInspectInput: pdfInspectDescriptor,
      measuredIterations: 100,
      excludedWarmupIterations: 20,
      retainedReportByteLimit: 262144,
      resourceLimits: pdfSettings,
      ...(args[0] === '--smoke' ? { supervisedProfileTimeoutMs: 90000 } : {}),
    },
    observationCoverage:
      'Native/public searchable document interoperability, actual metadata/text geometry, rotated text and merged page order in four isolated profiles; actual SDK exports exclude text and metadata.',
    limitations:
      'Small unsigned inactive synthetic documents and standard font only. Only fixed one-page inspection is measured; other operations remain functional verification. Native baseline uses the same pinned libraries but omits framework complete signature/active-content policy, child isolation, limits and lifecycle. Per-operation latency includes real metadata inspection and bounded report/assertion cost; warmup samples are excluded. Separate whole-supervised-lifecycle CPU/RSS includes Node bridge/worker/native children, startup, verification, warmup, measurement, independent completion checks, export and cleanup; Python observer and parent/collector are excluded. Standard/detailed samplingRatio=1 is diagnostic sampling, not a normal production budget. No Unicode-font, hostile-PDF, OCR, rendering, signature-preservation, calibrated observer overhead, matched open-loop load, confidence interval, release budget, five repetitions, one-hour soak or complete PDF performance acceptance.',
  },
  args,
);

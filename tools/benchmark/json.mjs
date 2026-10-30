// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete JSON worker resource sampling remains separate',
);
const fixture = { marker: 'owned-json-private-value-π' };
await runPureComparison(
  {
    scenarioId: 'json-native-schema-and-declarative-projection-verification',
    fixture,
    privacyValues: Object.values(fixture),
    privacyField: 'inputOccurrences',
    worker: new URL('./json-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'Node JSON and ajv@8.20.0 Draft 2020-12 with the same reviewed equality patch',
      operations: ['parse', 'stringify', 'validate', 'transform'],
      mappingGrammarVersion: '1.0.0',
      concurrency: 1,
      samplingSupported: false,
    },
    observationCoverage:
      'Actual native/public JSON parse, serialization, schema validation and one approved declarative projection in four isolated profiles. Verifies stable schema paths, missing versus null, arrays, explicit scalar conversion and unchanged input; real SDK exports exclude source payloads.',
    limitations:
      'Bounded valid corpus and one fixed projection using native JSON/Ajv plus ordinary explicit application projection. The native baseline does not reimplement the versioned mapping grammar and omits framework hostile-object capture, interpreter limits, worker isolation, deadlines and lifecycle policy. No arbitrary-mapping equivalence, complete worker resource sampling, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
  },
  args,
);

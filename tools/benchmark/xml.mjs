// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete XML worker resource sampling remains separate',
);
const fixture = { marker: 'owned-xml-private-value-π', namespace: 'urn:owned:xml:private' };
await runPureComparison(
  {
    scenarioId: 'xml-native-ordered-document-interoperability',
    fixture,
    privacyValues: Object.values(fixture),
    privacyField: 'inputOccurrences',
    worker: new URL('./xml-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'fast-xml-parser@5.11.2 and saxes@6.0.0',
      operations: ['parse', 'stringify'],
      documentsPerProfile: 3,
      namespaceMode: 'preserve',
      concurrency: 1,
      samplingSupported: false,
    },
    observationCoverage:
      'Actual native/public ordered XML tree and writer interoperability in four isolated profiles: mixed content, string attributes, namespace prefixes, Unicode/entities, CDATA and comments. Real SDK exports exclude documents and namespaces.',
    limitations:
      'Small valid self-contained corpus with native SAX syntax/namespace validation and explicit DTD rejection. Native baseline omits framework hostile-object capture, complete security limits, bounded worker isolation, deadlines, cancellation, expanded-name policy and lifecycle checks. No XSD engine or schema acceptance claim; well-formedness is not schema validation. No complete worker CPU/heap sampling, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
  },
  args,
);

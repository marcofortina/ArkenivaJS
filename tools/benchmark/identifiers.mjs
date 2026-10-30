// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import { v7 } from 'uuid';
import { runPureComparison } from './pure-comparison.mjs';
const fixture = { v4: randomUUID(), v7: v7({}) };
while (fixture.v4.toUpperCase() === fixture.v4) fixture.v4 = randomUUID();
await runPureComparison({
  scenarioId: 'identifier-microcomparison',
  fixture,
  privacyValues: Object.values(fixture),
  privacyField: 'identifierOccurrences',
  worker: new URL('./identifiers-worker.mjs', import.meta.url),
  inputs: {
    operations: [
      'uuidV4',
      'uuidV7',
      'parseV4',
      'parseV7',
      'validateV4',
      'validateV7',
      'rejectNoncanonical',
    ],
    fixedCanonicalFixtures: 2,
    uuidVersion: '14.0.3',
    tinybenchVersion: '6.2.2',
    concurrency: 1,
  },
  observationCoverage:
    'Identifier calls are pure helpers without automatic per-call spans or metrics; diagnostic modes install the actual SDK without adding artificial observation work.',
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureComparison } from './pure-comparison.mjs';
import { validationFixture } from './validation-workload.mjs';
await runPureComparison({
  scenarioId: 'validation-microcomparison',
  fixture: validationFixture,
  privacyValues: Object.values(validationFixture).filter((value) => typeof value === 'string'),
  privacyField: 'inputOccurrences',
  worker: new URL('./validation-worker.mjs', import.meta.url),
  inputs: {
    operations: [
      'email',
      'url',
      'ipv4',
      'ipv6',
      'uuid',
      'schema',
      'denyEmail',
      'denyIp',
      'denySchema',
    ],
    fixedInertCorpus: true,
    nativeVersions: { validator: '13.15.35', ipaddr: '2.5.0', ajv: '8.20.0', uuid: '14.0.3' },
    tinybenchVersion: '6.2.2',
    concurrency: 1,
  },
  observationCoverage:
    'Pure validation helpers have no automatic per-call spans or metrics; diagnostic modes install the actual SDK without artificial observation work.',
  limitations:
    'Fixed inert input microcomparison; framework data snapshots, bounds, lifecycle and safe error shaping are additional work. No adversarial input equivalence claim for the bare baseline, production budget, five repetition or soak claim.',
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureComparison } from './pure-comparison.mjs';
import { configFixture } from './config-workload.mjs';
await runPureComparison({
  scenarioId: 'configuration-service-comparison',
  fixture: configFixture,
  privacyValues: [configFixture.marker],
  privacyField: 'inputOccurrences',
  worker: new URL('./config-worker.mjs', import.meta.url),
  inputs: {
    operations: ['get', 'require', 'has', 'snapshot', 'reload'],
    nativeVersions: { yaml: '2.9.1', ajv: '8.20.0' },
    fixedFlatNonsecretCorpus: true,
    constructionExcludedFromSampling: true,
    samplesPerOperation: 1000,
    warmupIterations: 100,
    concurrency: 1,
  },
  observationCoverage:
    'Actual immutable configuration snapshots, precedence and validated reload in four isolated modes. No artificial per-read traces; diagnostic callbacks discard metadata and no secret provider is used.',
  limitations:
    'Fixed flat nonsecret corpus only; bare baseline omits framework protected paths, strict environment parser, secret policy, async preflight and audit policy. Configuration loading and file I/O are not sampled; uniform async sampling wrapper included for all operations. No full reload/security equivalence, release budget or repeated campaign claim.',
});

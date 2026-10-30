// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureComparison } from './pure-comparison.mjs';
import { loggingFixture } from './logging-workload.mjs';
await runPureComparison({
  scenarioId: 'logging-acknowledged-destination-comparison',
  fixture: loggingFixture,
  privacyValues: [loggingFixture.privateValue],
  privacyField: 'privateOccurrences',
  worker: new URL('./logging-worker.mjs', import.meta.url),
  inputs: {
    operations: ['info', 'childInfo'],
    nativeBackend: 'pino10.4.0',
    synchronousAcknowledgingDestination: true,
    sharedJsonValidationCost: true,
    samplesPerOperation: 1000,
    warmupIterations: 100,
    concurrency: 1,
  },
  observationCoverage:
    'Actual Pino/public logging rows reach an acknowledging JSON destination; redaction, level filtering and child bindings checked. Standard/detailed modes use actual SDK without artificial per-log observations.',
  limitations:
    'Fixed structured fields and a synchronous in-memory acknowledging destination only; parsing/validation cost is shared by every profile. No disk/fsync durability, network transport, arbitrary message security-policy equivalence, async-backpressure budget, repeated campaign or release performance acceptance.',
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startKafkaFixture } from './kafka-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete Kafka broker/client sampling remains separate',
);
const observer = await startKafkaFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'kafka-native-tls-sasl-and-independent-receipt-verification',
      fixture: observer.fixture,
      privacyValues: observer.privacyValues,
      privacyField: 'inputOccurrences',
      worker: new URL('./kafka-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: '@confluentinc/kafka-javascript@1.11.0 with the same reviewed corrections',
        recordsPerProfile: 3,
        samplingSupported: false,
      },
      observationCoverage:
        'Four isolated TLS/SASL profiles publish binary, empty and tombstone records with repeated nullable headers. An independent native consumer verifies exact wire data and manually commits observed offsets. Every broker receipt matches the independently consumed partition/offset. Actual SDK exports exclude payloads, identities, keys and connection details.',
      limitations:
        'Producer verification with a fixed corpus on an explicitly owned two-partition fixture. Native baseline omits framework capture, admission, cancellation, lifecycle and uncertain-outcome policy. Observer group commits do not establish public consumer, redelivery, transactional or end-to-end exactly-once parity. No complete broker/client resource accounting, full performance campaign or release acceptance claim.',
    },
    args,
  );
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(observer.verify(), null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await observer.close();
}

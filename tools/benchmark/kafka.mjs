// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startKafkaFixture } from './kafka-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';
import { kafkaIterations, kafkaWarmupIterations } from './kafka-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
const measure = args[0] === '--smoke',
  observer = await startKafkaFixture(measure);
try {
  const report = await runPureComparison(
    {
      scenarioId: 'kafka-native-tls-sasl-and-independent-receipt-verification',
      fixture: observer.fixture,
      privacyValues: observer.privacyValues,
      privacyField: 'inputOccurrences',
      worker: new URL('./kafka-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: '@confluentinc/kafka-javascript@1.11.0 with the same reviewed corrections',
        recordsPerProfile: 3,
        samplingSupported: true,
        measuredSamplesPerProfile: measure ? kafkaIterations : 0,
        warmupPublicationsPerProfile: measure ? kafkaWarmupIterations : 0,
        topicPolicyPrecondition:
          'Owned compacted topic with min.compaction.lag.ms=3600000; all campaign records retained through independent verification',
      },
      observationCoverage:
        'Four isolated TLS/SASL profiles publish binary, empty and tombstone records with repeated nullable headers. An independent native consumer verifies exact wire data and manually commits observed offsets. Every broker receipt matches the independently consumed partition/offset. Actual SDK exports exclude payloads, identities, keys and connection details.',
      limitations:
        'Publisher-receipt verification and optional short sequential sampling on an explicitly owned two-partition fixture. Native baseline omits framework capture, admission, cancellation, lifecycle and uncertain-outcome policy. Every timed callback awaits a broker receipt; independent observation and manual offset matching occur outside timing. Observer group commits do not establish application commitment, public consumer, redelivery, transactional or end-to-end exactly-once parity. Whole child process CPU includes native librdkafka threads; RSS includes native process memory, while JS heap excludes native buffers. Parent observer and broker resources are explicitly unknown and separate. No complete resource parity, dedicated-runner budget, five repetitions, one-hour soak or release acceptance claim.',
    },
    args,
  );
  const expectedRecords = report.records.reduce((sum, row) => {
    const completion = row.completion;
    assert.equal(
      completion.independentConsumerReceiptMatches,
      completion.sampledBrokerAcknowledgments + completion.warmupBrokerAcknowledgments,
    );
    return (
      sum +
      row.verification.actualBrokerAcknowledgments +
      completion.independentConsumerReceiptMatches
    );
  }, 0);
  const observation = observer.verify(expectedRecords),
    encoded = JSON.stringify(observation, null, 2) + '\n';
  for (const value of observer.privacyValues) assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'protocol-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  await observer.close();
}

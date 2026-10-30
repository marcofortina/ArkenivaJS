// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { runPureComparison } from './pure-comparison.mjs';
import { natsConnection } from './nats-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full NATS campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_NATS_BENCHMARK_DISPOSABLE,
    '1',
    'NATS smoke measurements require an explicitly disposable runner',
  );
assert.equal(
  process.env.ARKENIVA_NATS_DISPOSABLE,
  '1',
  'Use only the explicitly owned disposable NATS fixture',
);
const fixture = {
  url: process.env.ARKENIVA_NATS_URL,
  topic: 'comparison.' + randomBytes(16).toString('hex'),
  marker: 'owned-nats-private-payload',
  correlation: 'owned-nats-private-correlation',
};
const url = natsConnection(fixture);
await runPureComparison(
  {
    scenarioId: 'nats-native-mutual-tls-envelope-verification',
    fixture,
    privacyValues: [
      ...Object.values(fixture),
      decodeURIComponent(url.username),
      decodeURIComponent(url.password),
      ...url.searchParams.values(),
      '127.0.0.1',
      'localhost',
    ],
    privacyField: 'inputOccurrences',
    worker: new URL('./nats-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'nats@2.29.3',
      verificationMessagesPerProfile: 2,
      scenarios: ['publish-flush-and-dual-observed-receipt'],
      measuredSamplesPerScenario: measured ? 100 : null,
      warmupCallbacksPerScenario: measured ? 20 : null,
      traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
      concurrency: 1,
      samplingSupported: true,
    },
    observationCoverage:
      'Actual mutual-TLS Core NATS in four isolated profiles. An independent native connection verifies wire envelopes, identifiers and correlation in both directions. Actual SDK exports exclude subjects, payloads, credentials and connection details. Explicit smoke retains actual Tinybench raw latency samples of sequential publication flush plus exact independent native and service-handler observations; actual callback/delivery/encoded-byte counters and physical subscription/connection retirement are checked. STANDARD and DETAILED both use diagnostic trace sampling1.',
    limitations:
      'Bounded valid JSON corpus over scoped Core NATS, not JetStream. Native baseline omits framework capture, hostile-envelope validation, queue admission, cancellation and lifecycle policy. Publish flush and actual observation are separate from broker acknowledgment, which remains false. Timed wall latency includes the publish flush and both actual observations; this is not a broker durable acknowledgment or request/reply benchmark. CPU/RSS covers only the comparison client process and excludes broker/server costs. STANDARD uses diagnostic sampling1 rather than normal production sampling. No delivery persistence, retries, distributed authority, queue/backpressure campaign, complete broker/client CPU accounting, policy-equivalent overhead, calibrated budget, five repetitions or one-hour soak acceptance.',
  },
  args,
);

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startRealtimeFixture } from './realtime-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';
import { realtimeIterations, realtimeWarmupIterations } from './realtime-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
if (args[0] === '--smoke')
  assert.equal(
    process.env.ARKENIVA_REALTIME_BENCHMARK_DISPOSABLE,
    '1',
    'Realtime smoke requires an explicitly disposable measurement environment',
  );
const authority = await startRealtimeFixture(args[0] === '--smoke');
try {
  const report = await runPureComparison(
    {
      scenarioId: 'realtime-native-authenticated-websocket-and-sse-verification',
      fixture: authority.fixture,
      privacyValues: authority.privacyValues,
      privacyField: 'inputOccurrences',
      worker: new URL('./realtime-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: '@fastify/websocket@11.3.4, @fastify/sse@0.6.1, jose@6.2.13',
        sseEvents: 3,
        samplingSupported: true,
        measuredOperation:
          'Finite authenticated SSE HTTP response consumed by an independent parent client',
        samplesPerProfile: args[0] === '--smoke' ? realtimeIterations : 0,
        warmupPerProfile: args[0] === '--smoke' ? realtimeWarmupIterations : 0,
        eventsPerMeasuredStream: 3,
        concurrency: 1,
      },
      observationCoverage:
        'Actual signed-JWT admission precedes native/public WebSocket and SSE traffic. Existing Unicode/multiline/empty SSE frames, owned cursor resume, invalid/expired/foreign cursor rejection, denied anonymous/tampered-token requests and binary WebSocket exchange remain untimed. Optional smoke measures 100 finite SSE responses after 20 warmup callbacks per profile. An independent parent HTTP client reauthenticates through the actual auth service, consumes 480 streams and 1440 exact tenant-scoped events, verifies UTF8 bytes and waits for physical socket closure. Public source callbacks check actual auth-service tenant provenance. Parent observes four worker JWKS fetches plus one independent observer fetch. Actual SDK exports exclude identities, tokens and event data.',
      limitations:
        'Loopback-only test issuer/listeners, no production TLS claim. Finite synthetic source catalog, not actual durable storage or a cross-pod broker. Existing resume controls are functional only; no persistent replay, broadcast, exactly-once or WebSocket performance claim. Native reference omits full runtime identity provenance, connection quotas, backpressure and quarantine policy. Timing includes the authenticated parent observation RPC and complete native-client response/closure; it does not isolate server CPU or SSE encoding latency. Worker CPU/RSS is server-side; parent client/auth/issuer resources remain unknown and excluded. No complete resource or policy parity, calibrated budget, five repetitions, one-hour soak or release acceptance.',
    },
    args,
  );
  const streams = report.records.reduce((sum, row) => {
    assert.equal(
      row.completion.checkedStreams,
      row.completion.sampledStreams + row.completion.warmupStreams,
    );
    return sum + row.completion.checkedStreams;
  }, 0);
  const encoded = JSON.stringify(authority.verify(streams), null, 2) + '\n';
  for (const value of authority.privacyValues) assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'protocol-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  await authority.close();
}

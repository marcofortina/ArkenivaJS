// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startProxyFixture } from './proxy-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';
import { proxyIterations, proxyWarmupIterations } from './proxy-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
if (args[0] === '--smoke')
  assert.equal(
    process.env.ARKENIVA_PROXY_BENCHMARK_DISPOSABLE,
    '1',
    'Proxy smoke requires an explicitly disposable measurement environment',
  );
const authority = await startProxyFixture(undefined, args[0] === '--smoke');
try {
  const report = await runPureComparison(
    {
      scenarioId: 'proxy-native-fixed-https-streaming-verification',
      fixture: authority.fixture,
      privacyValues: [
        ...Object.values(authority.fixture).filter((value) => typeof value === 'string'),
        '127.0.0.1',
        'localhost',
        'foreign.invalid',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./proxy-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: '@fastify/http-proxy@11.6.5',
        requestsPerProfile: 2,
        responseBytesPerProfile: 262144,
        samplingSupported: true,
        measuredOperation:
          'Fixed HTTPS-upstream GET, complete response digest and own HTTP client retirement',
        samplesPerProfile: args[0] === '--smoke' ? proxyIterations : 0,
        warmupPerProfile: args[0] === '--smoke' ? proxyWarmupIterations : 0,
        responseBytesPerSample: 131072,
        concurrency: 1,
      },
      observationCoverage:
        'Actual native/public fixed HTTPS upstream forwarding preserves fragmented binary request/response bodies and raw query multiplicity. Optional100-sample20-warmup GET smoke checks complete131072-byte responses and privately retains compact digests instead of response buffers. Independent parent verifies488 upstream calls including8 original verification calls, exact payload bytes/query and stripped spoofed identity headers, with no pending handlers. Actual SDK exports exclude credentials, destination and payload.',
      limitations:
        'Explicit synthetic public route without authenticated identity delegation, with loopback HTTP ingress and verified HTTPS upstream. Timed work includes the native HTTP observer, response digest and physical own-client retirement; worker resources include both local observer and proxy, while parent HTTPS origin resources remain unknown and excluded. Existing upstream pooling is retained; no fresh-handshake claim. Native reference omits full SSRF/DNS policy, body admission, cancellation, lifecycle and hostile-input guards. Fixed finite corpus only, not arbitrary-response buffering or pressure/saturation proof. Payload counters are not TLS wire-byte accounting. No complete cross-process resource or authorization-policy parity, calibrated matched-load budget, five repetitions, one-hour soak or release acceptance.',
    },
    args,
  );
  const samples = report.records.reduce((sum, row) => {
    assert.equal(
      row.completion.checkedResponses,
      row.completion.sampledGets + row.completion.warmupGets,
    );
    return sum + row.completion.checkedResponses;
  }, 0);
  const encoded = JSON.stringify(authority.verify(4, samples), null, 2) + '\n';
  for (const value of Object.values(authority.fixture).filter((value) => typeof value === 'string'))
    assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'protocol-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  await authority.close();
}

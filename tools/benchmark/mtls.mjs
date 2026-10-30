// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startMtlsFixture } from './mtls-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';
import { mtlsIterations, mtlsWarmupIterations } from './mtls-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
if (args[0] === '--smoke')
  assert.equal(
    process.env.ARKENIVA_MTLS_BENCHMARK_DISPOSABLE,
    '1',
    'mTLS smoke requires an explicitly disposable measurement environment',
  );
const authority = await startMtlsFixture(args[0] === '--smoke');
try {
  const report = await runPureComparison(
    {
      scenarioId: 'mtls-native-two-stage-http2-service-identity-verification',
      fixture: authority.fixture,
      privacyValues: [
        ...Object.values(authority.fixture),
        ...authority.privacyValues,
        'localhost',
        '127.0.0.1',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./mtls-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'node:tls, node:http2, node:crypto and independent OpenSSL PKI authority',
        requestsPerProfile: 1,
        samplingSupported: true,
        measuredOperation:
          'Fresh TLS1.3 mutual handshake, asynchronous peer policy, one HTTP2 response and physical close',
        samplesPerProfile: args[0] === '--smoke' ? mtlsIterations : 0,
        warmupPerProfile: args[0] === '--smoke' ? mtlsWarmupIterations : 0,
        concurrency: 1,
        tlsSessionReuse: false,
      },
      observationCoverage:
        'Four actual TLS1.3 mutual-authentication profiles negotiate HTTP2. Both server and client independently verify actual socket-derived peer DER with chain, purpose and CRL checks before authorized application data. Optional100-sample20-warmup smoke opens a new non-resumed connection for every callback, awaits one exact response and physical session closure. Parent independently counts484 fresh sessions, requests and successful peer checks for each role, one stream per session and zero remaining sessions/provider work. Actual SDK exports exclude identities, credentials, certificate fingerprints and endpoint.',
      limitations:
        'Owned test-only private PKI, single explicit profile and fixed valid request. Timed work includes material preparation, native mutual handshake, asynchronous application peer policy, HTTP2 response and physical close; it does not isolate TLS handshake latency. Native baseline omits full framework material validation, generation provenance, atomic reload, runtime admission and cancellation policy. Worker resources exclude parent HTTP2 server, PKI provider and its native OpenSSL descendants, whose CPU/RSS remain unknown. No mesh/proxy identity claim, production provider, complete process-tree resource parity, calibrated budget, five repeats or one-hour soak acceptance.',
    },
    args,
  );
  const sampled = report.records.reduce((sum, row) => {
    assert.equal(
      row.completion.checkedExchanges,
      row.completion.sampledHandshakes + row.completion.warmupHandshakes,
    );
    return sum + row.completion.checkedExchanges;
  }, 0);
  const encoded = JSON.stringify(authority.verify(4 + sampled), null, 2) + '\n';
  for (const value of [...Object.values(authority.fixture), ...authority.privacyValues])
    assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'protocol-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  await authority.close();
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startMtlsFixture } from './mtls-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete mTLS provider/server resource accounting remains separate',
);
const authority = await startMtlsFixture();
try {
  await runPureComparison(
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
        samplingSupported: false,
      },
      observationCoverage:
        'Four actual TLS 1.3 mutual-authentication profiles negotiate HTTP/2. Both server and client independently verify actual socket-derived peer DER with chain, purpose and CRL checks before authorized application data. Parent counts four requests and both roles policy checks. Actual SDK exports exclude identities, credentials, certificate fingerprints and endpoint.',
      limitations:
        'Owned test-only private PKI, single explicit profile and fixed valid request. Native baseline omits full framework material validation, generation provenance, atomic reload, runtime admission and cancellation policy. No mesh/proxy identity claim, production provider, complete cross-process resource sampling, five repeats or one-hour soak acceptance.',
    },
    args,
  );
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(authority.verify(4), null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}

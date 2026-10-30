// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startProxyFixture } from './proxy-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete proxy process resource accounting remains separate',
);
const authority = await startProxyFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'proxy-native-fixed-https-streaming-verification',
      fixture: authority.fixture,
      privacyValues: [
        ...Object.values(authority.fixture),
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
        samplingSupported: false,
      },
      observationCoverage:
        'Actual native/public fixed HTTPS upstream forwarding preserves fragmented binary request/response bodies and raw query multiplicity. Independent parent verifies eight upstream calls, exact bytes and stripped spoofed identity headers. Actual SDK exports exclude credentials, destination and payload.',
      limitations:
        'Explicit synthetic public route without authenticated identity delegation. Native reference uses a fixed valid origin and small header allowlist; it omits full SSRF/DNS policy, body admission, cancellation, lifecycle and hostile-input guards. No full cross-process resource sampling, matched-load performance campaign or release acceptance.',
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

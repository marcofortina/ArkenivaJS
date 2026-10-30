// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startGrpcFixture } from './grpc-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete gRPC resource sampling remains separate',
);
const authority = await startGrpcFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'grpc-native-mutual-tls-unary-and-stream-verification',
      fixture: authority.fixture,
      privacyValues: [
        ...Object.values(authority.fixture),
        ...authority.privacyValues,
        '127.0.0.1',
        'localhost',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./grpc-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: '@grpc/grpc-js@1.14.6 and @grpc/proto-loader@0.8.1',
        callsPerProfile: 2,
        streamedMessagesPerProfile: 3,
        concurrency: 1,
        samplingSupported: false,
      },
      observationCoverage:
        'Four actual mutual-TLS gRPC profiles verify native client identity, unary int64/string and binary fidelity, ordered server streaming and independent parent call counts. Framework peers additionally complete the existing native OpenSSL path/CRL provider through an authenticated private test bridge. Actual SDK exports exclude payloads, endpoints, key material and provider data.',
      limitations:
        'Small valid protobuf corpus and test-only external credential/trust providers. Native grpc-js baseline verifies certificate trust/hostname but omits framework asynchronous CRL/identity policy, immutable descriptor capture, admission, cancellation and lifecycle checks. No authenticated application/tenant authority is granted or claimed. No bidi, distributed identity, complete client/server resource sampling, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
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

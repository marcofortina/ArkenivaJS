// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startGrpcFixture } from './grpc-fixture.mjs';
import { requireGrpcProcessTreeResource } from './grpc-workload.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full gRPC campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_GRPC_BENCHMARK_DISPOSABLE,
    '1',
    'gRPC smoke measurements require an explicitly disposable runner',
  );
const authority = await startGrpcFixture();
try {
  const report = await runPureComparison(
    {
      scenarioId: 'grpc-native-mutual-tls-unary-and-stream-verification',
      superviseProcessTree: true,
      fixture: authority.fixture,
      privacyValues: authority.privacyValues,
      privacyField: 'inputOccurrences',
      worker: new URL('./grpc-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: '@grpc/grpc-js@1.14.6 and @grpc/proto-loader@0.8.1',
        verificationCallsPerProfile: 2,
        scenarios: ['mutual-tls-unary-bounce'],
        measuredSamplesPerScenario: measured ? 100 : null,
        warmupCallbacksPerScenario: measured ? 20 : null,
        traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
        streamedMessagesPerProfile: 3,
        concurrency: 1,
        samplingSupported: true,
      },
      observationCoverage:
        'Four actual mutual-TLS gRPC profiles verify native client identity, unary int64/string and binary fidelity, ordered server streaming and independent parent call counts. Framework peers additionally complete the existing native OpenSSL path/CRL provider through an authenticated private test bridge. Actual SDK exports exclude payloads, endpoints, key material and provider data. Explicit smoke retains actual Tinybench unary latency samples and exact callback counts; the independent server validates full decoded protobuf inputs/outputs and aggregate fixture receipt integrity. Existing ordered stream verification remains outside samples. Every measured profile requires supervised whole-process lifecycle resources and physical cleanup. STANDARD and DETAILED both use diagnostic trace sampling1.',
      limitations:
        'Small valid protobuf corpus and test-only external credential/trust providers. Native grpc-js baseline verifies certificate trust/hostname but omits framework asynchronous CRL/identity policy, immutable descriptor capture, admission, cancellation and lifecycle checks. No authenticated application/tenant authority is granted or claimed. No bidi, distributed identity, complete client/server cost accounting, policy-equivalent overhead, calibrated budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  if (measured)
    for (const row of report.records) requireGrpcProcessTreeResource(row.processTreeResource);
  const protocol = authority.verify(
    report.records.length,
    report.records.map((row) => row.completion),
    measured,
  );
  await authority.close();
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(protocol, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}

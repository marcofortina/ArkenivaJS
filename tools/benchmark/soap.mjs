// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startSoapFixture } from './soap-fixture.mjs';
import { requireSoapProcessTreeResource } from './soap-workload.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full SOAP campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_SOAP_BENCHMARK_DISPOSABLE,
    '1',
    'SOAP smoke measurements require an explicitly disposable runner',
  );
const authority = await startSoapFixture();
try {
  const report = await runPureComparison(
    {
      scenarioId: 'soap-native-verified-https-interoperability',
      superviseProcessTree: true,
      fixture: authority.fixture,
      privacyValues: authority.privacyValues,
      privacyField: 'inputOccurrences',
      worker: new URL('./soap-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'soap@1.14.0 and axios@1.20.0 with the same reviewed patches',
        protocol: '1.1',
        binding: 'document/literal',
        verificationCallsPerProfile: 2,
        scenarios: ['read-stock-verified-https'],
        measuredSamplesPerScenario: measured ? 100 : null,
        warmupCallbacksPerScenario: measured ? 20 : null,
        traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
        concurrency: 1,
        samplingSupported: true,
      },
      observationCoverage:
        'Four real verified-HTTPS SOAP profiles use the compiled conformance WSDL and native server. Actual native client identity, approved operation, decoded scalar, HTTP status and distinct correlations are checked. Parent independently verifies exact decoded Unicode inputs, numeric output and fixture-owned response receipt correlations. Explicit smoke retains actual Tinybench latency samples and exact callback counts with bounded aggregate receipt integrity. All measured profiles require supervised whole-process lifecycle observations and physical cleanup. STANDARD and DETAILED both use diagnostic trace sampling1. Actual SDK exports exclude WSDL paths, endpoint and payload.',
      limitations:
        'Small document/literal SOAP 1.1 corpus without authentication secrets beyond the explicit test trust anchor. Native baseline omits framework immutable WSDL capture, import allowlist, input/scalar/fault security policy, bounded parser isolation, admission and lifecycle checks. No SOAP 1.2/RPC equivalence, WS-Security, server resource accounting, policy-equivalent overhead, calibrated budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  if (measured)
    for (const row of report.records) requireSoapProcessTreeResource(row.processTreeResource);
  await authority.quiescent();
  const completions = report.records.map((row) => row.completion),
    expectedCalls = completions.reduce((sum, row) => sum + row.totalCalls, 0);
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(authority.verify(expectedCalls, completions, measured), null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}

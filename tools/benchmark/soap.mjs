// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startSoapFixture } from './soap-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete SOAP resource sampling remains separate',
);
const authority = await startSoapFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'soap-native-verified-https-interoperability',
      fixture: authority.fixture,
      privacyValues: [...Object.values(authority.fixture), '127.0.0.1', 'localhost'],
      privacyField: 'inputOccurrences',
      worker: new URL('./soap-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'soap@1.14.0 and axios@1.20.0 with the same reviewed patches',
        protocol: '1.1',
        binding: 'document/literal',
        callsPerProfile: 2,
        concurrency: 1,
        samplingSupported: false,
      },
      observationCoverage:
        'Four real verified-HTTPS SOAP profiles use the compiled conformance WSDL and native server. Actual native client identity, approved operation, decoded scalar, HTTP status and distinct correlations are checked. Parent independently verifies all eight distinct-input calls. Actual SDK exports exclude WSDL paths, endpoint and payload.',
      limitations:
        'Small document/literal SOAP 1.1 corpus without authentication secrets beyond the explicit test trust anchor. Native baseline omits framework immutable WSDL capture, import allowlist, input/scalar/fault security policy, bounded parser isolation, admission and lifecycle checks. No SOAP 1.2/RPC equivalence, WS-Security, complete worker/server resource sampling, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(authority.verify(8), null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}

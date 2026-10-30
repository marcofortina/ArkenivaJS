// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startDnsFixture } from '../../examples/dns/dist/fixture.js';
import { runPureComparison } from './pure-comparison.mjs';
import { dnsTypes } from './dns-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
const before = dns.getServers(),
  authority = await startDnsFixture();
try {
  const fixture = { server: authority.server, hostname: 'internal.test' };
  const report = await runPureComparison(
    {
      scenarioId: 'dns-protocol-comparison',
      fixture,
      privacyValues: [fixture.server, fixture.hostname, '192.0.2.', '198.51.100.', '127.0.0.1'],
      privacyField: 'inputOccurrences',
      worker: new URL('./dns-worker.mjs', import.meta.url),
      inputs: {
        operations: [
          ...dnsTypes.map((type) => 'resolve' + type),
          'lookupOs',
          'reverse',
          'resolverNames',
        ],
        nativeBackend: 'node:dns/promises c-ares and getaddrinfo',
        deterministicFreshNames: true,
        samplesPerOperation: 100,
        warmupIterations: 20,
        concurrency: 1,
      },
      observationCoverage:
        'The actual DNS plugin records bounded operation diagnostics in standard/detailed profiles; native protocol queries use one owned nonforwarding loopback authority. No global resolver changes.',
      limitations:
        'Local controlled DNS protocol smoke; fresh deterministic query names reduce cache effects. Not external DNS latency, DNSSEC, SSRF authorization, startup/shutdown overhead, release budget, five repetitions or soak evidence.',
    },
    args,
  );
  assert.ok(report.records.every((row) => row.verification.globalResolversUnchanged));
  assert.ok(
    authority.requests >= 48,
    'The verification must reach the actual DNS authority in every profile',
  );
  if (args[0] === '--smoke')
    assert.ok(authority.requests >= 4800, 'Sampling must perform actual completed DNS work');
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(
      {
        receivedDnsRequests: authority.requests,
        forwardedRequests: 0,
        globalResolversUnchanged: JSON.stringify(dns.getServers()) === JSON.stringify(before),
        releaseGate: false,
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
  assert.deepEqual(dns.getServers(), before);
}

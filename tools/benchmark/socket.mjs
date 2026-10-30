// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; socket performance accounting remains separate',
);
const directory = await mkdtemp('/tmp/arkenivajs-socket-comparison-');
const fixture = {
  directory,
  certificateFile: join(directory, 'server.pem'),
  privateKeyFile: join(directory, 'server.key'),
  marker: randomBytes(24).toString('hex'),
};
try {
  await chmod(directory, 0o700);
  await promisify(execFile)(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-days',
      '1',
      '-subj',
      '/CN=Owned Socket Comparison',
      '-addext',
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
      '-keyout',
      fixture.privateKeyFile,
      '-out',
      fixture.certificateFile,
    ],
    { timeout: 10000, maxBuffer: 65536 },
  );
  await chmod(fixture.privateKeyFile, 0o600);
  await runPureComparison(
    {
      scenarioId: 'socket-native-independent-client-verification',
      fixture,
      privacyValues: [...Object.values(fixture), '127.0.0.1', 'localhost'],
      privacyField: 'inputOccurrences',
      worker: new URL('./socket-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'Node net, tls and dgram',
        scenarios: ['tcp64', 'tcp65536', 'tls64', 'udp256', 'unix4096'],
        independentClientProcess: true,
        concurrency: 1,
        testCertificateKey: 'EC P-256',
        samplingSupported: false,
      },
      observationCoverage:
        'Actual independent-process native clients verify byte identity over five transport scenarios in four isolated server profiles; real listener counters, TLS hostname rejection, closed handles and Unix path retirement are checked. SDK exports exclude payloads and endpoints.',
      limitations:
        'Bounded functional echo only; raw stream chunks are never treated as framed messages. Native Node baseline omits framework admission, bounded queues, cancellation and lifecycle checks. UDP proves only the observed local request/reply, with no end-to-end reliability or OS-loss claim. No sampled first-byte latency, handshake rate, backpressure campaign, independent-process CPU accounting, dedicated-runner budgets, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}

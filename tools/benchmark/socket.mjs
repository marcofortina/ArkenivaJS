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
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
assert.ok(
  args[0] !== '--smoke' || process.env.ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE === '1',
  'Socket smoke requires an explicitly disposable measurement environment',
);
const directory = await mkdtemp('/tmp/arkenivajs-socket-comparison-');
const fixture = {
  directory,
  certificateFile: join(directory, 'server.pem'),
  privateKeyFile: join(directory, 'server.key'),
  marker: randomBytes(24).toString('hex'),
  sampleEcho: args[0] === '--smoke',
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
      privacyValues: [
        ...Object.values(fixture).filter((value) => typeof value === 'string'),
        '127.0.0.1',
        'localhost',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./socket-worker.mjs', import.meta.url),
      superviseProcessTree: true,
      inputs: {
        nativeBackend: 'Node net, tls and dgram',
        scenarios: ['tcp64', 'tcp65536', 'tls64', 'udp256', 'unix4096'],
        independentClientProcess: true,
        concurrency: 1,
        testCertificateKey: 'EC P-256',
        samplingSupported: true,
        measuredScenario: 'TCP64 independent client process lifecycle and echo',
        samplesPerProfile: args[0] === '--smoke' ? 100 : 0,
        warmupEchoesPerProfile: args[0] === '--smoke' ? 20 : 0,
      },
      observationCoverage:
        'Actual independent-process native clients verify byte identity over five transport scenarios in four isolated server profiles; real listener counters, TLS hostname rejection, closed handles and Unix path retirement are checked. Optional TCP64 smoke awaits120 distinct client process lifecycles, verifies every exact echo and reconciles independent listener byte/connection counters before physical closure. Supervision includes server worker and actual descendant clients. SDK exports exclude payloads and endpoints.',
      limitations:
        'The bounded TCP64 scenario includes child process startup, IPC, connection, echo and physical client exit in each Tinybench callback; it is not steady-connection echo latency. Client first-byte and exchange observations start after native socket construction and exclude process startup/IPC. Other transport scenarios remain verification only. Raw stream chunks are never treated as framed messages. Native Node baseline omits framework admission, bounded queues, cancellation and lifecycle checks. UDP proves only observed local request/reply, with no reliability or OS-loss claim. Sampled summed RSS is not exact peak/PSS; opaque kernel buffers remain unknown. No handshake-rate, backpressure campaign, calibrated policy-equivalent overhead, dedicated-runner budgets, five repetitions, one-hour soak or release acceptance.',
    },
    args,
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}

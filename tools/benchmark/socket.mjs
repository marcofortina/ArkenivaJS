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
  args.length === 2 && ['--verify', '--smoke', '--smoke-unix', '--smoke-tls'].includes(args[0]),
  'Use --verify, --smoke, --smoke-unix or --smoke-tls with a fresh absolute external report directory',
);
const measure = args[0] !== '--verify',
  unix = args[0] === '--smoke-unix',
  tls = args[0] === '--smoke-tls';
assert.ok(
  !measure || process.env.ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE === '1',
  'Socket smoke requires an explicitly disposable measurement environment',
);
assert.ok(!unix || process.platform === 'linux', 'Unix socket sampling requires Linux');
const directory = await mkdtemp('/tmp/arkenivajs-socket-comparison-');
const fixture = {
  directory,
  certificateFile: join(directory, 'server.pem'),
  privateKeyFile: join(directory, 'server.key'),
  marker: randomBytes(24).toString('hex'),
  sampleEcho: measure,
  sampleUnixEcho: unix,
  ...(tls ? { sampleTlsEcho: true } : {}),
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
      scenarioId: unix
        ? 'socket-unix-independent-client-lifecycle'
        : tls
          ? 'socket-tls-independent-client-lifecycle'
          : 'socket-native-independent-client-verification',
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
        measuredScenario: unix
          ? 'Unix4096 independent client process lifecycle and echo'
          : tls
            ? 'TLS64 independent client process lifecycle, handshake and echo'
            : 'TCP64 independent client process lifecycle and echo',
        ...(unix ? { sampledTransport: 'unix', sampledPayloadBytes: 4096 } : {}),
        ...(tls
          ? {
              sampledTransport: 'tls',
              sampledPayloadBytes: 64,
              minimumTlsVersion: 'TLSv1.3',
              sessionReuseAllowed: false,
              hostnameVerificationRequired: true,
            }
          : {}),
        samplesPerProfile: measure ? 100 : 0,
        warmupEchoesPerProfile: measure ? 20 : 0,
      },
      observationCoverage:
        'Actual independent-process native clients verify byte identity over five transport scenarios in four isolated server profiles; real listener counters, TLS hostname rejection, closed handles and Unix path retirement are checked. Optional ' +
        (unix ? 'Unix4096' : tls ? 'TLS64' : 'TCP64') +
        ' smoke awaits120 distinct client process lifecycles, verifies every exact echo and reconciles independent listener byte/connection counters before physical closure. ' +
        (unix
          ? 'The sampled Unix socket has owned mode0600 and a stable device/inode before close; its path must be absent afterward. '
          : '') +
        (tls
          ? 'Every sampled TLS client reports an authorized nonresumed TLS1.3 handshake, actual cipher and certificate key metadata; separate monotonic TCP-connect, handshake and payload timing windows are retained. '
          : '') +
        'Supervision includes server worker and actual descendant clients. SDK exports exclude payloads and endpoints.',
      limitations:
        'The bounded ' +
        (unix ? 'Unix4096' : tls ? 'TLS64' : 'TCP64') +
        ' scenario includes child process startup, IPC, connection, echo and physical client exit in each Tinybench callback; it is not steady-connection echo latency. Client first-byte and exchange observations start after native socket construction and exclude process startup/IPC. ' +
        (tls
          ? 'Additional TLS connect-origin timings begin before client construction after CA reading; handshake timing spans TCP connect through secureConnect, while payload timings begin at secureConnect. Certificate metadata inspection is outside those TLS event windows but remains inside full child lifecycle latency. '
          : '') +
        'Other transport scenarios remain verification only. Raw stream chunks are never treated as framed messages. Native Node baseline omits framework admission, bounded queues, cancellation and lifecycle checks. UDP proves only observed local request/reply, with no reliability or OS-loss claim. Sampled summed RSS is not exact peak/PSS; opaque kernel buffers remain unknown. No handshake-rate, backpressure campaign, calibrated policy-equivalent overhead, dedicated-runner budgets, five repetitions, one-hour soak or release acceptance.',
    },
    unix || tls ? ['--smoke', args[1]] : args,
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}

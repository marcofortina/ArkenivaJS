// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { runPureComparison } from './pure-comparison.mjs';
import { sftpSettings, nativeSftp } from './sftp-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; streaming performance sampling remains separate',
);
assert.ok(process.env.ARKENIVA_SFTP_FIXTURE, 'The owned private SFTP fixture metadata is required');
const metadata = JSON.parse(await readFile(process.env.ARKENIVA_SFTP_FIXTURE, 'utf8')),
  key = await readFile(metadata.privateKeyFile);
try {
  const fixture = {
    ...Object.fromEntries(
      ['host', 'port', 'username', 'pins', 'root'].map((name) => [name, metadata[name]]),
    ),
    encodedKey: key.toString('base64'),
    fileStem: 'owned-comparison-' + randomBytes(16).toString('hex'),
    marker: 'owned-sftp-private-content',
    command: "owned-ssh-literal ' ; $(printf unexpected)",
  };
  const owner = sftpSettings(fixture);
  owner.close();
  await runPureComparison(
    {
      scenarioId: 'sftp-ssh-native-server-verification',
      fixture,
      privacyValues: [
        fixture.encodedKey,
        fixture.username,
        fixture.root,
        fixture.fileStem,
        fixture.marker,
        fixture.command,
        ...fixture.pins,
        ...key
          .toString('utf8')
          .split(/\r?\n/)
          .filter((line) => line.length > 20),
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./sftp-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'ssh2-sftp-client@12.1.1 with shell-quote@1.12.0',
        operations: ['upload', 'list', 'rename', 'download', 'exec'],
        sourceChunkBytesMaximum: 8192,
        concurrency: 1,
        samplingSupported: false,
      },
      observationCoverage:
        'Actual pinned-key OpenSSH uploads/downloads, remote size/readback, exact hashes, acknowledged rename and literal allowed command in four isolated profiles; real SDK export privacy.',
      limitations:
        'Synthetic file and owned test account only. Native baseline uses SDK streams and quoting but omits framework path/metadata, admission, cancellation and lifecycle policy. Standard rename acknowledgement is not an atomic or durable-publication guarantee. No first-byte, backpressure-duration, peak-buffer, throughput, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const inspection = await nativeSftp(fixture);
  try {
    for (const suffix of ['.part', '.ready'])
      assert.equal(
        await inspection.files
          .native('owned')
          .exists(fixture.root + '/' + fixture.fileStem + suffix),
        false,
      );
  } finally {
    await inspection.close();
  }
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify({ ownedFilesRemaining: 0, releaseGate: false }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  key.fill(0);
}

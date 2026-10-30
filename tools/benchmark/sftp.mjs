// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { runPureComparison } from './pure-comparison.mjs';
import {
  sftpSettings,
  nativeSftp,
  sftpCorpus,
  sftpSamplePath,
  inspectSftpFile,
  sftpSampleBytes,
  sftpPressureBytes,
} from './sftp-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full SFTP campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_SFTP_BENCHMARK_DISPOSABLE,
    '1',
    'SFTP smoke measurements require an explicitly disposable runner',
  );
assert.ok(process.env.ARKENIVA_SFTP_FIXTURE, 'The owned private SFTP fixture metadata is required');
const metadata = JSON.parse(await readFile(process.env.ARKENIVA_SFTP_FIXTURE, 'utf8')),
  key = await readFile(metadata.privateKeyFile);
let fixture;
const prepared = new Set(),
  readbacks = [];
try {
  fixture = {
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
  if (measured) {
    const preparation = await nativeSftp(fixture);
    try {
      const client = preparation.files.native('owned');
      for (const pressure of [false, true]) {
        const path = sftpSamplePath(fixture, pressure),
          data = sftpCorpus(fixture, pressure ? sftpPressureBytes : sftpSampleBytes);
        assert.equal(await client.exists(path), false);
        // Only exact absent random paths submitted with exclusive creation become cleanup candidates.
        prepared.add(path);
        await preparation.files.upload(
          'owned',
          {
            async *[Symbol.asyncIterator]() {
              for (let offset = 0; offset < data.length; offset += 8192)
                yield data.subarray(offset, offset + 8192);
            },
          },
          path,
        );
        readbacks.push({
          phase: 'before-profiles',
          ...(await inspectSftpFile(client, fixture, pressure)),
        });
      }
    } finally {
      await preparation.close();
    }
  }
  await runPureComparison(
    {
      scenarioId: 'sftp-ssh-native-server-verification',
      superviseProcessTree: true,
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
        samplingSupported: true,
        measuredScenarios: ['download-validated-byte-stream'],
        measuredSamplesPerScenario: measured ? 100 : null,
        warmupCallbacksPerScenario: measured ? 20 : null,
        measuredFileBytes: measured ? sftpSampleBytes : null,
        downloadHighWaterMarkBytes: 65536,
        expectedCorpusPreparedOutsideTiming: true,
        clientTcpNoDelay: measured ? true : null,
        pressureFileBytes: measured ? sftpPressureBytes : null,
        pressureConsumerHoldMs: measured ? 50 : null,
        uploadTimingSupported: false,
        readAheadObservationScope: 'client-sdk-readable-only',
        traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
      },
      observationCoverage:
        'Actual pinned-key OpenSSH uploads/downloads, remote size/readback, exact hashes, acknowledged rename and literal allowed command in four isolated profiles; real SDK export privacy. Explicit smoke retains actual Tinybench download samples, first delivered byte, total duration, actual byte/chunk counters and receipt integrity. Separate pressure probe holds only a real destination callback and passively observes a pre-EOF plateau in the pinned SDK Readable byte counter/queue. All profiles require supervised client lifecycle resources and physical stream retirement.',
      limitations:
        'Synthetic files and owned test account only. Native baseline uses SDK streams and quoting but omits framework path/metadata, admission, cancellation and lifecycle policy. All measured clients explicitly use documented ssh2 Client.setNoDelay(true) before callbacks; these tuned diagnostic results are not default socket performance. Download latency includes bounded consumer equality/SHA checks; setup uploads and independent native readbacks are outside timing. STANDARD and DETAILED both force diagnostic sampling1. Passively sampled SDK readableLength is not exact peak memory: opaque SSH/socket/server buffers remain null and remote producer pressure is not established. External OpenSSH/container CPU/RSS, parent observer and collector are excluded. Standard rename acknowledgement is not atomic or durable publication. Upload timing, full policy equivalence, calibrated throughput/memory budgets, five repetitions and one-hour soak remain separate.',
    },
    args,
  );
  const inspection = await nativeSftp(fixture);
  try {
    const client = inspection.files.native('owned');
    if (measured)
      for (const pressure of [false, true])
        readbacks.push({
          phase: 'after-profiles',
          ...(await inspectSftpFile(client, fixture, pressure)),
        });
    for (const suffix of ['.part', '.ready'])
      assert.equal(
        await inspection.files
          .native('owned')
          .exists(fixture.root + '/' + fixture.fileStem + suffix),
        false,
      );
    for (const path of prepared) {
      await client.delete(path, true);
      assert.equal(await client.exists(path), false);
    }
    prepared.clear();
  } finally {
    await inspection.close();
  }
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(
      {
        ownedFilesRemaining: 0,
        releaseGate: false,
        ...(measured
          ? { independentReadbacks: readbacks, externalServerResourcesIncluded: false }
          : {}),
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  try {
    if (prepared.size > 0) {
      const cleanup = await nativeSftp(fixture);
      try {
        const client = cleanup.files.native('owned');
        for (const path of prepared) {
          await client.delete(path, true);
          assert.equal(await client.exists(path), false);
        }
      } finally {
        await cleanup.close();
      }
    }
  } finally {
    key.fill(0);
  }
}

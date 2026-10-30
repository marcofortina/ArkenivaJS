// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { sftpPlugin } from '@arkenivajs/sftp';
import { sftpSettings, nativeSftp } from '../sftp-workload.mjs';

test(
  'Native and public SFTP comparisons reject an incorrect host pin against a healthy owned server',
  { timeout: 15000 },
  async () => {
    assert.ok(process.env.ARKENIVA_SFTP_FIXTURE);
    const metadata = JSON.parse(await readFile(process.env.ARKENIVA_SFTP_FIXTURE, 'utf8')),
      key = await readFile(metadata.privateKeyFile);
    let app, owner;
    try {
      const fixture = {
        ...metadata,
        encodedKey: key.toString('base64'),
        fileStem: 'owned-comparison-' + randomBytes(16).toString('hex'),
      };
      const healthy = await nativeSftp(fixture);
      await healthy.close();
      const invalid = {
        ...fixture,
        pins: ['SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, '')],
      };
      await assert.rejects(nativeSftp(invalid));
      owner = sftpSettings(invalid);
      app = await createApplication({
        service: { name: 'sftp-comparison-wrong-pin', version: '1.0.0', environment: 'test' },
        plugins: [sftpPlugin(owner.settings)],
      });
      await assert.rejects(app.start());
    } finally {
      try {
        await app?.stop();
      } finally {
        owner?.close();
        key.fill(0);
      }
    }
  },
);

test(
  'Four OpenSSH profiles prove real file data, literal commands, private SDK exports and remote cleanup',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-sftp-harness-')),
      script = fileURLToPath(new URL('../sftp.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      const protocol = JSON.parse(
        await readFile(join(output, 'protocol-observation.json'), 'utf8'),
      );
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.deepEqual(protocol, { ownedFilesRemaining: 0, releaseGate: false });
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.doesNotMatch(
        encoded,
        /owned-sftp-private-content|owned-ssh-literal|BEGIN OPENSSH PRIVATE KEY|owned-comparison-/,
      );
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.records.length, 0);
        assert.deepEqual(row.verification, {
          actualTransferredBytes: Buffer.byteLength('owned-sftp-private-content') * 4096,
          sourceConsumedOnce: true,
          remoteListingVerified: true,
          renameObserved: true,
          awaitedDownloadVerified: true,
          nativeDigestsMatched: true,
          literalCommandVerified: true,
        });
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      const rejected = join(directory, 'sample');
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', rejected], {
          timeout: 5000,
          maxBuffer: 1048576,
        }),
      );
      await assert.rejects(access(rejected), { code: 'ENOENT' });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

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
import { createApplication } from '@arkenivajs/core';
import { mailPlugin, MAIL_CAPABILITY } from '@arkenivajs/mail';
import { startMailFixture } from '../mail-fixture.mjs';
import { nativeMail, mailSettings, mailPrivateValues } from '../mail-workload.mjs';

test(
  'Owned SMTP verification rejects an untrusted root and removes its private fixture',
  { timeout: 15000 },
  async () => {
    const before = process.env.NODE_EXTRA_CA_CERTS,
      authority = await startMailFixture(),
      native = nativeMail(authority.fixture),
      app = await createApplication({
        service: { name: 'mail-untrusted-comparison', version: '1.0.0', environment: 'test' },
        plugins: [mailPlugin(mailSettings(authority.fixture))],
      });
    try {
      await app.start();
      await assert.rejects(native.verifyTransport());
      assert.equal((await app.resolve(MAIL_CAPABILITY).verifyTransport()).available, false);
      assert.equal(authority.state.authentications, 0);
      assert.equal(authority.state.acceptedMessages, 0);
      assert.equal(process.env.NODE_EXTRA_CA_CERTS, before);
    } finally {
      native.close();
      await app.stop();
      await authority.close();
    }
    await assert.rejects(access(authority.trustAnchorFile), { code: 'ENOENT' });
  },
);

test(
  'Four SMTP profiles prove received TLS MIME work and exclude all private message data',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mail-harness-')),
      script = fileURLToPath(new URL('../mail.mjs', import.meta.url)),
      before = process.env.NODE_EXTRA_CA_CERTS;
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded),
        protocol = JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8'));
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(protocol.acceptedMessages, 8);
      assert.equal(protocol.attachmentBytes, 48);
      assert.ok(protocol.authentications >= 4);
      assert.equal(protocol.secureSessions, protocol.authentications);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      for (const value of mailPrivateValues) assert.equal(encoded.includes(value), false);
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.records.length, 0);
        assert.deepEqual(row.verification, {
          checkedMessages: 2,
          actualTransportVerified: true,
          streamedAttachments: true,
        });
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
      assert.equal(process.env.NODE_EXTRA_CA_CERTS, before);
      const rejected = join(directory, 'sample'),
        env = { ...process.env };
      delete env.ARKENIVA_MAIL_BENCHMARK_DISPOSABLE;
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', rejected], {
          env,
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

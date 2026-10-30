// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Readable } from 'node:stream';
import nodemailer from 'nodemailer';
import { simpleParser } from 'mailparser';
import {
  mailMessage,
  attachmentBytes,
  mailPrivateValues,
  mailReceiptDigest,
  verifyMailReceipt,
  verifyMail,
  mailWorkload,
  mailObservations,
} from '../mail-workload.mjs';

test('SMTP entry rejects unsupported campaigns and unmarked smoke before certificate or evidence creation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mail-entry-')),
    env = { ...process.env };
  delete env.ARKENIVA_MAIL_BENCHMARK_DISPOSABLE;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../mail.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full SMTP campaigns remain separate|explicitly disposable runner/.test(error.stderr),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Untimed SMTP helper accounting consumes fresh attachment streams and retains only aggregate receipt integrity', async () => {
  const ids = [];
  // This unit double checks helper accounting only; it is not SMTP or performance evidence.
  const service = {
    async verifyTransport() {
      return { available: true, checkedAt: new Date().toISOString() };
    },
    async send(message) {
      const chunks = [];
      for await (const chunk of message.attachments[0].content.stream) chunks.push(chunk);
      assert.deepEqual(Buffer.concat(chunks), attachmentBytes);
      const transportId = '<' + randomUUID() + '@unit.invalid>';
      ids.push(transportId);
      return {
        outcome: 'accepted',
        accepted: [mailPrivateValues[2]],
        rejected: [],
        transportId,
        sentAt: new Date().toISOString(),
      };
    },
  };
  await verifyMail(service);
  assert.equal(await mailWorkload(service)['smtp-accepted-streamed-attachment'](), true);
  const observed = mailObservations(service, { measure: false, records: [] });
  assert.deepEqual(observed, {
    actualSubmissionCallbacks: 1,
    acceptedSubmissions: 1,
    verificationAccepted: 2,
    totalReceipts: 3,
    receiptDigest: mailReceiptDigest(ids),
    expectedAttachmentBytes: 18,
    activeCallbacks: 0,
    peakConcurrentCallbacks: 1,
    retainedReceiptIds: 0,
  });
  for (const id of ids) assert.equal(JSON.stringify(observed).includes(id), false);
  for (const value of mailPrivateValues)
    assert.equal(JSON.stringify(observed).includes(value), false);
  assert.notEqual(mailReceiptDigest(ids), mailReceiptDigest([...ids].reverse()));
  assert.throws(() => mailReceiptDigest(Array(513).fill('overflow')));
});

test('SMTP acceptance validation rejects partial recipients, absent receipts and malformed timestamps', () => {
  const accepted = {
    outcome: 'accepted',
    accepted: [mailPrivateValues[2]],
    rejected: [],
    transportId: '<unit@invalid>',
    sentAt: new Date().toISOString(),
  };
  assert.equal(verifyMailReceipt(accepted), accepted.transportId);
  for (const changed of [
    { ...accepted, outcome: 'partial' },
    { ...accepted, accepted: ['foreign@example.test'] },
    { ...accepted, rejected: [mailPrivateValues[2]] },
    { ...accepted, transportId: undefined },
    { ...accepted, transportId: 'bad\r\nreceipt' },
    { ...accepted, sentAt: 'invalid-time' },
  ])
    assert.throws(() => verifyMailReceipt(changed));
});

test('Pinned MIME generation preserves fixture text and binary attachment without any SMTP transport', async () => {
  const message = mailMessage(),
    transport = nodemailer.createTransport({
      streamTransport: true,
      buffer: true,
      newline: 'windows',
    });
  try {
    const encoded = await transport.sendMail({
      from: message.from.address,
      to: message.to.map((value) => value.address),
      subject: message.subject,
      text: message.text,
      attachments: message.attachments.map((entry) => ({
        filename: entry.filename,
        content: Readable.from(entry.content.stream),
      })),
    });
    assert.ok(encoded.message.length < 65536);
    const parsed = await simpleParser(encoded.message);
    assert.equal(parsed.text.replace(/\r\n/g, '\n').replace(/\n$/, ''), mailPrivateValues[0]);
    assert.deepEqual(
      parsed.from.value.map((entry) => entry.address),
      [mailPrivateValues[1]],
    );
    assert.deepEqual(
      parsed.to.value.map((entry) => entry.address),
      [mailPrivateValues[2]],
    );
    assert.equal(parsed.messageId, encoded.messageId);
    assert.deepEqual(parsed.attachments[0].content, attachmentBytes);
  } finally {
    transport.close();
  }
});

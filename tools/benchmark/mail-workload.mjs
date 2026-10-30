// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import nodemailer from 'nodemailer';
import { createHash } from 'node:crypto';

export const mailPrivateValues = Object.freeze([
  'owned-private-mail-content',
  'sender@example.test',
  'recipient@example.test',
  'owned-report.bin',
]);
export const attachmentBytes = Buffer.from([0, 1, 2, 253, 254, 255]);
export const mailMessage = () => ({
  from: { address: mailPrivateValues[1] },
  to: [{ address: mailPrivateValues[2] }],
  subject: 'Owned SMTP comparison',
  text: mailPrivateValues[0],
  attachments: [
    {
      filename: mailPrivateValues[3],
      content: {
        stream: (async function* () {
          yield attachmentBytes.subarray(0, 3);
          yield attachmentBytes.subarray(3);
        })(),
      },
    },
  ],
});
export function mailSettings(fixture) {
  return {
    transports: [
      {
        name: 'owned',
        host: 'localhost',
        port: fixture.port,
        requireTls: true,
        usernameRef: 'owned-user-reference',
        passwordRef: 'owned-credential-reference',
        allowedFromAddresses: [mailPrivateValues[1]],
        maxAttachmentBytes: 65536,
      },
    ],
    secretProvider: {
      async get(reference) {
        assert.ok(['owned-user-reference', 'owned-credential-reference'].includes(reference));
        return {
          bytes: Buffer.from(
            reference === 'owned-user-reference' ? 'owned-user' : fixture.credential,
          ),
          keyVersion: 'one',
        };
      },
    },
    policy: { maxConcurrent: 1, timeoutMs: 5000 },
  };
}
/** Native Nodemailer owns MIME, STARTTLS, authentication and one pooled connection. */
export function nativeMail(fixture) {
  const transport = nodemailer.createTransport({
    host: 'localhost',
    port: fixture.port,
    secure: false,
    requireTLS: true,
    tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' },
    auth: { user: 'owned-user', pass: fixture.credential },
    pool: true,
    maxConnections: 1,
    maxMessages: 100,
    maxRequeues: 0,
    connectionTimeout: 5000,
    greetingTimeout: 5000,
    socketTimeout: 5000,
    disableFileAccess: true,
    disableUrlAccess: true,
    logger: false,
    debug: false,
  });
  return {
    async verifyTransport() {
      return { available: await transport.verify(), checkedAt: new Date().toISOString() };
    },
    async send(message) {
      const result = await transport.sendMail({
        from: message.from.address,
        to: message.to.map((value) => value.address),
        subject: message.subject,
        text: message.text,
        attachments: message.attachments.map((entry) => ({
          filename: entry.filename,
          content: Readable.from(entry.content.stream),
        })),
      });
      return {
        outcome: result.rejected.length ? 'partial' : 'accepted',
        accepted: result.accepted,
        rejected: result.rejected,
        transportId: result.messageId,
        sentAt: new Date().toISOString(),
      };
    },
    close() {
      transport.close();
    },
  };
}
const observations = new WeakMap();

/** Aggregate private receipt integrity; never use this digest as a telemetry label. */
export function mailReceiptDigest(ids) {
  assert.ok(Array.isArray(ids) && ids.length <= 512);
  const digest = createHash('sha256').update('arkenivajs.mail.benchmark.receipts.v1\n');
  for (const id of ids) {
    assert.equal(typeof id, 'string');
    assert.ok(id.length > 0 && id.length <= 2048 && !/[\r\n]/.test(id));
    digest.update(JSON.stringify(id) + '\n');
  }
  return digest.digest('hex');
}

export function verifyMailReceipt(result) {
  assert.equal(result.outcome, 'accepted');
  assert.deepEqual(result.accepted, [mailPrivateValues[2]]);
  assert.deepEqual(result.rejected, []);
  assert.equal(typeof result.transportId, 'string');
  assert.ok(result.transportId.length > 0 && result.transportId.length <= 2048);
  assert.ok(!/[\r\n]/.test(result.transportId));
  assert.ok(Number.isFinite(Date.parse(result.sentAt)));
  return result.transportId;
}

function captureReceipt(state, result) {
  const id = verifyMailReceipt(result);
  assert.ok(state.ids.length < 128, 'The bounded SMTP receipt capacity is exceeded');
  assert.equal(state.seen.has(id), false, 'A submitted SMTP receipt was repeated');
  state.seen.add(id);
  state.ids.push(id);
}

export async function verifyMail(service) {
  const health = await service.verifyTransport();
  assert.equal(health.available, true);
  assert.ok(Number.isFinite(Date.parse(health.checkedAt)));
  const state = {
    ids: [],
    seen: new Set(),
    verificationAccepted: 0,
    callbacks: 0,
    completed: 0,
    active: 0,
    peakActive: 0,
  };
  observations.set(service, state);
  for (let index = 0; index < 2; index++) {
    const result = await service.send(mailMessage());
    captureReceipt(state, result);
    state.verificationAccepted++;
  }
  return { checkedMessages: 2, actualTransportVerified: true, streamedAttachments: true };
}

/** Each callback creates a new single-pass attachment and awaits real SMTP acceptance. */
export function mailWorkload(service) {
  const state = observations.get(service);
  assert.ok(state, 'SMTP corpus verification must precede workload execution');
  return {
    'smtp-accepted-streamed-attachment': async () => {
      assert.equal(state.active, 0);
      state.callbacks++;
      state.active++;
      state.peakActive = Math.max(state.peakActive, state.active);
      try {
        captureReceipt(state, await service.send(mailMessage()));
        state.completed++;
        return true;
      } finally {
        state.active--;
      }
    },
  };
}

export function mailObservations(service, { measure, records }) {
  const state = observations.get(service);
  assert.ok(state, 'SMTP corpus verification must precede completion');
  assert.equal(state.callbacks, state.completed);
  assert.equal(state.active, 0);
  assert.ok(state.peakActive <= 1);
  if (measure) {
    assert.equal(records.length, 1);
    const record = records[0];
    assert.equal(record.operation, 'smtp-accepted-streamed-attachment');
    assert.equal(record.sampleCount, 100);
    assert.equal(record.warmupIterations, 20);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, record.sampleCount);
    assert.ok(record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0));
    assert.equal(state.callbacks, record.sampleCount + record.warmupIterations);
  } else assert.equal(records.length, 0);
  const totalReceipts = state.verificationAccepted + state.completed;
  assert.equal(state.ids.length, totalReceipts);
  const receiptDigest = mailReceiptDigest(state.ids);
  state.ids.length = 0;
  state.seen.clear();
  return {
    actualSubmissionCallbacks: state.callbacks,
    acceptedSubmissions: state.completed,
    verificationAccepted: state.verificationAccepted,
    totalReceipts,
    receiptDigest,
    expectedAttachmentBytes: totalReceipts * attachmentBytes.length,
    activeCallbacks: state.active,
    peakConcurrentCallbacks: state.peakActive,
    retainedReceiptIds: state.ids.length,
  };
}

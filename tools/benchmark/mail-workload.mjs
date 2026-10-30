// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import nodemailer from 'nodemailer';

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
export async function verifyMail(service) {
  const health = await service.verifyTransport();
  assert.equal(health.available, true);
  assert.ok(Number.isFinite(Date.parse(health.checkedAt)));
  for (let index = 0; index < 2; index++) {
    const result = await service.send(mailMessage());
    assert.equal(result.outcome, 'accepted');
    assert.deepEqual(result.accepted, [mailPrivateValues[2]]);
    assert.deepEqual(result.rejected, []);
    assert.equal(typeof result.transportId, 'string');
    assert.ok(Number.isFinite(Date.parse(result.sentAt)));
  }
  return { checkedMessages: 2, actualTransportVerified: true, streamedAttachments: true };
}

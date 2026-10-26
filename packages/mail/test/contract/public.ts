// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { mailPlugin } from '../../dist/index.js';
import type { MailService, MailMessage, MailReceipt } from '../../dist/index.js';

/** Compile the explicit transport selector and prohibit native/path/URL escape hatches. */
export async function publicContract(mail: MailService, message: MailMessage) {
  const receipt: MailReceipt = await mail.send(message, { transport: 'primary', timeoutMs: 1000 });
  await mail.verifyTransport({ transport: 'primary' });
  // @ts-expect-error Recipient outcomes are immutable.
  receipt.accepted.push('manual@example.test');
  // @ts-expect-error User-selected SMTP endpoints are not public operation options.
  await mail.send(message, { host: 'smtp.example.test' });
  await mail.send({
    ...message,
    // @ts-expect-error Explicit content does not accept implicit local files or URL downloads.
    attachments: [{ filename: 'report', content: { path: '/etc/passwd' } }],
  });
  mailPlugin({
    transports: [
      {
        name: 'primary',
        host: 'smtp.example.test',
        port: 587,
        // @ts-expect-error TLS-required profiles cannot be configured for cleartext credentials.
        requireTls: false,
        allowedFromAddresses: ['sender@example.test'],
        maxAttachmentBytes: 1,
      },
    ],
    secretProvider: {
      async get() {
        return { bytes: new Uint8Array(), keyVersion: 'one' };
      },
    },
    policy: { maxConcurrent: 1, timeoutMs: 1000 },
  });
  return receipt;
}

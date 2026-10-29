// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import { mailPlugin, MAIL_CAPABILITY } from '../../dist/index.js';
import type { MailService, MailMessage, SecretProvider } from '../../dist/index.js';

/** Only the owned SMTP fixture launches this client with an ephemeral startup trust anchor. */
if (process.env.ARKENIVA_MAIL_DISPOSABLE !== '1')
  throw new Error('The SMTP client requires an explicitly disposable fixture');
let version = 'one',
  unavailable = false;
const input = JSON.parse(process.argv[2]!) as { port: number; mode: string; timeoutMs?: number };
const captureMode = input.mode.startsWith('provider-capture-');
if (captureMode) input.mode = input.mode.slice('provider-capture-'.length);
let metadataEffects = 0,
  providerCalls = 0,
  replacements = 0;
const provider: SecretProvider = {
  async get(reference) {
    assert.equal(this, provider);
    providerCalls++;
    if (unavailable) throw new Error('The disposable provider is unavailable');
    return {
      bytes: Buffer.from(
        reference === 'fixture-password' && version === 'two' ? 'fixture-password-next' : reference,
      ),
      keyVersion: version,
    };
  },
};
if (captureMode)
  for (const key of ['bind', 'name', 'length'])
    Object.defineProperty(provider.get, key, {
      get() {
        metadataEffects++;
        throw new Error('Callable provider metadata must not execute');
      },
    });
const app = await createApplication({
  service: { name: 'mail-native-fixture', version: '0.1.0', environment: 'test' },
  plugins: [
    mailPlugin({
      transports: [
        {
          name: 'local',
          host: 'localhost',
          port: input.port,
          requireTls: true,
          usernameRef: 'fixture-user',
          passwordRef: 'fixture-password',
          allowedFromAddresses: ['sender@example.test'],
          maxAttachmentBytes: 65536,
        },
      ],
      secretProvider: provider,
      templates: { greeting: '<p>Hello {{person.name}}</p>' },
      policy: { maxConcurrent: 2, timeoutMs: 5000 },
    }),
  ],
});
try {
  await app.start();
  if (captureMode)
    provider.get = async () => {
      replacements++;
      throw new Error('The late provider replacement must not run');
    };
  const mail = app.resolve<MailService>(MAIL_CAPABILITY);
  if (input.mode === 'verify') console.log(JSON.stringify(await mail.verifyTransport()));
  else {
    const message: MailMessage = {
      from: { address: 'sender@example.test', displayName: 'Caffè 🦊' },
      to: [
        {
          address: input.mode === 'all-rejected' ? 'reject@example.test' : 'recipient@example.test',
        },
      ],
      ...(input.mode === 'partial'
        ? { cc: [{ address: 'reject@example.test' }], bcc: [{ address: 'hidden@example.test' }] }
        : {}),
      subject: 'Native fixture 東京',
      ...(input.mode === 'template'
        ? {
            templateId: 'greeting',
            templateModel: { person: { name: '<script>private-template-value</script>' } },
          }
        : {
            text: 'Private MIME fixture text',
            html: '<p>Safe HTML</p><script>private-script-value</script><img src="file:///etc/passwd" onerror="alert(1)">',
          }),
      attachments: [
        {
          filename: 'report-東京.bin',
          mimeType: 'application/octet-stream',
          content: {
            stream: (async function* () {
              yield new Uint8Array([0, 1, 2]);
              yield new Uint8Array([253, 254, 255]);
            })(),
          },
        },
      ],
    };
    if (input.mode === 'concurrent') {
      const controller = new AbortController();
      process.once('message', () => controller.abort());
      const first = mail.send(
          { ...message, to: [{ address: 'first@example.test' }], attachments: [] },
          { signal: controller.signal },
        ),
        second = mail.send({
          ...message,
          to: [{ address: 'second@example.test' }],
          attachments: [],
        }),
        results = Promise.allSettled([first, second]);
      let capacity: string | undefined;
      try {
        await mail.send({ ...message, attachments: [] });
      } catch (cause) {
        if (cause instanceof KitError) capacity = cause.code;
        else throw cause;
      }
      const [a, b] = await results;
      console.log(
        JSON.stringify({
          first:
            a!.status === 'rejected' && a!.reason instanceof KitError
              ? a!.reason.code
              : 'unexpected',
          second: b!.status === 'fulfilled' ? b!.value.outcome : 'unexpected',
          capacity,
        }),
      );
    } else {
      const result = await mail.send(
        message,
        input.timeoutMs === undefined ? undefined : { timeoutMs: input.timeoutMs },
      );
      if (input.mode === 'rotation') version = 'two';
      if (input.mode === 'outage') unavailable = true;
      if (['two', 'rotation', 'outage'].includes(input.mode))
        await mail.send({
          ...message,
          attachments: [
            {
              filename: 'second.bin',
              content: { bytes: new Uint8Array([0, 1, 2, 253, 254, 255]) },
            },
          ],
        });
      console.log(
        JSON.stringify({
          outcome: result.outcome,
          accepted: result.accepted.length,
          rejected: result.rejected.length,
          transportId: typeof result.transportId === 'string',
        }),
      );
    }
  }
} catch (cause) {
  if (!(cause instanceof KitError)) throw cause;
  console.log(JSON.stringify({ code: cause.code, outcome: cause.details.outcome }));
} finally {
  try {
    await app.stop();
  } finally {
    if (process.connected) process.disconnect();
    if (captureMode) {
      assert.equal(metadataEffects, 0);
      assert.equal(replacements, 0);
      assert.equal(providerCalls, input.mode === 'outage' ? 3 : 4);
    }
  }
}

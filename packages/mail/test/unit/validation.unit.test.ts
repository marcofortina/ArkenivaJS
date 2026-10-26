// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import { mailPlugin, MAIL_CAPABILITY } from '../../dist/index.js';
import type { MailService, MailPluginSettings, MailMessage } from '../../dist/index.js';
import { setImmediate as immediate } from 'node:timers/promises';
import { templates, message as captureMessage } from '../../dist/messages.js';
import { capture } from '../../dist/settings.js';

const profile = () => ({
  name: 'local',
  host: 'localhost',
  port: 1,
  requireTls: true as const,
  usernameRef: 'user',
  passwordRef: 'password',
  allowedFromAddresses: ['sender@example.test'],
  maxAttachmentBytes: 1024,
});
const config = (): MailPluginSettings => ({
  transports: [profile()],
  policy: { maxConcurrent: 1, timeoutMs: 1000 },
  secretProvider: {
    async get() {
      throw new Error('The fixture provider must not be called');
    },
  },
});
const message = (): MailMessage => ({
  from: { address: 'sender@example.test' },
  to: [{ address: 'recipient@example.test' }],
  subject: 'fixture',
  text: 'fixture',
});
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
async function fixture(settings = config()) {
  const app = await createApplication({
    service: { name: 'mail-validation', version: '0.1.0', environment: 'test' },
    plugins: [mailPlugin(settings)],
  });
  await app.start();
  return { app, mail: app.resolve<MailService>(MAIL_CAPABILITY) };
}
test('Unsafe SMTP configuration, missing providers and unbounded policies fail before registration', () => {
  let reads = 0;
  const getter = Object.defineProperty({}, 'host', {
    get() {
      reads++;
      return 'localhost';
    },
  });
  for (const input of [
    null,
    {},
    { ...config(), secretProvider: {} },
    { ...config(), transports: [] },
    { ...config(), transports: [{ ...profile(), requireTls: false }] },
    { ...config(), transports: [{ ...profile(), host: 'smtp://localhost' }] },
    { ...config(), transports: [{ ...profile(), port: 0 }] },
    { ...config(), transports: [{ ...profile(), passwordRef: undefined }] },
    { ...config(), transports: [getter] },
    { ...config(), transports: [profile(), profile()] },
    { ...config(), policy: { maxConcurrent: 1, timeoutMs: 0 } },
    { ...config(), templates: { greeting: '{{{raw}}}' } },
    { ...config(), templates: { greeting: '{{#loop}}x{{/loop}}' } },
    { ...config(), templates: { greeting: '{{constructor.name}}' } },
  ])
    assert.throws(() => mailPlugin(input as never), code('EK_MAIL_CONFIG'));
  assert.equal(reads, 0);
});
test('Header injection, excessive recipients, unknown fields and implicit attachments fail before secrets or SMTP', async () => {
  let calls = 0,
    sourceCalls = 0,
    getters = 0;
  const source = {
      [Symbol.asyncIterator]() {
        sourceCalls++;
        throw new Error('private-source-value');
      },
    },
    { app, mail } = await fixture({
      ...config(),
      secretProvider: {
        async get() {
          calls++;
          throw new Error('private-secret-value');
        },
      },
    });
  try {
    const getter = Object.defineProperty({}, 'subject', {
      get() {
        getters++;
        return 'header';
      },
    });
    for (const input of [
      null,
      {},
      getter,
      { ...message(), subject: 'safe\r\nBcc: injected@example.test' },
      { ...message(), from: { address: 'sender@example.test', displayName: 'bad\nname' } },
      { ...message(), to: [{ address: 'recipient@example.test\r\nMAIL FROM: attacker' }] },
      { ...message(), to: [] },
      {
        ...message(),
        to: Array.from({ length: 101 }, () => ({ address: 'recipient@example.test' })),
      },
      { ...message(), raw: 'raw MIME' },
      {
        ...message(),
        attachments: [{ filename: 'report', content: { href: 'https://private.invalid/file' } }],
      },
      {
        ...message(),
        attachments: [{ filename: 'report', content: { bytes: new Uint8Array(1025) } }],
      },
      { ...message(), attachments: [{ filename: '../report', content: { stream: source } }] },
      {
        ...message(),
        attachments: [{ filename: 'report', content: { bytes: new Uint8Array(), stream: source } }],
      },
    ])
      await assert.rejects(mail.send(input as never), code('EK_MAIL_CONFIG'));
    await assert.rejects(
      mail.send({ ...message(), from: { address: 'unauthorized@example.test' } }),
      code('EK_MAIL_REJECTED'),
    );
    for (const options of [
      null,
      { host: 'remote.invalid' },
      { transport: 'missing' },
      { timeoutMs: 0 },
      { signal: { aborted: false } },
    ])
      await assert.rejects(mail.send(message(), options as never), code('EK_MAIL_CONFIG'));
    assert.deepEqual({ calls, sourceCalls, getters }, { calls: 0, sourceCalls: 0, getters: 0 });
  } finally {
    await app.stop();
  }
});
test('Several configured transports require a named selection and cannot silently choose the first profile', async () => {
  const { app, mail } = await fixture({
    ...config(),
    transports: [profile(), { ...profile(), name: 'other' }],
  });
  try {
    await assert.rejects(mail.verifyTransport(), code('EK_MAIL_CONFIG'));
    await assert.rejects(mail.send(message()), code('EK_MAIL_CONFIG'));
    await assert.rejects(
      mail.send({ ...message(), subject: 'bad\nheader' }, { transport: 'other' }),
      code('EK_MAIL_CONFIG'),
    );
  } finally {
    await app.stop();
  }
});
test('A provider outage, invalid credential bytes or expiry cannot fall back to an unauthenticated SMTP send', async () => {
  for (const value of [
    undefined,
    {},
    { bytes: new Uint8Array(), keyVersion: 'one' },
    { bytes: new Uint8Array([255]), keyVersion: 'one' },
    { bytes: Buffer.from('fixture'), keyVersion: 'one', expiresAt: '2000-01-01T00:00:00.000Z' },
  ]) {
    const { app, mail } = await fixture({
      ...config(),
      secretProvider: {
        async get() {
          if (value === undefined) throw new Error('private-provider-error');
          return value as never;
        },
      },
    });
    try {
      await assert.rejects(mail.send(message()), (error) => {
        assert.ok(error instanceof KitError);
        assert.ok(['EK_MAIL_CONFIG', 'EK_MAIL_SEND'].includes(error.code));
        assert.equal(error.cause, undefined);
        assert.ok(!JSON.stringify(error.toSafeJSON()).includes('private'));
        return true;
      });
    } finally {
      await app.stop();
    }
  }
});
test('Closed application-owned services reject new work without consulting a provider', async () => {
  const a = await fixture(),
    b = await fixture();
  try {
    await a.mail.close();
    await a.mail.close();
    await assert.rejects(a.mail.send(message()), code('EK_RESOURCE_CLOSED'));
    await assert.rejects(a.mail.verifyTransport(), code('EK_RESOURCE_CLOSED'));
    await assert.rejects(
      b.mail.send({ ...message(), subject: 'bad\nheader' }),
      code('EK_MAIL_CONFIG'),
    );
  } finally {
    await a.app.stop();
    await b.app.stop();
  }
});
test('Cancellation retains admission until an uncooperative secret provider settles and never starts SMTP afterward', async () => {
  let resolve!: (value: { bytes: Uint8Array; keyVersion: string }) => void,
    entered!: () => void,
    calls = 0;
  const held = new Promise<{ bytes: Uint8Array; keyVersion: string }>((done) => {
      resolve = done;
    }),
    ready = new Promise<void>((done) => {
      entered = done;
    }),
    { app, mail } = await fixture({
      ...config(),
      secretProvider: {
        async get() {
          calls++;
          entered();
          return held;
        },
      },
    }),
    controller = new AbortController();
  try {
    const task = mail.send(message(), { signal: controller.signal }),
      rejected = assert.rejects(task, code('EK_ABORTED'));
    await ready;
    controller.abort(new Error('private-abort-value'));
    await rejected;
    await assert.rejects(mail.send(message()), code('EK_MAIL_SEND'));
    assert.equal(calls, 1);
    resolve({ bytes: Buffer.from('fixture'), keyVersion: 'one' });
    await mail.close();
    assert.equal(calls, 1);
    await immediate();
    await assert.rejects(mail.verifyTransport(), code('EK_RESOURCE_CLOSED'));
  } finally {
    resolve({ bytes: Buffer.from('fixture'), keyVersion: 'one' });
    await app.stop();
  }
});
test('The upstream template adapter renders only owned scalars and rejects cyclic, executable or accessor models', () => {
  const setting = capture({
      ...config(),
      templates: { scalar: '<p>{{person.name}}/{{missing}}/{{count}}/{{flag}}/{{values.0}}</p>' },
    }),
    render = templates(setting);
  assert.equal(
    render('scalar', { person: { name: '<&' }, count: 0, flag: false, values: [7] }),
    '<p>&lt;&amp;//0/false/7</p>',
  );
  let reads = 0;
  const getter = Object.defineProperty({}, 'name', {
      enumerable: true,
      get() {
        reads++;
        throw new Error('private-model-value');
      },
    }),
    cycle: Record<string, unknown> = {};
  cycle.child = cycle;
  for (const input of [
    null,
    [],
    cycle,
    { person: { name: () => 'executable' } },
    { person: getter },
    { count: Infinity },
    { person: { name: {} } },
    JSON.parse('{"__proto__":{"name":"unsafe"}}'),
  ])
    assert.throws(
      () =>
        captureMessage(
          {
            from: message().from,
            to: message().to,
            subject: 'fixture',
            templateId: 'scalar',
            templateModel: input as never,
          },
          profile(),
          setting,
          render,
        ),
      code('EK_MAIL_CONFIG'),
    );
  assert.equal(reads, 0);
  assert.throws(() => render('missing', {}), code('EK_MAIL_CONFIG'));
  assert.throws(
    () => templates(capture({ ...config(), templates: { broken: '{{#unterminated}}' } })),
    code('EK_MAIL_CONFIG'),
  );
  const view = captureMessage(
    {
      ...message(),
      html: '<a href="javascript:private-value" onclick="private-value">safe</a><script>private-value</script>',
    },
    profile(),
    setting,
    render,
  );
  assert.ok(!view.html?.includes('javascript:'));
  assert.ok(!view.html?.includes('<script'));
  assert.ok(!view.html?.includes('onclick'));
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createApplication, KitError } from '@arkenivajs/core';
import { socketPlugin, SOCKET_CAPABILITY } from '../../dist/index.js';
import type { SocketListenerDefinition, SocketService } from '../../dist/index.js';

const code = (value: string) => (cause: unknown) =>
  cause instanceof KitError && cause.code === value;
const handler = () => undefined;
const files = {
  certificateFile: '/approved/certificate.pem',
  privateKeyFile: '/approved/private-material.pem',
};
test('Runtime configuration rejects malformed, forged and unbounded public policy before allocating listeners', () => {
  const invalid: unknown[] = [
    null,
    [],
    { other: true },
    { listeners: [null] },
    { listeners: [{ kind: 'quic', options: { name: 'test', port: 9000 }, handler }] },
    { listeners: Object.assign([], { extra: true }) },
    {
      get listeners() {
        throw new Error('Private diagnostic');
      },
    },
    ...[
      { name: '', port: 9000 },
      { name: 'Invalid', port: 9000 },
      { name: 'test', port: 0.5 },
      { name: 'test', port: null },
      { name: 'test', port: 65536 },
      { name: 'test', port: 9000, host: 'localhost' },
      { name: 'test', port: 9000, host: 'https://127.0.0.1' },
      { name: 'test', port: 9000, ipv6Only: true },
      { name: 'test', port: 9000, idleTimeoutMs: null },
      { name: 'test', port: 9000, maxConnections: 0 },
      { name: 'test', port: 9000, maxPendingWriteBytes: 16777217 },
      { name: 'test', port: 9000, shutdownTimeoutMs: 0 },
      { name: 'test', port: 9000, arbitrary: true },
      {
        name: 'test',
        get port() {
          throw new Error('Private getter');
        },
      },
      new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error('Private proxy');
          },
        },
      ),
    ].map((options) => ({ listeners: [{ kind: 'tcp', options, handler }] })),
    ...[
      { name: 'test', port: 9000 },
      { name: 'test', port: 9000, tls: null },
      { name: 'test', port: 9000, tls: { ...files, certificateFile: 'relative.pem' } },
      { name: 'test', port: 9000, tls: { ...files, minVersion: 'TLSv1.1' } },
      { name: 'test', port: 9000, tls: { ...files, clientCertificate: 'required' } },
      { name: 'test', port: 9000, tls: files, handshakeTimeoutMs: 0 },
    ].map((options) => ({ listeners: [{ kind: 'tls', options, handler }] })),
    ...[
      { name: 'test', path: 'relative.sock' },
      { name: 'test', path: '/tmp/../test.sock' },
      { name: 'test', path: '/tmp/' + 'x'.repeat(104) },
      { name: 'test', path: '/tmp/test.sock', mode: 0o777 },
      { name: 'test', path: '/tmp/test.sock', mode: 0 },
    ].map((options) => ({ listeners: [{ kind: 'unix', options, handler }] })),
    ...[
      { name: 'test', port: 9000, family: 'udp4', host: '::1' },
      { name: 'test', port: 9000, family: 'udp6', host: '127.0.0.1' },
      { name: 'test', port: 9000, family: 'other' },
      { name: 'test', port: 9000, family: 'udp4', maxDatagramBytes: 65508 },
      { name: 'test', port: 9000, family: 'udp4', maxReplyAmplificationFactor: 0 },
      { name: 'test', port: 9000, family: 'udp4', allowOutboundDestinations: true },
      { name: 'test', port: 9000, family: 'udp4', destinationAllowlist: ['127.0.0.1:9001'] },
      ...[
        'https://host.invalid',
        'localhost:9001',
        '127.0.0.1',
        '127.0.0.1:0',
        '127.0.0.1:9001/path',
        '[::1]:9001',
      ].map((destination) => ({
        name: 'test',
        port: 9000,
        family: 'udp4',
        allowOutboundDestinations: true,
        destinationAllowlist: [destination],
      })),
      {
        name: 'test',
        port: 9000,
        family: 'udp4',
        allowOutboundDestinations: true,
        destinationAllowlist: ['127.0.0.1:9001', '127.0.0.1:9001'],
      },
    ].map((options) => ({ listeners: [{ kind: 'udp', options, handler }] })),
  ];
  for (const input of invalid)
    assert.throws(() => socketPlugin(input as never), code('EK_SOCKET_CONFIG'));
});

test('Duplicate listener names and stream endpoints fail as a whole before startup', () => {
  const first: SocketListenerDefinition = {
    kind: 'tcp',
    options: { name: 'first', port: 9001 },
    handler,
  };
  assert.throws(() => socketPlugin({ listeners: [first, first] }), code('EK_SOCKET_CONFIG'));
  assert.throws(
    () =>
      socketPlugin({
        listeners: [
          first,
          { kind: 'tls', options: { name: 'secure', port: 9001, tls: files }, handler },
        ],
      }),
    code('EK_SOCKET_CONFIG'),
  );
});

test('Native operation signals, positive deadlines and closed handles cannot be bypassed with structural objects', async () => {
  const app = await createApplication({
    service: { name: 'policy', version: '1.0.0', environment: 'test' },
    plugins: [socketPlugin()],
  });
  await app.start();
  try {
    const sockets = app.resolve<SocketService>(SOCKET_CAPABILITY),
      tcp = sockets.createTcpServer({ name: 'policy', port: 0 }, handler),
      udp = sockets.createUdpServer({ name: 'udp', family: 'udp4', port: 0 }, handler);
    for (const options of [
      null,
      [],
      { timeoutMs: 0 },
      { timeoutMs: 1.5 },
      { timeoutMs: NaN },
      { signal: { aborted: false, addEventListener() {} } },
      { other: 1 },
    ])
      assert.throws(() => tcp.start(options as never), code('EK_SOCKET_CONFIG'));
    await tcp.start();
    await udp.start();
    await assert.rejects(
      udp.sendTo({ address: '127.0.0.1', port: 0, family: 'IPv4' }, Buffer.from('x')),
      code('EK_SOCKET_DATAGRAM'),
    );
    await assert.rejects(
      udp.reply(
        {
          bytes: new Uint8Array(),
          remote: { address: '127.0.0.1', port: 9000, family: 'IPv4' },
          receivedAt: new Date().toISOString(),
        },
        new Uint8Array(),
      ),
      code('EK_SOCKET_DATAGRAM'),
    );
    await tcp.stop();
    await assert.rejects(tcp.start(), code('EK_SOCKET_STATE'));
    assert.equal(tcp.stats().state, 'CLOSED');
  } finally {
    await app.stop({ timeoutMs: 1000 });
  }
});

test('The unsupported Windows Unix guard fails explicitly without attempting filesystem binding', async () => {
  const app = await createApplication({
    service: { name: 'platform-guard', version: '1.0.0', environment: 'test' },
    plugins: [socketPlugin()],
  });
  await app.start();
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform')!;
  try {
    const listener = app
      .resolve<SocketService>(SOCKET_CAPABILITY)
      .createUnixServer({ name: 'guard', path: '/approved/listener.sock' }, handler);
    Object.defineProperty(process, 'platform', { ...descriptor, value: 'win32' });
    await assert.rejects(listener.start(), code('EK_UNSUPPORTED_CAPABILITY'));
  } finally {
    Object.defineProperty(process, 'platform', descriptor);
    await app.stop({ timeoutMs: 1000 });
  }
});

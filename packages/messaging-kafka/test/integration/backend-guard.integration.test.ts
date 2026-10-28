// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { managedProducer } from '../../dist/producer.js';
import { settings } from '../../dist/settings.js';

test('A missing or incompatible actual native build marker fails before secret access, CA access or network I/O', async () => {
  assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
  const require = createRequire(import.meta.url);
  const local = createRequire(require.resolve('@confluentinc/kafka-javascript/package.json'));
  const binding = local('./librdkafka.js') as Record<string, unknown>;
  const original = Object.getOwnPropertyDescriptor(
    binding,
    'arkenivajsNativeCompatibilityVersion',
  )!;
  assert.equal(original.value, 1);
  let connections = 0,
    secrets = 0;
  const server = createServer((socket) => {
    connections++;
    socket.destroy();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try {
    for (const version of [undefined, 0, 2, '1']) {
      Object.defineProperty(binding, 'arkenivajsNativeCompatibilityVersion', {
        ...original,
        value: version,
      });
      const owner = managedProducer(
        settings({
          clusters: [
            {
              name: 'owned',
              brokers: ['127.0.0.1:' + address.port],
              clientId: 'owned-backend-guard',
              topics: ['orders.created'],
              credentialSecretRef: 'owned-credential',
              tlsCaFile: '/unavailable-owned-certificate.pem',
              maxBufferedMessages: 1,
              maxMessageBytes: 1024,
              acks: 'all',
              idempotentProducer: true,
            },
          ],
          resolveSecret: async () => {
            secrets++;
            throw new Error('The secret provider must not run');
          },
        }),
        new AbortController().signal,
        () => true,
        'production',
      );
      try {
        await assert.rejects(owner.init(), { code: 'EK_KAFKA_CONFIG' });
      } finally {
        await owner.close();
      }
    }
    assert.equal(secrets, 0);
    assert.equal(connections, 0);
  } finally {
    Object.defineProperty(binding, 'arkenivajsNativeCompatibilityVersion', original);
    await new Promise<void>((done) => server.close(() => done()));
  }
});

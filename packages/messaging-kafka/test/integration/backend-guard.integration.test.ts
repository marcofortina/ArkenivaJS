// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import filesystem from 'node:fs/promises';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { managedProducer } from '../../dist/producer.js';
import { settings } from '../../dist/settings.js';

test('Actual native data markers reject missing, legacy, accessor and incompatible builds before secret, CA or network access', async (context) => {
  assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
  const require = createRequire(import.meta.url);
  const local = createRequire(require.resolve('@confluentinc/kafka-javascript/package.json'));
  const binding = local('./librdkafka.js') as Record<string, unknown>;
  const compatibilityName = 'arkenivajsNativeCompatibilityVersion',
    zlibName = 'arkenivajsNativeZlibVersion';
  const original = Object.getOwnPropertyDescriptor(binding, compatibilityName)!,
    originalZlib = Object.getOwnPropertyDescriptor(binding, zlibName)!;
  assert.ok(Object.hasOwn(original, 'value'));
  assert.ok(Object.hasOwn(originalZlib, 'value'));
  assert.equal(original.value, 3);
  assert.equal(originalZlib.value, '1.4');
  let connections = 0,
    secrets = 0,
    certificateOpens = 0,
    getters = 0;
  const certificateFile = '/unavailable-owned-certificate.pem',
    originalOpen = filesystem.open;
  const server = createServer((socket) => {
    connections++;
    socket.destroy();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try {
    filesystem.open = (...args: Parameters<typeof originalOpen>) => {
      if (args[0] === certificateFile) certificateOpens++;
      return originalOpen(...args);
    };
    syncBuiltinESMExports();
    assert.equal((await import('node:fs/promises')).open, filesystem.open);
    const benchmark = (await import(
      new URL('../../../../tools/benchmark/kafka-workload.mjs', import.meta.url).href
    )) as {
      nativeKafkaClient(
        fixture: { broker: string; topic: string; caFile: string; secretFile: string },
        clientId: string,
      ): Promise<unknown>;
    };
    const invalid: { label: string; property: string; descriptor?: PropertyDescriptor }[] = [];
    for (const [property, valid, values] of [
      [compatibilityName, 3, [undefined, 0, 1, 2, 4, '3']],
      [zlibName, '1.4', [undefined, null, 1.4, {}, '', '1.2.13', '1.3.2', '1.4.0']],
    ] as const) {
      invalid.push({ label: property + ' missing', property });
      for (const value of values)
        invalid.push({
          label: property + ' rejects ' + String(value),
          property,
          descriptor: { configurable: true, enumerable: true, writable: true, value },
        });
      invalid.push({
        label: property + ' getter is not trusted or invoked',
        property,
        descriptor: {
          configurable: true,
          enumerable: true,
          get() {
            getters++;
            return valid;
          },
        },
      });
      invalid.push({
        label: property + ' throwing getter is not invoked',
        property,
        descriptor: {
          configurable: true,
          enumerable: true,
          get() {
            getters++;
            throw new Error('The native metadata getter must not run');
          },
        },
      });
    }
    for (const entry of invalid)
      await context.test(entry.label, async () => {
        Object.defineProperty(binding, compatibilityName, original);
        Object.defineProperty(binding, zlibName, originalZlib);
        if (entry.descriptor) Object.defineProperty(binding, entry.property, entry.descriptor);
        else delete binding[entry.property];
        for (const credential of [true, false]) {
          const owner = managedProducer(
            settings({
              clusters: [
                {
                  name: 'owned',
                  brokers: ['127.0.0.1:' + address.port],
                  clientId: 'owned-backend-guard',
                  topics: ['orders.created'],
                  ...(credential ? { credentialSecretRef: 'owned-credential' } : {}),
                  tlsCaFile: certificateFile,
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
        await assert.rejects(
          benchmark.nativeKafkaClient(
            {
              broker: '127.0.0.1:' + address.port,
              topic: 'orders.created',
              caFile: certificateFile,
              secretFile: '/unavailable-owned-credential.json',
            },
            'owned-reference-backend-guard',
          ),
          { code: 'ERR_ASSERTION' },
        );
        assert.equal(secrets, 0);
        assert.equal(certificateOpens, 0);
        assert.equal(getters, 0);
        assert.equal(connections, 0);
      });
    assert.equal(secrets, 0);
    assert.equal(certificateOpens, 0);
    assert.equal(getters, 0);
    assert.equal(connections, 0);
  } finally {
    Object.defineProperty(binding, compatibilityName, original);
    Object.defineProperty(binding, zlibName, originalZlib);
    filesystem.open = originalOpen;
    syncBuiltinESMExports();
    await new Promise<void>((done) => server.close(() => done()));
  }
});

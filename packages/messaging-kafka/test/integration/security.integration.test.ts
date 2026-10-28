// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { createServer } from 'node:tls';
import { once } from 'node:events';
import { managedService } from '../../dist/service.js';
import { settings } from '../../dist/settings.js';

function fixture(
  reference = 'fixture-allowed',
  authority = 'ca.pem',
  brokerPort = 19094,
  corrupt = false,
) {
  assert.equal(process.env.ARKENIVA_KAFKA_DISPOSABLE, '1');
  const directory = process.env.ARKENIVA_KAFKA_SECRETS!;
  assert.ok(directory?.startsWith('/'));
  return managedService(
    settings({
      clusters: [
        {
          name: 'secure',
          brokers: ['127.0.0.1:' + brokerPort],
          clientId: 'owned-secure-' + randomUUID(),
          topics: ['orders.created'],
          credentialSecretRef: reference,
          tlsCaFile: join(directory, authority),
          maxBufferedMessages: 4,
          maxMessageBytes: 262144,
          acks: 'all',
          idempotentProducer: true,
        },
      ],
      resolveSecret: async (name: string) => {
        assert.ok(['fixture-allowed', 'fixture-denied'].includes(name));
        const encoded = await readFile(join(directory, name + '.json'), 'utf8');
        return corrupt
          ? JSON.stringify({ ...JSON.parse(encoded), password: randomUUID() })
          : encoded;
      },
    }),
    new AbortController().signal,
    () => true,
    'production',
  );
}

test(
  'The actual native TLS client rejects TLS 1.1 and negotiates verified TLS 1.2 and TLS 1.3',
  { timeout: 30000 },
  async () => {
    const directory = process.env.ARKENIVA_KAFKA_SECRETS!;
    assert.ok(directory?.startsWith('/'));
    const pfx = await readFile(join(directory, 'server.p12'));
    const passphrase = await readFile(join(directory, 'keystore-password'), 'utf8');
    for (const version of ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const) {
      let accepted = false;
      const server = createServer(
        {
          pfx,
          passphrase,
          minVersion: version,
          maxVersion: version,
          ciphers: 'DEFAULT:@SECLEVEL=0',
        },
        (socket) => {
          accepted = true;
          socket.destroy();
        },
      );
      server.on('tlsClientError', () => undefined);
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const address = server.address();
      assert.ok(address && typeof address !== 'string');
      const owner = fixture('fixture-allowed', 'ca.pem', address.port);
      try {
        // This peer terminates after TLS; Kafka bootstrap must still fail rather than invent a broker.
        await assert.rejects(owner.init());
        assert.equal(
          accepted,
          version !== 'TLSv1.1',
          'Native negotiation did not enforce the required TLS version',
        );
      } finally {
        await owner.close({ timeoutMs: 30000 });
        await new Promise<void>((done) => server.close(() => done()));
      }
    }
  },
);

test(
  'Actual production Kafka requires a trusted TLS server and authenticated authorized SASL identity',
  { timeout: 30000 },
  async () => {
    const owner = fixture(),
      marker = randomUUID();
    let resolve!: () => void;
    const received = new Promise<void>((done) => {
      resolve = done;
    });
    let timer!: ReturnType<typeof setTimeout>;
    try {
      await owner.init();
      assert.equal((await owner.service.health('secure')).available, true);
      const subscription = await owner.service.consume(
        {
          cluster: 'secure',
          topics: ['orders.created'],
          groupId: 'owned-secure-' + randomUUID(),
          offsetReset: 'earliest',
        },
        async (record) => {
          if (Buffer.from(record.key ?? []).toString() !== marker) return;
          assert.deepEqual([...record.value!], [0, 128, 255]);
          assert.equal(record.verifiedTenant, undefined);
          resolve();
        },
      );
      const receipt = await owner.service.publish({
        cluster: 'secure',
        topic: 'orders.created',
        key: Buffer.from(marker),
        value: Buffer.from([0, 128, 255]),
        headers: { tenant_id: 'untrusted-wire-claim' },
      });
      assert.equal(receipt.status, 'acknowledged');
      await Promise.race([
        received,
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () => reject(new Error('The authenticated Kafka record was not received')),
            10000,
          );
        }),
      ]);
      await subscription.close();
    } finally {
      clearTimeout(timer);
      await owner.close();
    }
  },
);

test(
  'Actual Kafka rejects wrong CA, wrong server name, invalid credentials and missing topic ACLs without downgrade',
  { timeout: 60000 },
  async () => {
    for (const owner of [
      fixture('fixture-allowed', 'other-ca.pem'),
      fixture('fixture-allowed', 'ca.pem', 19097),
      fixture('fixture-allowed', 'ca.pem', 19094, true),
      fixture('fixture-denied'),
    ]) {
      try {
        await assert.rejects(owner.init(), (error: unknown) => {
          const value = error as { code?: string; cause?: unknown; message?: string };
          assert.ok(
            ['EK_KAFKA_CONNECT', 'EK_KAFKA_CONFIG', 'EK_TIMEOUT'].includes(value.code ?? ''),
          );
          assert.equal(value.cause, undefined);
          assert.equal(value.message, 'The managed Kafka operation could not complete');
          return true;
        });
      } finally {
        await owner.close({ timeoutMs: 30000 });
      }
    }
  },
);

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Etcd3, KVClient, GRPCUnavailableError } from 'etcd3';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { etcdPlugin } from '@arkenivajs/database-etcd';
import { etcdConfiguration } from '../../dist/config.js';
import { EtcdTransport } from '../../dist/transport.js';

const service = { name: 'etcd-public-contract', version: '1.0.0', environment: 'test' as const };
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
async function fixture(context: TestContext, plugin: Plugin = etcdPlugin()) {
  assert.equal(
    process.env.ARKENIVA_ETCD_DISPOSABLE,
    '1',
    'Only an explicitly disposable etcd fixture is permitted',
  );
  assert.ok(process.env.ARKENIVA_ETCD_URL, 'The authenticated TLS fixture is required');
  const configuration = etcdConfiguration(
    { driver: 'etcd', connectionStringEnv: 'ARKENIVA_ETCD_URL' },
    'test',
  );
  const app = await createApplication({
    service,
    plugins: [plugin],
    databases: { configuration: { driver: 'etcd', connectionStringEnv: 'ARKENIVA_ETCD_URL' } },
  });
  const provider = app.etcd!,
    base = 'public:' + randomUUID() + ':',
    keys = new Set<string>();
  context.after(async () => {
    try {
      await app.stop();
    } finally {
      if (keys.size) {
        const cleanup = new EtcdTransport(configuration, new AbortController().signal);
        try {
          for (const key of keys) await cleanup.client.delete().key(configuration.prefix + key);
        } finally {
          cleanup.client.close();
        }
      }
    }
  });
  await app.start();
  return {
    app,
    provider,
    configuration,
    base,
    native: provider.native() as Etcd3,
    key(name: string) {
      const key = base + name;
      keys.add(key);
      return key;
    },
  };
}

test(
  'EK-DB-002 real public etcd preserves raw bytes, exact metadata and deletion acknowledgments without SQL',
  { timeout: 20_000 },
  async (context) => {
    const f = await fixture(context),
      key = f.key('value');
    assert.ok(f.native instanceof Etcd3);
    assert.equal(await f.provider.get(key), null);
    assert.equal(await f.provider.delete(key), false);
    const bytes = Uint8Array.from([0, 255, 128, 1]);
    const writing = f.provider.put(key, bytes);
    bytes.fill(42);
    await writing;
    const first = await f.provider.get(key);
    assert.ok(first && Object.isFrozen(first));
    assert.deepEqual(first.value, Uint8Array.from([0, 255, 128, 1]));
    assert.equal(first.key, key);
    assert.equal(first.version, 1n);
    assert.equal(typeof first.revision, 'bigint');
    first.value.fill(99);
    assert.deepEqual((await f.provider.get(key))!.value, Uint8Array.from([0, 255, 128, 1]));
    await f.provider.put(key, new Uint8Array());
    const second = await f.provider.get(key);
    assert.equal(second!.value.byteLength, 0);
    assert.equal(second!.version, 2n);
    assert.ok(second!.revision > first.revision);
    await assert.rejects(f.native.get('/outside-scope').exec());
    assert.throws(() => f.app.sql, code('EK_UNSUPPORTED_CAPABILITY'));
    assert.equal(await f.provider.delete(key), true);
    assert.equal(await f.provider.delete(key), false);
    assert.equal(await f.provider.get(key), null);
  },
);

test(
  'EK-DB-002 a lost real put acknowledgment reports an unknown outcome without replaying the write',
  { timeout: 20_000 },
  async (context) => {
    const f = await fixture(context),
      key = f.key('lost-ack');
    const nativePut = KVClient.prototype.put;
    let submissions = 0;
    context.mock.method(
      KVClient.prototype,
      'put',
      async function (this: KVClient, ...args: Parameters<typeof nativePut>) {
        const result = await nativePut.apply(this, args);
        if (args[0].key?.equals(Buffer.from(f.configuration.prefix + key))) {
          submissions++;
          throw new GRPCUnavailableError(
            'Injected lost acknowledgment after the real server write',
          );
        }
        return result;
      },
    );
    await assert.rejects(
      f.provider.put(key, Uint8Array.from([7])),
      (cause: unknown) =>
        cause instanceof KitError && cause.details.outcome === 'unknown' && !cause.retryable,
    );
    const stored = await f.provider.get(key);
    assert.equal(submissions, 1);
    assert.equal(stored?.version, 1n);
    assert.deepEqual(stored?.value, Uint8Array.from([7]));
  },
);

test(
  'EK-DB-002 real public etcd CAS has exactly one winner across applications with a reusable plugin factory',
  { timeout: 20_000 },
  async (context) => {
    const plugin = etcdPlugin(),
      a = await fixture(context, plugin),
      b = await fixture(context, plugin),
      key = a.key('cas');
    assert.notEqual(a.native, b.native);
    assert.notEqual(a.provider, b.provider);
    assert.equal(
      await a.provider.compareAndSwap({ key, expectedRevision: 0n, value: Uint8Array.from([1]) }),
      true,
    );
    assert.equal(
      await a.provider.compareAndSwap({ key, expectedRevision: 0n, value: Uint8Array.from([2]) }),
      false,
    );
    const original = (await a.provider.get(key))!;
    const results = await Promise.all([
      a.provider.compareAndSwap({
        key,
        expectedRevision: original.revision,
        value: Uint8Array.from([3]),
      }),
      b.provider.compareAndSwap({
        key,
        expectedRevision: original.revision,
        value: Uint8Array.from([4]),
      }),
    ]);
    assert.deepEqual([...results].sort(), [false, true]);
    assert.ok([3, 4].includes((await a.provider.get(key))!.value[0]!));
    await b.app.stop();
    await a.provider.put(key, Uint8Array.from([5]));
    assert.equal((await a.provider.get(key))!.value[0], 5);
  },
);

test(
  'EK-CORE-001 public etcd owns watch and lease lifetimes and shutdown removes a long-lived leased key',
  { timeout: 20_000 },
  async (context) => {
    const f = await fixture(context),
      other = await fixture(context),
      key = f.key('leased');
    const watch = await f.provider.watch(f.base),
      iterator = watch[Symbol.asyncIterator]();
    const lease = await f.provider.grantLease(30);
    assert.ok(Object.isFrozen(lease));
    await assert.rejects(
      other.provider.put(key, Uint8Array.from([1]), { leaseId: lease.id }),
      code('EK_KV_CONFLICT'),
    );
    await f.provider.put(key, Uint8Array.from([9]), { leaseId: lease.id });
    const event = await within(() => iterator.next(), { timeoutMs: 5000 });
    assert.equal(event.value.type, 'put');
    assert.equal(event.value.key, key);
    lease.keepAlive();
    const pending = iterator.next();
    await f.app.stop();
    assert.deepEqual(await pending, { done: true, value: undefined });
    await assert.rejects(f.provider.get(key), code('EK_RESOURCE_CLOSED'));
    await lease.revoke();
    assert.throws(() => lease.keepAlive(), code('EK_RESOURCE_CLOSED'));
    assert.equal(await other.provider.get(key), null);
    const status = await other.native.leaseClient.leaseTimeToLive({ ID: lease.id });
    assert.equal(status.TTL, '-1');
    await f.app.stop();
  },
);

test(
  'EK-SEC-001 real etcd startup rejects wrong server identity, untrusted CA, absent client identity and unauthorized certificates',
  { timeout: 30_000 },
  async () => {
    assert.equal(process.env.ARKENIVA_ETCD_DISPOSABLE, '1');
    const missingCA = new URL(process.env.ARKENIVA_ETCD_URL!);
    missingCA.searchParams.delete('sslca');
    const missingClient = new URL(process.env.ARKENIVA_ETCD_URL!);
    missingClient.searchParams.delete('sslcert');
    missingClient.searchParams.delete('sslkey');
    const variable = 'ARKENIVA_ETCD_NEGATIVE_TEST',
      previous = process.env[variable];
    try {
      for (const url of [
        process.env.ARKENIVA_ETCD_WRONG_SAN_URL!,
        missingCA.href,
        missingClient.href,
        process.env.ARKENIVA_ETCD_UNKNOWN_IDENTITY_URL!,
      ]) {
        assert.ok(url, 'Every negative fixture must be configured');
        process.env[variable] = url;
        const app = await createApplication({
          service,
          plugins: [etcdPlugin()],
          databases: { configuration: { driver: 'etcd', connectionStringEnv: variable } },
        });
        const stale = app.etcd!;
        await assert.rejects(
          app.start(),
          (error) =>
            error instanceof KitError &&
            error.cause instanceof KitError &&
            ['EK_BACKEND_UNAVAILABLE', 'EK_TIMEOUT'].includes(error.cause.code),
        );
        assert.equal(app.state, 'CLOSED');
        await assert.rejects(stale.get('key'), code('EK_RESOURCE_CLOSED'));
        await app.stop();
      }
    } finally {
      if (previous === undefined) delete process.env[variable];
      else process.env[variable] = previous;
    }
  },
);

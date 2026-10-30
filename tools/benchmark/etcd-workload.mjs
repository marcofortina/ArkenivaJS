// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { on } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { Etcd3 } from 'etcd3';
import { noop } from 'cockatiel';
const workloads = new WeakMap();
export const etcdIterations = 100;
export const etcdWarmupIterations = 20;
const modes = ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'];

export function selectEtcdProfile(fixture, mode) {
  assert.ok(modes.includes(mode));
  assert.ok(Array.isArray(fixture.profileNamespaces) && fixture.profileNamespaces.length === 4);
  assert.equal(new Set(fixture.profileNamespaces).size, 4);
  for (const namespace of fixture.profileNamespaces) etcdConnection({ ...fixture, namespace });
  return { ...fixture, namespace: fixture.profileNamespaces[modes.indexOf(mode)] };
}

const casKey = (fixture, index) =>
  fixture.namespace + 'sample-cas/' + String(index).padStart(3, '0');
export const etcdCasValue = (index) => Uint8Array.of(0, 255, 128, index);

export function etcdConnection(fixture) {
  try {
    const url = new URL(fixture.url);
    assert.equal(url.protocol, 'https:');
    assert.equal(url.hostname, 'localhost');
    assert.ok(url.port && !url.username && !url.password && !url.hash);
    assert.ok(['', '/'].includes(url.pathname));
    for (const key of url.searchParams.keys()) {
      assert.ok(['sslca', 'sslcert', 'sslkey', 'prefix'].includes(key));
      assert.equal(url.searchParams.getAll(key).length, 1);
    }
    for (const key of ['sslca', 'sslcert', 'sslkey'])
      assert.ok(url.searchParams.get(key)?.startsWith('/'));
    const prefix = url.searchParams.get('prefix');
    assert.match(prefix, /^\/arkeniva_test_[a-f0-9]{24}\/$/);
    assert.match(fixture.namespace, /^comparison_[a-f0-9]{32}\/$/);
    return { url, prefix, physical: prefix + fixture.namespace };
  } catch {
    throw new Error(
      'The owned etcd comparison requires localhost mTLS and a random scoped namespace',
    );
  }
}

export async function connectEtcd(fixture, maximumResponseBytes) {
  const { url, physical } = etcdConnection(fixture);
  if (maximumResponseBytes !== undefined)
    assert.ok(
      Number.isSafeInteger(maximumResponseBytes) &&
        maximumResponseBytes >= 1024 &&
        maximumResponseBytes <= 1048576,
    );
  const client = new Etcd3({
    hosts: url.origin,
    credentials: {
      rootCertificate: await readFile(url.searchParams.get('sslca')),
      certChain: await readFile(url.searchParams.get('sslcert')),
      privateKey: await readFile(url.searchParams.get('sslkey')),
    },
    grpcOptions: {
      'grpc.enable_retries': 0,
      ...(maximumResponseBytes === undefined
        ? {}
        : { 'grpc.max_receive_message_length': maximumResponseBytes }),
    },
    faultHandling: { global: noop, host: () => noop },
    defaultCallOptions: ({ isStream }) => (isStream ? {} : { deadline: Date.now() + 5000 }),
  });
  try {
    await client.get(physical + 'health').exec();
    return client;
  } catch {
    client.close();
    throw new Error('The owned native etcd comparison connection failed');
  }
}

/** This valid-corpus facade delegates bytes, exact revisions, transactions and streams to etcd3. */
export async function nativeEtcd(fixture) {
  const client = await connectEtcd(fixture),
    { prefix } = etcdConnection(fixture);
  const leases = new Map();
  return {
    native: () => client,
    async get(key) {
      const row = (await client.get(prefix + key).exec()).kvs[0];
      return row
        ? {
            key,
            value: Uint8Array.from(row.value),
            revision: BigInt(row.mod_revision),
            version: BigInt(row.version),
          }
        : null;
    },
    async put(key, value, options = {}) {
      const request = client.put(prefix + key).value(Buffer.from(value));
      if (options.leaseId) request.lease(options.leaseId);
      await request.exec();
    },
    async delete(key) {
      return (
        (
          await client
            .delete()
            .key(prefix + key)
            .exec()
        ).deleted === '1'
      );
    },
    async compareAndSwap(input) {
      return (
        await client
          .if(prefix + input.key, 'Mod', '==', input.expectedRevision.toString())
          .then(client.put(prefix + input.key).value(Buffer.from(input.value)))
          .commit()
      ).succeeded;
    },
    async watch(key) {
      const watcher = await client
        .watch()
        .prefix(prefix + key)
        .create();
      const responses = on(watcher, 'data');
      const iterator = (async function* () {
        for await (const [response] of responses)
          for (const event of response.events) {
            const row = event.kv,
              type = event.type === 'Delete' ? 'delete' : 'put';
            yield {
              type,
              key: row.key.toString().slice(prefix.length),
              revision: BigInt(row.mod_revision),
              ...(type === 'put' ? { value: Uint8Array.from(row.value) } : {}),
            };
          }
      })();
      return {
        [Symbol.asyncIterator]: () => iterator,
        async close() {
          await watcher.cancel();
          await responses.return();
          await iterator.return();
        },
      };
    },
    async grantLease(ttl) {
      const lease = client.lease(ttl, { autoKeepAlive: false });
      lease.on('lost', () => undefined);
      const id = await lease.grant();
      leases.set(id, lease);
      return {
        id,
        keepAlive: () => lease.keepaliveOnce(),
        async revoke() {
          await lease.revoke();
          leases.delete(id);
        },
      };
    },
    async close() {
      try {
        await Promise.all([...leases.values()].map((lease) => lease.revoke()));
      } finally {
        client.close();
      }
    },
  };
}

export async function cleanupEtcd(client, fixture) {
  const { physical } = etcdConnection(fixture);
  await client.delete().prefix(physical).exec();
}

/** Fresh-key CAS is one acknowledged transaction; no hidden retry or update-CAS claim. */
export function etcdWorkload(service, fixture) {
  etcdConnection(fixture);
  assert.equal(workloads.has(service), false);
  const state = { successful: 0, active: false, closed: false };
  workloads.set(service, state);
  return {
    async casCreate() {
      assert.equal(state.closed, false, 'The etcd sampling corpus is already complete');
      assert.equal(state.active, false, 'Only one sampled etcd callback may be active');
      assert.ok(
        state.successful < etcdIterations + etcdWarmupIterations,
        'The bounded etcd fresh-key corpus is exhausted',
      );
      state.active = true;
      try {
        assert.equal(
          await service.compareAndSwap({
            key: casKey(fixture, state.successful),
            expectedRevision: 0n,
            value: etcdCasValue(state.successful),
          }),
          true,
        );
        state.successful++;
        return true;
      } finally {
        state.active = false;
      }
    },
  };
}

export async function completeEtcdWorkload(service, { fixture, measure, records }) {
  const state = workloads.get(service);
  try {
    if (!measure) {
      assert.equal(state, undefined);
      assert.deepEqual(records, []);
      return { sampledCreates: 0, warmupCreates: 0, acknowledgedCreates: 0, staleCasRejections: 0 };
    }
    assert.ok(state);
    assert.equal(state.active, false);
    assert.equal(records.length, 1);
    const record = records[0];
    assert.equal(record.operation, 'casCreate');
    assert.equal(record.sampleCount, etcdIterations);
    assert.equal(record.warmupIterations, etcdWarmupIterations);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, record.sampleCount);
    assert.equal(state.successful, record.sampleCount + record.warmupIterations);
    assert.equal(
      await service.compareAndSwap({
        key: casKey(fixture, 0),
        expectedRevision: 0n,
        value: Uint8Array.of(9, 9, 9, 9),
      }),
      false,
      'An existing key cannot acknowledge another create-only CAS',
    );
    return {
      sampledCreates: record.sampleCount,
      warmupCreates: record.warmupIterations,
      acknowledgedCreates: state.successful,
      staleCasRejections: 1,
      activeCallbacks: 0,
      retainedOwnedKeys: state.successful,
      acknowledgedValueBytes: state.successful * 4,
    };
  } finally {
    if (state) state.closed = true;
    workloads.delete(service);
  }
}

/** Parent-owned native readback checks a bounded range after all worker acknowledgments. */
export async function verifyEtcdCasReadback(observer, fixture, expectedCount) {
  assert.ok(
    Number.isSafeInteger(expectedCount) &&
      expectedCount >= 1 &&
      expectedCount <= etcdIterations + etcdWarmupIterations,
  );
  const { prefix, physical } = etcdConnection(fixture),
    response = await observer
      .getAll()
      .prefix(physical)
      .limit(expectedCount + 1)
      .exec(),
    rows = response.kvs;
  assert.equal(rows.length, expectedCount);
  assert.notEqual(response.more, true, 'The independent etcd range must not be truncated');
  const values = new Map();
  let observedBytes = 0;
  for (const row of rows) {
    assert.ok(Buffer.isBuffer(row.key) && Buffer.isBuffer(row.value));
    observedBytes += row.key.length + row.value.length;
    assert.ok(observedBytes <= 32768, 'The independent etcd range exceeds its byte budget');
    values.set(row.key.toString(), row);
  }
  assert.equal(values.size, expectedCount);
  let previous = 0n;
  for (let index = 0; index < expectedCount; index++) {
    const row = values.get(prefix + casKey(fixture, index));
    assert.ok(row);
    assert.deepEqual(row.value, Buffer.from(etcdCasValue(index)));
    assert.equal(BigInt(row.version), 1n);
    assert.match(row.mod_revision, /^[1-9][0-9]*$/);
    const revision = BigInt(row.mod_revision);
    assert.ok(revision > previous);
    previous = revision;
  }
  return {
    independentlyVerifiedKeys: expectedCount,
    valueBytes: expectedCount * 4,
    observedKeyAndValueBytes: observedBytes,
    exactRevisionAndVersionVerified: true,
  };
}

export async function verifyEtcd(service, fixture) {
  const config = etcdConnection(fixture),
    observer = await connectEtcd(fixture);
  let owned = false,
    watch,
    lease;
  try {
    assert.ok(service.native() instanceof Etcd3);
    assert.equal((await observer.getAll().prefix(config.physical).exec()).kvs.length, 0);
    owned = true;
    const key = fixture.namespace + 'bytes',
      watched = fixture.namespace + 'events/value';
    assert.equal(await service.get(key), null);
    assert.equal(await service.delete(key), false);
    const bytes = Uint8Array.from([0, 255, 128, 7]);
    await service.put(key, bytes);
    const first = await service.get(key);
    assert.deepEqual(first.value, bytes);
    assert.equal(first.version, 1n);
    assert.equal(typeof first.revision, 'bigint');
    assert.ok(first.revision > 0n);
    assert.deepEqual(await observer.get(config.prefix + key).buffer(), Buffer.from(bytes));
    const winners = await Promise.all(
      [8, 9].map((value) =>
        service.compareAndSwap({
          key,
          expectedRevision: first.revision,
          value: Uint8Array.of(value),
        }),
      ),
    );
    assert.deepEqual(winners.toSorted(), [false, true]);
    const second = await service.get(key);
    assert.equal(second.version, 2n);
    assert.ok(second.revision > first.revision);
    assert.equal(await service.compareAndSwap({ key, expectedRevision: 0n, value: bytes }), false);
    watch = await service.watch(fixture.namespace + 'events/');
    const iterator = watch[Symbol.asyncIterator]();
    const events = (async () => {
      const values = [];
      for (let i = 0; i < 3; i++) values.push((await iterator.next()).value);
      return values;
    })();
    void events.catch(() => undefined);
    await service.put(watched, bytes);
    await service.put(watched, new Uint8Array());
    assert.equal(await service.delete(watched), true);
    const ordered = await events;
    assert.deepEqual(
      ordered.map((event) => event.type),
      ['put', 'put', 'delete'],
    );
    assert.deepEqual(ordered[0].value, bytes);
    assert.equal(ordered[1].value.byteLength, 0);
    assert.ok(
      ordered.every((event) => event.key === watched && typeof event.revision === 'bigint'),
    );
    assert.ok(
      ordered[0].revision < ordered[1].revision && ordered[1].revision < ordered[2].revision,
    );
    await watch.close();
    watch = undefined;
    lease = await service.grantLease(30);
    const leased = fixture.namespace + 'leased';
    await service.put(leased, bytes, { leaseId: lease.id });
    const initial = BigInt((await observer.leaseClient.leaseTimeToLive({ ID: lease.id })).TTL);
    let beforeRenewal = initial;
    const agingDeadline = performance.now() + 5000;
    while (beforeRenewal >= initial) {
      assert.ok(
        performance.now() < agingDeadline,
        'The owned lease did not age on the actual server',
      );
      await delay(25);
      beforeRenewal = BigInt((await observer.leaseClient.leaseTimeToLive({ ID: lease.id })).TTL);
    }
    assert.ok(beforeRenewal > 0n);
    await lease.keepAlive();
    const renewalDeadline = performance.now() + 5000;
    while (
      BigInt((await observer.leaseClient.leaseTimeToLive({ ID: lease.id })).TTL) <= beforeRenewal
    ) {
      assert.ok(
        performance.now() < renewalDeadline,
        'The actual server did not acknowledge lease renewal',
      );
      await delay(25);
    }
    assert.deepEqual(await observer.get(config.prefix + leased).buffer(), Buffer.from(bytes));
    await lease.revoke();
    const gone = await observer.leaseClient.leaseTimeToLive({ ID: lease.id });
    assert.equal(gone.TTL, '-1');
    lease = undefined;
    assert.equal(await service.get(leased), null);
    assert.equal(await service.delete(key), true);
    assert.equal(await service.delete(key), false);
    return {
      rawBytesVerified: true,
      exactRevisionAndVersionVerified: true,
      concurrentCasWinners: 1,
      orderedWatchEvents: 3,
      nativeLeaseGrantAndRevokeVerified: true,
      serverObservedLeaseRenewal: true,
    };
  } finally {
    try {
      if (watch) await watch.close();
      if (lease) await lease.revoke();
      if (owned) await cleanupEtcd(observer, fixture);
    } finally {
      observer.close();
    }
  }
}

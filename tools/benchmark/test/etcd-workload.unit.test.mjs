// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Bench } from 'tinybench';
import { setImmediate as nextTurn } from 'node:timers/promises';
import {
  etcdConnection,
  selectEtcdProfile,
  etcdWorkload,
  completeEtcdWorkload,
  verifyEtcdCasReadback,
  etcdIterations,
  etcdWarmupIterations,
} from '../etcd-workload.mjs';

function fixtureInput() {
  const url = new URL('https://localhost:12379');
  for (const name of ['sslca', 'sslcert', 'sslkey']) url.searchParams.set(name, '/private/' + name);
  url.searchParams.set('prefix', '/arkeniva_test_' + 'a'.repeat(24) + '/');
  const profileNamespaces = ['b', 'c', 'd', 'e'].map(
    (letter) => 'comparison_' + letter.repeat(32) + '/',
  );
  return { url: url.href, namespace: profileNamespaces[0], profileNamespaces };
}

test('Owned etcd comparison rejects foreign origins, TLS bypasses and unrelated namespaces before I/O', () => {
  const url = new URL('https://localhost:12379');
  for (const key of ['sslca', 'sslcert', 'sslkey']) url.searchParams.set(key, '/private/' + key);
  url.searchParams.set('prefix', '/arkeniva_test_' + 'a'.repeat(24) + '/');
  const fixture = { url: url.href, namespace: 'comparison_' + 'b'.repeat(32) + '/' };
  assert.ok(etcdConnection(fixture));
  for (const change of [
    (u) => {
      u.hostname = 'foreign.invalid';
    },
    (u) => {
      u.protocol = 'http:';
    },
    (u) => {
      u.searchParams.set('sslkey', 'relative');
    },
    (u) => {
      u.searchParams.set('tlsInsecure', 'true');
    },
    (u) => {
      u.searchParams.append('sslca', '/another');
    },
    (u) => {
      u.searchParams.set('prefix', '/unrelated/');
    },
  ]) {
    const changed = new URL(url);
    change(changed);
    assert.throws(() => etcdConnection({ ...fixture, url: changed.href }));
  }
  assert.throws(() => etcdConnection({ ...fixture, namespace: '/unrelated/' }));
});

test('Each etcd comparison profile captures a distinct owned namespace without changing TLS policy', () => {
  const fixture = fixtureInput(),
    namespaces = new Set();
  for (const mode of ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED']) {
    const selected = selectEtcdProfile(fixture, mode);
    assert.equal(selected.url, fixture.url);
    namespaces.add(selected.namespace);
  }
  assert.equal(namespaces.size, 4);
  assert.equal(fixture.namespace, fixture.profileNamespaces[0]);
  assert.throws(() =>
    selectEtcdProfile(
      { ...fixture, profileNamespaces: Array(4).fill(fixture.namespace) },
      'BASELINE',
    ),
  );
});

test('Etcd fresh-key sampling reconciles actual Tinybench callbacks and independently checks exact int64 revisions', async () => {
  const fixture = fixtureInput(),
    rows = new Map();
  let calls = 0;
  const service = {
    async compareAndSwap(input) {
      calls++;
      assert.equal(input.expectedRevision, 0n);
      if (rows.has(input.key)) return false;
      rows.set(input.key, Buffer.from(input.value));
      return true;
    },
  };
  const work = etcdWorkload(service, fixture).casCreate,
    bench = new Bench({
      time: 0,
      iterations: etcdIterations,
      warmupTime: 0,
      warmupIterations: etcdWarmupIterations,
      retainSamples: true,
      throws: true,
    });
  bench.add('casCreate', async () => {
    await work();
  });
  await bench.run();
  const samples = bench.tasks[0].result.latency.samples;
  assert.equal(samples.length, etcdIterations);
  assert.equal(rows.size, samples.length + etcdWarmupIterations);
  await assert.rejects(work());
  assert.equal(calls, 120, 'A full corpus must reject before another native transaction');
  const completion = await completeEtcdWorkload(service, {
    fixture,
    measure: true,
    records: [
      {
        operation: 'casCreate',
        sampleCount: samples.length,
        warmupIterations: etcdWarmupIterations,
        rawLatency: { unit: 'milliseconds', values: [...samples] },
      },
    ],
  });
  assert.equal(completion.acknowledgedCreates, 120);
  assert.equal(completion.staleCasRejections, 1);
  assert.equal(calls, 121);
  await assert.rejects(work());
  assert.equal(calls, 121);
  const values = [...rows.values()];
  assert.deepEqual(values[0], Buffer.from([0, 255, 128, 0]));
  assert.deepEqual(values.at(-1), Buffer.from([0, 255, 128, 119]));
  const prefix = etcdConnection(fixture).prefix;
  let limit, mode;
  const observed = [...rows].map(([key, value], index) => ({
    key: Buffer.from(prefix + key),
    value,
    version: '1',
    mod_revision: String(9007199254740993n + BigInt(index)),
  }));
  const observer = {
    getAll() {
      return {
        prefix(value) {
          assert.equal(value, etcdConnection(fixture).physical);
          return {
            limit(count) {
              limit = count;
              return {
                async exec() {
                  const copy = observed.map((row) => ({ ...row }));
                  if (mode === 'bytes') copy[0].value = Buffer.from([9]);
                  if (mode === 'version') copy[0].version = '2';
                  if (mode === 'revision') copy[1].mod_revision = copy[0].mod_revision;
                  return { kvs: copy, more: mode === 'truncated' };
                },
              };
            },
          };
        },
      };
    },
  };
  const readback = await verifyEtcdCasReadback(observer, fixture, 120);
  assert.equal(limit, 121);
  assert.equal(readback.independentlyVerifiedKeys, 120);
  assert.equal(readback.exactRevisionAndVersionVerified, true);
  assert.equal(readback.valueBytes, 480);
  for (mode of ['bytes', 'version', 'revision', 'truncated'])
    await assert.rejects(verifyEtcdCasReadback(observer, fixture, 120));
});

test('Etcd callbacks wait for acknowledged transactions and never queue another callback behind held work', async () => {
  const fixture = fixtureInput();
  let release,
    enter,
    calls = 0,
    completed = false;
  const gate = new Promise((resolve) => {
      release = resolve;
    }),
    entered = new Promise((resolve) => {
      enter = resolve;
    }),
    service = {
      async compareAndSwap() {
        calls++;
        enter();
        await gate;
        return true;
      },
    },
    work = etcdWorkload(service, fixture).casCreate,
    pending = work().then(() => {
      completed = true;
    });
  try {
    await entered;
    await nextTurn();
    assert.equal(completed, false);
    await assert.rejects(work());
    assert.equal(calls, 1);
  } finally {
    release();
  }
  await pending;
  assert.equal(completed, true);
  await assert.rejects(completeEtcdWorkload(service, { fixture, measure: false, records: [] }));
  await assert.rejects(work());
  assert.equal(calls, 1);
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import native from 'node:dns/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { createDnsService } from '@arkenivajs/dns';
import { startDnsFixture } from '../dist/fixture.js';
import { runDnsExample } from '../dist/main.js';

const code = (expected: string) => (error: unknown) =>
  error instanceof Error && Object.getOwnPropertyDescriptor(error, 'code')?.value === expected;
test('Public DNS example uses a real local authority and prints only result counts', async () => {
  assert.deepEqual(await runDnsExample(), {
    aRecords: 1,
    srvRecords: 1,
    txtRecords: 2,
    firstTxtSegments: 2,
    ttlObserved: true,
    osLookupDistinct: true,
  });
});
test('Every approved record family is decoded by the actual Node resolver over UDP', async () => {
  const fixture = await startDnsFixture(),
    dns = createDnsService({
      resolvers: [{ name: 'lab', servers: [fixture.server] }],
      maxConcurrency: 4,
      timeoutMs: 1000,
    });
  try {
    const query = { hostname: 'internal.test' };
    assert.deepEqual(await dns.resolve({ ...query, type: 'A' }), [
      { address: '192.0.2.11', ttlSeconds: 30 },
    ]);
    assert.deepEqual(await dns.resolve({ ...query, type: 'AAAA' }), [
      { address: '2001:db8::1', ttlSeconds: 30 },
    ]);
    assert.deepEqual(await dns.resolve({ ...query, type: 'CNAME' }), [
      { hostname: 'target.internal.test' },
    ]);
    assert.deepEqual(await dns.resolve({ ...query, type: 'NS' }), [
      { hostname: 'ns.internal.test' },
    ]);
    assert.deepEqual(await dns.resolve({ ...query, type: 'PTR' }), [
      { hostname: 'ptr.internal.test' },
    ]);
    assert.deepEqual(await dns.resolve({ ...query, type: 'MX' }), [
      { exchange: 'mail.internal.test', priority: 10 },
    ]);
    assert.deepEqual(await dns.resolve({ ...query, type: 'SOA' }), [
      {
        nsname: 'ns.internal.test',
        hostmaster: 'hostmaster.internal.test',
        serial: 42,
        refresh: 300,
        retry: 60,
        expire: 3600,
        minttl: 30,
      },
    ]);
    assert.deepEqual(
      await dns.resolve({ hostname: '_postgresql._tcp.internal.test', type: 'SRV' }),
      [{ name: 'db.internal.test', port: 5432, priority: 10, weight: 5 }],
    );
    assert.deepEqual(await dns.resolve({ ...query, type: 'TXT' }), [
      { segments: ['first', 'second'] },
      { segments: ['separate'] },
    ]);
    assert.deepEqual(await dns.resolve({ ...query, type: 'CAA' }), [
      { critical: 0, tag: 'issue', value: 'ca.internal.test' },
    ]);
    assert.deepEqual(await dns.resolve({ ...query, type: 'NAPTR' }), [
      {
        order: 10,
        preference: 20,
        flags: 'S',
        service: 'SIP+D2U',
        regexp: '',
        replacement: '_sip._udp.internal.test',
      },
    ]);
    assert.deepEqual(await dns.reverse('192.0.2.1'), ['ptr.internal.test']);
    assert.deepEqual(await dns.reverse('2001:db8::1'), ['ptr.internal.test']);
    assert.equal(
      (await dns.resolve({ hostname: 'bücher.internal.test', type: 'A' }))[0]!.address,
      '192.0.2.11',
    );
  } finally {
    await dns.close();
    await fixture.close();
  }
});
test('Contradictory named resolvers and independent service instances never mutate global DNS or hosts lookup', async () => {
  const a = await startDnsFixture('192.0.2.11'),
    b = await startDnsFixture('192.0.2.22'),
    before = native.getServers(),
    settings = {
      resolvers: [
        { name: 'first', servers: [a.server] },
        { name: 'second', servers: [b.server] },
      ],
      maxConcurrency: 4,
      timeoutMs: 1000,
    },
    first = createDnsService(settings),
    second = createDnsService(settings);
  try {
    assert.equal(
      (await first.resolve({ hostname: 'internal.test', type: 'A' }))[0]!.address,
      '192.0.2.11',
    );
    assert.equal(
      (await first.resolve({ hostname: 'internal.test', type: 'A', resolver: 'second' }))[0]!
        .address,
      '192.0.2.22',
    );
    assert.equal(
      (await first.resolve({ hostname: 'localhost', type: 'A' }))[0]!.address,
      '192.0.2.11',
    );
    const local = await first.lookup('localhost', { family: 4, all: true });
    assert.ok(local.some((record) => record.address === '127.0.0.1'));
    assert.ok(local.every((record) => record.address !== '192.0.2.11'));
    await first.close();
    assert.equal(
      (await second.resolve({ hostname: 'internal.test', type: 'A', resolver: 'second' }))[0]!
        .address,
      '192.0.2.22',
    );
    assert.deepEqual(native.getServers(), before);
  } finally {
    await first.close();
    await second.close();
    await a.close();
    await b.close();
  }
});
test(
  'Real NXDOMAIN, NODATA, server failure and deadlines retain safe categories',
  { timeout: 3000 },
  async () => {
    const fixture = await startDnsFixture(),
      dns = createDnsService({
        resolvers: [{ name: 'lab', servers: [fixture.server] }],
        maxConcurrency: 4,
        timeoutMs: 1000,
      });
    try {
      await assert.rejects(
        () => dns.resolve({ hostname: 'missing.internal.test', type: 'A' }),
        code('EK_DNS_NOT_FOUND'),
      );
      await assert.rejects(
        () => dns.resolve({ hostname: 'empty.internal.test', type: 'A' }),
        code('EK_DNS_NOT_FOUND'),
      );
      await assert.rejects(
        () => dns.resolve({ hostname: 'failure.internal.test', type: 'A' }),
        code('EK_DNS_TEMPORARY'),
      );
      await assert.rejects(
        () => dns.resolve({ hostname: 'timeout.internal.test', type: 'A' }, { timeoutMs: 10 }),
        code('EK_DNS_TIMEOUT'),
      );
    } finally {
      await dns.close();
      await fixture.close();
    }
  },
);
test(
  'One canceled query does not cancel another query on the same actual Resolver',
  { timeout: 3000 },
  async () => {
    const fixture = await startDnsFixture(),
      dns = createDnsService({
        resolvers: [{ name: 'lab', servers: [fixture.server] }],
        maxConcurrency: 4,
        timeoutMs: 1000,
      });
    try {
      const controller = new AbortController(),
        a = dns.resolve(
          { hostname: 'delayed.first.internal.test', type: 'A' },
          { signal: controller.signal },
        ),
        b = dns.resolve({ hostname: 'delayed.second.internal.test', type: 'A' });
      await delay(1);
      controller.abort();
      await assert.rejects(a, code('EK_ABORTED'));
      assert.equal((await b)[0]!.address, '192.0.2.11');
    } finally {
      await dns.close();
      await fixture.close();
    }
  },
);

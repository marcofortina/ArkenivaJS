// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication, KitError, COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry, Plugin } from '@arkenivajs/core';
import { createDnsService, dnsPlugin, DNS_CAPABILITY } from '../../dist/index.js';
import type { DnsService } from '../../dist/index.js';

const settings = () => ({
  resolvers: [{ name: 'lab', servers: ['127.0.0.1:15353'] }],
  maxConcurrency: 2,
  timeoutMs: 1000,
});
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
test('DNS constructors capture immutable profiles without changing global resolvers or disclosing endpoints', async () => {
  const before = dns.getServers(),
    config = settings(),
    service = createDnsService(config);
  config.resolvers[0]!.servers[0] = '192.0.2.1';
  try {
    assert.deepEqual(service.getResolvers(), ['lab']);
    assert.ok(Object.isFrozen(service.getResolvers()));
    assert.deepEqual(dns.getServers(), before);
    assert.ok(!JSON.stringify(service.getResolvers()).includes('127.0.0.1'));
  } finally {
    await service.close();
    await service.close();
  }
});
test('Query validation rejects unsafe names, profiles, options and forged values before native calls', async (t) => {
  let calls = 0;
  t.mock.method(dns.Resolver.prototype, 'resolve4', async () => {
    calls++;
    return [{ address: '192.0.2.1', ttl: 30 }];
  });
  const service = createDnsService(settings());
  try {
    for (const name of [
      '',
      'a..test',
      'a'.repeat(64) + '.test',
      '-bad.test',
      'bad-.test',
      'a/b.test',
      'name\n.test',
      null,
      {},
    ])
      await assert.rejects(
        () => service.resolve({ hostname: name as never, type: 'A' }),
        code('EK_DNS_CONFIG'),
      );
    for (const query of [
      null,
      { hostname: 'internal.test', type: 'ANY' },
      { hostname: 'internal.test', type: 'A', resolver: 'missing' },
      { hostname: 'internal.test', type: 'A', extra: true },
    ])
      await assert.rejects(() => service.resolve(query as never), code('EK_DNS_CONFIG'));
    for (const options of [
      null,
      { timeoutMs: 0 },
      { timeoutMs: null },
      { signal: {} },
      { signal: { aborted: false, addEventListener() {}, removeEventListener() {} } },
      { signal: Object.create(AbortSignal.prototype) },
      { signal: null },
      { clock: () => 0 },
    ])
      await assert.rejects(
        () => service.resolve({ hostname: 'internal.test', type: 'A' }, options as never),
        code('EK_DNS_CONFIG'),
      );
    assert.equal(calls, 0);
    assert.deepEqual(await service.resolve({ hostname: 'bücher.internal.test', type: 'A' }), [
      { address: '192.0.2.1', ttlSeconds: 30 },
    ]);
    assert.equal(calls, 1);
  } finally {
    await service.close();
  }
});
test('Native answers are bounded, normalized and immutable without fabricated TTL or merged TXT records', async (t) => {
  t.mock.method(dns.Resolver.prototype, 'resolve4', async () => ['192.0.2.1']);
  t.mock.method(dns.Resolver.prototype, 'resolveTxt', async () => [['first', 'second'], ['third']]);
  const service = createDnsService(settings());
  try {
    assert.deepEqual(await service.resolve({ hostname: 'internal.test', type: 'A' }), [
      { address: '192.0.2.1' },
    ]);
    const records = await service.resolve({ hostname: 'internal.test', type: 'TXT' });
    assert.deepEqual(records, [{ segments: ['first', 'second'] }, { segments: ['third'] }]);
    assert.ok(Object.isFrozen(records));
    assert.ok(Object.isFrozen(records[0]!.segments));
    t.mock.method(dns.Resolver.prototype, 'resolve4', async () => [
      { address: 'not-an-ip', ttl: 1 },
    ]);
    await assert.rejects(
      () => service.resolve({ hostname: 'internal.test', type: 'A' }),
      code('EK_DNS_TEMPORARY'),
    );
  } finally {
    await service.close();
  }
});
test('Native failure categories produce fixed safe errors without resolver or hostname disclosure', async (t) => {
  const service = createDnsService(settings());
  try {
    for (const [nativeCode, expected] of [
      ['ENOTFOUND', 'EK_DNS_NOT_FOUND'],
      ['ENODATA', 'EK_DNS_NOT_FOUND'],
      ['ETIMEOUT', 'EK_DNS_TIMEOUT'],
      ['ESERVFAIL', 'EK_DNS_TEMPORARY'],
      ['EINVAL', 'EK_DNS_CONFIG'],
    ]) {
      t.mock.method(dns.Resolver.prototype, 'resolve4', async () => {
        throw Object.assign(new Error('private-dns-endpoint'), { code: nativeCode });
      });
      await assert.rejects(
        () => service.resolve({ hostname: 'private.internal.test', type: 'A' }),
        (error) => {
          assert.ok(error instanceof KitError);
          assert.equal(error.code, expected);
          assert.ok(!JSON.stringify(error.toSafeJSON()).includes('private'));
          return true;
        },
      );
    }
  } finally {
    await service.close();
  }
});
test(
  'Cancellation and timeout retain physical admission without cancelling another shared resolver query',
  { timeout: 3000 },
  async (t) => {
    let finish!: (value: { address: string; ttl: number }[]) => void,
      cancelled = 0;
    const pending = new Promise<{ address: string; ttl: number }[]>((resolve) => {
      finish = resolve;
    });
    t.mock.method(dns.Resolver.prototype, 'resolve4', () => pending);
    const original = dns.Resolver.prototype.cancel;
    t.mock.method(
      dns.Resolver.prototype,
      'cancel',
      function (this: InstanceType<typeof dns.Resolver>) {
        cancelled++;
        return original.call(this);
      },
    );
    const service = createDnsService({ ...settings(), maxConcurrency: 1 });
    try {
      const controller = new AbortController(),
        result = service.resolve(
          { hostname: 'internal.test', type: 'A' },
          { signal: controller.signal },
        );
      await delay(0);
      controller.abort();
      await assert.rejects(result, code('EK_ABORTED'));
      await assert.rejects(
        () => service.resolve({ hostname: 'other.internal.test', type: 'A' }),
        code('EK_DNS_TEMPORARY'),
      );
      assert.equal(cancelled, 0);
      finish([{ address: '192.0.2.1', ttl: 10 }]);
      await delay(0);
      assert.equal(
        (await service.resolve({ hostname: 'other.internal.test', type: 'A' }))[0]!.address,
        '192.0.2.1',
      );
    } finally {
      finish([]);
      await service.close();
    }
  },
);
test('OS lookup uses native getaddrinfo semantics and remains independently closeable', async () => {
  const service = createDnsService(settings());
  assert.deepEqual(await service.lookup('127.0.0.1', { family: 4, all: true }), [
    { address: '127.0.0.1', family: 4 },
  ]);
  for (const query of [{ family: 5 }, { all: 'yes' }, null, { resolver: 'lab' }])
    await assert.rejects(() => service.lookup('localhost', query as never), code('EK_DNS_CONFIG'));
  for (const value of ['127.1', 'fe80::1%eth0', null, {}])
    await assert.rejects(() => service.reverse(value as never), code('EK_DNS_CONFIG'));
  await service.close();
  await assert.rejects(() => service.lookup('localhost'), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => service.getResolvers(), code('EK_RESOURCE_CLOSED'));
});
test('Configuration rejects incomplete/unsafe profiles before native resource allocation', () => {
  for (const input of [
    null,
    {},
    { ...settings(), extra: true },
    { ...settings(), maxConcurrency: 0 },
    { ...settings(), timeoutMs: 0 },
    { ...settings(), defaultResolver: 'missing' },
    { ...settings(), resolvers: [] },
    { ...settings(), resolvers: [{ name: 'lab', servers: [] }] },
    { ...settings(), resolvers: [{ name: 'lab', servers: ['localhost:53'] }] },
    { ...settings(), resolvers: [{ name: 'lab', servers: ['127.0.0.1:0'] }] },
    { ...settings(), resolvers: [{ name: 'lab', servers: ['127.0.0.1:53', '127.0.0.1:53'] }] },
    { ...settings(), resolvers: [settings().resolvers[0], settings().resolvers[0]] },
  ])
    assert.throws(() => createDnsService(input as never), code('EK_DNS_CONFIG'));
});
test('Managed resolvers require no implicit logging service and isolate their application lifetime', async () => {
  const plugin = dnsPlugin(settings()),
    config = {
      service: { name: 'dns-fixture', version: '1.0.0', environment: 'test' as const },
      plugins: [plugin],
    };
  const a = await createApplication(config),
    b = await createApplication(config);
  try {
    await a.start();
    await b.start();
    const first = a.resolve<DnsService>(DNS_CAPABILITY),
      second = b.resolve<DnsService>(DNS_CAPABILITY);
    await a.stop();
    await assert.rejects(() => first.lookup('127.0.0.1'), code('EK_RESOURCE_CLOSED'));
    assert.deepEqual(await second.lookup('127.0.0.1'), [{ address: '127.0.0.1', family: 4 }]);
  } finally {
    await a.stop();
    await b.stop();
  }
});

test('Optional observation has bounded labels, never receives query payloads and cannot replace native results', async (t) => {
  let calls = 0;
  const events: unknown[] = [];
  t.mock.method(dns.Resolver.prototype, 'resolve4', async () => {
    calls++;
    return [{ address: '192.0.2.1', ttl: 30 }];
  });
  const log = (message: string, fields?: Readonly<Record<string, unknown>>) => {
    events.push({ message, fields });
  };
  const logger: Logger = {
    trace: log,
    debug: log,
    info: log,
    warn: log,
    error: log,
    fatal: log,
    child: () => logger,
    setLevel() {},
    async flush() {},
  };
  const telemetry: Telemetry = {
    async measure(_name, fn) {
      return fn();
    },
    async withSpan(_name, fn) {
      return fn();
    },
    addCounter(name, value, attrs) {
      events.push({ name, value, attrs });
    },
    recordHistogram() {
      return Promise.reject(new Error('private-observation-value'));
    },
    setGauge(name, value, attrs) {
      events.push({ name, value, attrs });
    },
    async flush() {},
  };
  const logging: Plugin = {
      id: 'logging-fixture',
      version: '1.0.0',
      capabilities: new Set(['logger']),
      init(context) {
        context.provide(COMPONENTS.logger, logger);
      },
      close() {},
    },
    observation: Plugin = {
      id: 'telemetry-fixture',
      version: '1.0.0',
      capabilities: new Set(['telemetry']),
      init(context) {
        context.provide(COMPONENTS.telemetry, telemetry);
      },
      close() {},
    };
  const app = await createApplication({
    service: { name: 'dns-observation', version: '1.0.0', environment: 'test' },
    plugins: [dnsPlugin(settings()), observation, logging],
  });
  try {
    await app.start();
    const result = await app
      .resolve<DnsService>(DNS_CAPABILITY)
      .resolve({ hostname: 'private.internal.test', type: 'A' });
    assert.equal(result[0]!.address, '192.0.2.1');
    assert.equal(calls, 1);
    const wire = JSON.stringify(events);
    assert.ok(wire.includes('dns.operation.count'));
    assert.ok(wire.includes('dns.observation.dropped'));
    assert.ok(!wire.includes('private'));
    assert.ok(!wire.includes('127.0.0.1'));
    assert.ok(!wire.includes('192.0.2.1'));
  } finally {
    await app.stop();
  }
});

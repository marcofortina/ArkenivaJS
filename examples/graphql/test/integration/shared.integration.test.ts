// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { sharedFixture, until } from '../shared-fixture.js';

test(
  'Packed public counter adapter isolates real mTLS NATS events across independent WSS processes',
  { timeout: 25000 },
  async () => {
    const namespace = randomBytes(12).toString('hex'),
      r = await sharedFixture(namespace);
    const service = r.f.service();
    const child = fork(new URL('../shared-worker.js', import.meta.url), [], {
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    const messages: {
      kind: string;
      a?: unknown[];
      b?: unknown[];
      active?: number;
      failures?: number;
    }[] = [];
    child.on('message', (message) => messages.push(message as (typeof messages)[number]));
    const exited = once(child, 'exit');
    async function wait(kind: string) {
      await until(() => {
        assert.equal(child.exitCode, null, 'The independent counter process exited prematurely');
        assert.equal(
          messages.some((message) => message.kind === 'failure'),
          false,
        );
        return messages.some((message) => message.kind === kind);
      });
    }
    const event = { type: 'next', id: 'counter', payload: { data: { counterChanged: 1 } } };
    try {
      const authorization = await r.f.token(),
        otherAuthorization = await r.f.token('tenant-b');
      child.send({ namespace, issuer: r.f.issuer, authorization, otherAuthorization });
      const local = await r.connect(authorization);
      await until(() => r.provider.stats().acquired === 1);
      await r.provider.ready();
      await wait('ready');
      for (const token of [authorization, otherAuthorization]) {
        const response = await r.f.send({ query: 'mutation { increment }' }, token);
        assert.equal(response.status, 200);
        assert.deepEqual(JSON.parse(response.body), { data: { increment: 1 } });
      }
      await until(() => local.frames.length === 1);
      assert.deepEqual(local.frames, [event]);
      child.send({ kind: 'mutate' });
      await wait('mutated');
      await until(() => local.frames.length === 2);
      await delay(40);
      child.send({ kind: 'inspect' });
      await wait('frames');
      const remote = messages.find((message) => message.kind === 'frames')!;
      assert.deepEqual(remote.a, [event, event]);
      assert.deepEqual(remote.b, [event]);
      assert.deepEqual(local.frames, [event, event]);
      const tenant = r.authority.tenantFrom(await r.authority.verifyBearer(authorization));
      await assert.rejects(r.provider.port.publish('counter', 2, { ...tenant }));
      assert.throws(() => r.provider.port.subscribe('counter', { ...tenant }));
      await assert.rejects(r.provider.port.publish('foreign-topic', 2, tenant));
      await assert.rejects(r.provider.port.publish('counter', 2147483648, tenant));
      const proxy = new Proxy(tenant, {
        getOwnPropertyDescriptor() {
          throw new Error('Tenant proxy hooks must not execute');
        },
      });
      assert.throws(() => r.provider.port.subscribe('counter', proxy));
      const sources = Array.from({ length: 3 }, () => r.provider.port.subscribe('counter', tenant));
      await r.provider.ready();
      assert.equal(r.provider.stats().active, 4);
      assert.throws(() => r.provider.port.subscribe('counter', tenant));
      for (const source of sources) await source[Symbol.asyncIterator]().return?.();
      const abort = new AbortController();
      const cancelled = r.provider.port.subscribe('counter', tenant, { signal: abort.signal });
      abort.abort();
      assert.equal((await cancelled[Symbol.asyncIterator]().next()).done, true);
      await until(() => r.provider.stats().active === 1);
      assert.equal(r.failures(), 0);
      assert.doesNotMatch(r.f.logs(), /Bearer /);
    } finally {
      if (child.connected) child.send({ kind: 'close' });
      const timeout = setTimeout(() => child.kill('SIGTERM'), 5000);
      timeout.unref();
      try {
        const [code] = await exited;
        assert.equal(code, 0);
        assert.ok(
          messages.some(
            (message) =>
              message.kind === 'closed' && message.active === 0 && message.failures === 0,
          ),
        );
      } finally {
        clearTimeout(timeout);
        await r.close();
      }
      assert.equal(r.provider.stats().active, 0);
      assert.equal(r.bus.stats().subscriptions, 0);
      assert.equal(service.stats().activeSubscriptions, 0);
    }
  },
);

test(
  'Shared counter delivery rejects broker payloads, retires overflow and owns pending reads',
  { timeout: 15000 },
  async () => {
    const namespace = randomBytes(12).toString('hex'),
      r = await sharedFixture(namespace);
    try {
      const tenant = r.authority.tenantFrom(await r.authority.verifyBearer(await r.f.token()));
      const subject =
        'graphql.counter.v1.' +
        namespace +
        '.' +
        createHash('sha256')
          .update(JSON.stringify([tenant.identity.issuer, tenant.tenantId]))
          .digest('hex');
      const overflow = r.provider.port.subscribe('counter', tenant)[Symbol.asyncIterator]();
      await r.provider.ready();
      for (let value = 0; value < 5; value++) await r.bus.publish(subject, value);
      await until(() => r.provider.stats().active === 0);
      await assert.rejects(overflow.next(), { code: 'EK_GQL_SUBSCRIPTION' });
      const invalid = r.provider.port.subscribe('counter', tenant)[Symbol.asyncIterator]();
      await r.provider.ready();
      await r.bus.publish(subject, 'invalid counter wire payload');
      await until(() => r.provider.stats().active === 0);
      await assert.rejects(invalid.next(), { code: 'EK_GQL_SUBSCRIPTION' });
      const pending = r.provider.port.subscribe('counter', tenant)[Symbol.asyncIterator]();
      await r.provider.ready();
      const first = pending.next();
      await assert.rejects(pending.next(), { code: 'EK_GQL_SUBSCRIPTION' });
      await pending.return?.();
      assert.equal((await first).done, true);
      assert.equal(r.provider.stats().active, 0);
      assert.equal(r.bus.stats().subscriptions, 0);
      assert.equal(r.failures(), 0);
      assert.doesNotMatch(r.f.logs(), /invalid counter wire payload|Bearer /);
      await r.bus.close();
      const unavailable = r.provider.port.subscribe('counter', tenant)[Symbol.asyncIterator]();
      await assert.rejects(unavailable.next(), { code: 'EK_GQL_SUBSCRIPTION' });
      await until(() => r.provider.stats().active === 0);
      await assert.rejects(r.provider.ready(), { code: 'EK_GQL_SUBSCRIPTION' });
    } finally {
      await r.close();
    }
  },
);

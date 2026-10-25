// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { etcdConfiguration } from '../../dist/config.js';
import { EtcdTransport } from '../../dist/transport.js';
import { EtcdWatch } from '../../dist/watch.js';
import { streamProxy } from '../fixtures/stream-proxy.js';

function fixture(context: TestContext) {
  assert.equal(
    process.env.ARKENIVA_ETCD_DISPOSABLE,
    '1',
    'Only a dedicated disposable etcd server may be used',
  );
  assert.ok(
    process.env.ARKENIVA_ETCD_URL && process.env.ARKENIVA_ETCD_CONTROL_URL,
    'Authenticated client/control fixture URLs are required',
  );
  const configuration = etcdConfiguration(
    { driver: 'etcd', connectionStringEnv: 'ARKENIVA_ETCD_URL' },
    'test',
  );
  const controller = new AbortController(),
    writer = new EtcdTransport(configuration, controller.signal);
  const base = 'watch:' + randomUUID() + ':',
    keys = new Set<string>(),
    watches = new Set<EtcdWatch>();
  context.after(async () => {
    try {
      await Promise.all([...watches].map((watch) => watch.close()));
      for (const key of keys) await writer.client.delete().key(configuration.prefix + key);
    } finally {
      controller.abort();
      writer.client.close();
    }
  });
  return {
    configuration,
    writer,
    controller,
    base,
    key(name: string) {
      const key = base + name;
      keys.add(key);
      return key;
    },
    watch(
      options: {
        signal?: AbortSignal;
        configuration?: typeof configuration;
        reconnect?: () => void;
        closed?: () => void;
      } = {},
    ) {
      const watch = new EtcdWatch(
        options.configuration ?? configuration,
        configuration.prefix + base,
        controller.signal,
        options.signal,
        options.reconnect ?? (() => {}),
        options.closed ?? (() => {}),
      );
      watches.add(watch);
      return watch;
    },
  };
}

const next = (watch: EtcdWatch) => within(() => watch.next(), { timeoutMs: 5000 });
async function eventually(check: () => boolean) {
  const deadline = performance.now() + 5000;
  while (!check()) {
    if (performance.now() > deadline) assert.fail('The watch condition did not complete');
    await delay(10);
  }
}

test(
  'EK-DB-002 live etcd watch preserves binary values, exact revisions, ordered updates and delete events',
  { timeout: 20_000 },
  async (context) => {
    const f = fixture(context),
      watch = f.watch(),
      key = f.key('value');
    await watch.open();
    const bytes = Buffer.from([0, 255, 128, 1]);
    await f.writer.client.put(f.configuration.prefix + key).value(bytes);
    await f.writer.client.put(f.configuration.prefix + key).value(Buffer.alloc(0));
    await f.writer.client.delete().key(f.configuration.prefix + key);
    const first = await next(watch),
      second = await next(watch),
      third = await next(watch);
    assert.equal(first.done, false);
    assert.equal(second.done, false);
    assert.equal(third.done, false);
    assert.deepEqual(first.value, {
      type: 'put',
      key,
      value: Uint8Array.from(bytes),
      revision: first.value.revision,
    });
    assert.equal(typeof first.value.revision, 'bigint');
    assert.equal(second.value.type, 'put');
    assert.equal(second.value.value!.byteLength, 0);
    assert.equal(third.value.type, 'delete');
    assert.equal(third.value.value, undefined);
    assert.ok(
      first.value.revision < second.value.revision && second.value.revision < third.value.revision,
    );
    const pending = watch.next();
    await watch.close();
    assert.deepEqual(await pending, { done: true, value: undefined });
    assert.deepEqual(await watch.next(), { done: true, value: undefined });
    assert.deepEqual(await watch.return(), { done: true, value: undefined });
  },
);

test(
  'EK-CORE-001 live etcd aborts an idle watch iterator and closes its owned client once',
  { timeout: 15_000 },
  async (context) => {
    const f = fixture(context),
      abort = new AbortController();
    let closed = 0;
    const watch = f.watch({
      signal: abort.signal,
      closed: () => {
        closed++;
      },
    });
    await watch.open();
    const pending = watch.next();
    abort.abort('Watch caller stopped');
    await assert.rejects(
      pending,
      (error) => error instanceof KitError && error.code === 'EK_ABORTED',
    );
    await watch.close();
    await watch.close();
    assert.equal(closed, 1);
    await assert.rejects(
      watch.next(),
      (error) => error instanceof KitError && error.code === 'EK_ABORTED',
    );
  },
);

test(
  'EK-DB-002 live etcd watch pressure reports an explicit gap instead of silently dropping events',
  { timeout: 30_000 },
  async (context) => {
    const f = fixture(context);
    let closed = false;
    const watch = f.watch({
        closed: () => {
          closed = true;
        },
      }),
      key = f.key('pressure');
    await watch.open();
    for (let index = 0; index < 270; index++)
      await f.writer.client.put(f.configuration.prefix + key).value(String(index));
    await eventually(() => closed);
    await assert.rejects(
      watch.next(),
      (error) =>
        error instanceof KitError &&
        error.code === 'EK_KV_CONFLICT' &&
        error.details.watchGap === true &&
        error.details.limitExceeded === true,
    );
  },
);

for (const compact of [false, true]) {
  test(
    `EK-DB-002 real etcd watch ${compact ? 'surfaces compacted history' : 'replays missed changes'} after a targeted TCP disconnect`,
    { timeout: 30_000 },
    async (context) => {
      const f = fixture(context),
        original = new URL(process.env.ARKENIVA_ETCD_URL!);
      const proxy = await streamProxy(Number(original.port || 443));
      context.after(() => proxy.close());
      const configuration = {
        ...f.configuration,
        native: { ...f.configuration.native, hosts: [`https://localhost:${proxy.port}`] },
      };
      let reconnects = 0;
      const watch = f.watch({
          configuration,
          reconnect: () => {
            reconnects++;
          },
        }),
        key = f.key('replay');
      await watch.open();
      const first = await f.writer.client
        .put(f.configuration.prefix + key)
        .value('first')
        .exec();
      assert.equal((await next(watch)).value.revision, BigInt(first.header.revision));
      proxy.cut();
      await eventually(() => reconnects > 0);
      const second = await f.writer.client
        .put(f.configuration.prefix + key)
        .value('second')
        .exec();
      const third = await f.writer.client
        .put(f.configuration.prefix + key)
        .value('third')
        .exec();
      if (compact) {
        const root = etcdConfiguration(
          { driver: 'etcd', connectionStringEnv: 'ARKENIVA_ETCD_CONTROL_URL' },
          'test',
        );
        const control = new EtcdTransport(root, f.controller.signal);
        try {
          await control.client.kv.compact({ revision: third.header.revision, physical: true });
        } finally {
          control.client.close();
        }
      }
      proxy.restore();
      if (compact) {
        await assert.rejects(
          next(watch),
          (error) =>
            error instanceof KitError &&
            error.code === 'EK_KV_CONFLICT' &&
            error.details.watchGap === true &&
            typeof error.details.compactedRevision === 'string',
        );
      } else {
        const a = await next(watch),
          b = await next(watch);
        assert.equal(a.value.revision, BigInt(second.header.revision));
        assert.equal(b.value.revision, BigInt(third.header.revision));
        assert.equal(new TextDecoder().decode(a.value.value), 'second');
        assert.equal(new TextDecoder().decode(b.value.value), 'third');
      }
      await watch.close();
    },
  );
}

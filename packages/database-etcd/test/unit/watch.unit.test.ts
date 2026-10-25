// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { WatchClient, Etcd3, EtcdPermissionDeniedError } from 'etcd3';
import type { IDuplexStream, IWatchRequest, IWatchResponse } from 'etcd3';
import { KitError } from '@arkenivajs/core';
import { EtcdWatch } from '../../dist/watch.js';
import { header, deferred } from '../fixtures/native-double.js';

/** Only the selected SDK's stream boundary is doubled; integration suites exercise real TLS streams. */
class WatchStream extends EventEmitter {
  readonly requests: IWatchRequest[] = [];
  cancels = 0;
  cancelFailure = false;
  writeFailure = false;
  write(request: IWatchRequest) {
    if (this.writeFailure) throw new Error('Injected watch write failure');
    this.requests.push(request);
    return true;
  }
  cancel() {
    this.cancels++;
    this.emit('status', {});
    if (this.cancelFailure) throw new Error('Injected watch cancellation failure');
  }
  frame(fields: Record<string, unknown> = {}) {
    this.emit('data', { header, events: [], compact_revision: '0', ...fields });
  }
}

async function eventually(check: () => boolean) {
  const expires = performance.now() + 3000;
  while (!check()) {
    assert.ok(performance.now() < expires, 'The SDK watch boundary did not settle');
    await delay(5);
  }
}

function fixture(
  context: TestContext,
  reconnect = () => {},
  closed: (failure?: unknown) => void = () => {},
) {
  const streams: WatchStream[] = [],
    parent = new AbortController();
  context.mock.method(WatchClient.prototype, 'watch', async () => {
    const stream = new WatchStream();
    streams.push(stream);
    return stream as unknown as IDuplexStream<IWatchRequest, IWatchResponse>;
  });
  const watch = new EtcdWatch(
    { prefix: '/scope/', native: { hosts: ['http://127.0.0.1:1'] } },
    '/scope/item',
    parent.signal,
    undefined,
    reconnect,
    closed,
  );
  let cleanupFailure = false;
  context.after(async () => {
    try {
      await watch.close();
    } catch (cause) {
      if (!cleanupFailure) throw cause;
    }
  });
  return {
    watch,
    streams,
    parent,
    allowCleanupFailure() {
      cleanupFailure = true;
    },
    async open(revision = '10') {
      const opening = watch.open();
      await eventually(() => !!streams[0]?.requests.length);
      streams[0]!.frame({ created: true, header: { ...header, revision } });
      await opening;
      return streams[0]!;
    },
  };
}

function event(
  revision = '11',
  value: unknown = Buffer.from([0, 255]),
  key: unknown = Buffer.from('/scope/item:a'),
) {
  return { type: 'Put', kv: { key, value, mod_revision: revision } };
}

test('watch preserves exact cursors across resumed acknowledgments and fragmented replay', async (context) => {
  let recoveries = 0;
  const f = fixture(context, () => {
    recoveries++;
    throw new Error('Diagnostic failure');
  });
  const first = await f.open('9007199254740993');
  assert.equal(f.watch[Symbol.asyncIterator](), f.watch);
  first.emit('end');
  await eventually(() => !!f.streams[1]?.requests.length);
  const second = f.streams[1]!;
  assert.equal(second.requests[0]?.create_request?.start_revision, '9007199254740994');
  second.frame({ created: true, header: { ...header, revision: '9007199254741000' } });
  second.frame({
    fragment: true,
    header: { ...header, revision: '9007199254740994' },
    events: [event('9007199254740994')],
  });
  assert.equal((await f.watch.next()).value?.revision, 9007199254740994n);
  second.emit('end');
  await eventually(() => !!f.streams[2]?.requests.length);
  const third = f.streams[2]!;
  assert.equal(third.requests[0]?.create_request?.start_revision, '9007199254740994');
  third.frame({ created: true, header: { ...header, revision: '9007199254741000' } });
  third.frame({
    header: { ...header, revision: '9007199254740994' },
    events: [event('9007199254740994')],
  });
  assert.equal((await f.watch.next()).value?.revision, 9007199254740994n);
  third.emit('end');
  await eventually(() => !!f.streams[3]?.requests.length);
  assert.equal(f.streams[3]?.requests[0]?.create_request?.start_revision, '9007199254740995');
  assert.equal(recoveries, 3);
  // Events arriving from a replaced stream cannot alter the active cursor or queue.
  first.frame({ events: [event()] });
});

test('watch rejects a second pending read and resolves the first when the iterator returns', async (context) => {
  const f = fixture(context),
    stream = await f.open();
  const pending = f.watch.next();
  await assert.rejects(f.watch.next(), { code: 'EK_CONFIG_INVALID' });
  assert.deepEqual(await f.watch.return(), { done: true, value: undefined });
  assert.deepEqual(await pending, { done: true, value: undefined });
  assert.deepEqual(await f.watch.next(), { done: true, value: undefined });
  await assert.rejects(f.watch.open(), { code: 'EK_RESOURCE_CLOSED' });
  await f.watch.close();
  assert.equal(stream.cancels, 1);
});

test('watch hands bytes to a waiting reader and retains a leading UTF-8 BOM in keys', async (context) => {
  const f = fixture(context),
    stream = await f.open();
  const pending = f.watch.next(),
    value = Buffer.from([0, 255]);
  stream.frame({ events: [event('11', value, Buffer.from('/scope/item\uFEFF'))] });
  value[0] = 9;
  const result = await pending;
  assert.deepEqual(result.value?.value, Uint8Array.from([0, 255]));
  assert.equal(result.value?.key, 'item\uFEFF');
  stream.frame({
    events: [{ type: 'Delete', kv: { key: Buffer.from('/scope/item:a'), mod_revision: '12' } }],
  });
  assert.equal((await f.watch.next()).value?.type, 'delete');
});

test('watch rejects malformed responses and events before yielding portable data', async (context) => {
  const malformed: unknown[] = [
    null,
    { header, events: 'invalid' },
    { header, compact_revision: '0', events: [{}] },
    { header, compact_revision: '0', events: [{ ...event(), type: 'Unknown' }] },
    { header, compact_revision: '0', events: [event('11', Buffer.alloc(0), 'invalid')] },
    { header, compact_revision: '0', events: [event('11', Buffer.alloc(0), Buffer.from([0xff]))] },
    {
      header,
      compact_revision: '0',
      events: [event('11', Buffer.alloc(0), Buffer.from('/other/key'))],
    },
  ];
  for (const response of malformed) {
    await context.test('invalid stream frame is terminal', async (child) => {
      const f = fixture(child),
        stream = await f.open();
      stream.emit('data', response);
      await assert.rejects(f.watch.next(), KitError);
    });
  }
});

test('watch reports byte overflow and invalid values as an explicit history gap', async (context) => {
  for (const value of [undefined, 'invalid', Buffer.alloc(1_048_577)]) {
    await context.test('invalid byte value cannot silently disappear', async (child) => {
      const f = fixture(child),
        stream = await f.open();
      stream.frame({ events: [event('11', value === undefined ? null : value)] });
      await assert.rejects(
        f.watch.next(),
        (cause: unknown) => cause instanceof KitError && cause.details?.watchGap === true,
      );
    });
  }
  await context.test('aggregate byte capacity is independently bounded', async (child) => {
    const f = fixture(child),
      stream = await f.open();
    stream.frame({
      events: [event('11', Buffer.alloc(1_048_576)), event('11', Buffer.alloc(1_048_576))],
    });
    await assert.rejects(
      f.watch.next(),
      (cause: unknown) => cause instanceof KitError && cause.details?.limitExceeded === true,
    );
  });
});

test('watch preserves a compaction gap when stream cancellation also fails', async (context) => {
  const f = fixture(context, undefined, () => {
    throw new Error('Owner diagnostic failure');
  });
  f.allowCleanupFailure();
  const opening = f.watch.open();
  await eventually(() => !!f.streams[0]?.requests.length);
  const stream = f.streams[0]!;
  stream.cancelFailure = true;
  stream.frame({ canceled: true, compact_revision: '9007199254740997' });
  await assert.rejects(
    opening,
    (cause: unknown) =>
      cause instanceof KitError &&
      cause.code === 'EK_KV_CONFLICT' &&
      cause.details?.compactedRevision === '9007199254740997' &&
      cause.cause instanceof AggregateError,
  );
  await assert.rejects(f.watch.close(), { code: 'EK_BACKEND_UNAVAILABLE' });
  assert.equal(stream.cancels, 1);
});

test('watch treats authorization rejection as terminal and observes owner callback faults', async (context) => {
  const f = fixture(context, undefined, () => {
    throw new Error('Owner diagnostic failure');
  });
  const stream = await f.open();
  stream.emit('error', new EtcdPermissionDeniedError('Permission denied'));
  await assert.rejects(f.watch.next(), { code: 'EK_BACKEND_UNAVAILABLE' });
  await f.watch.close();
  assert.equal(f.streams.length, 1);
});

test('watch owner abort closes the active stream and remains terminal on reopen', async (context) => {
  const f = fixture(context),
    stream = await f.open();
  f.parent.abort(new Error('Owner shutdown'));
  await assert.rejects(f.watch.next(), { code: 'EK_ABORTED' });
  await f.watch.close();
  assert.equal(stream.cancels, 1);
  await assert.rejects(f.watch.open(), { code: 'EK_ABORTED' });
});

test('watch closes late connection completion and observes a failed late stream cancellation', async (context) => {
  for (const broken of [false, true]) {
    await context.test('setup abort retains ownership of the eventual stream', async (child) => {
      const f = fixture(child),
        gate = deferred(),
        stream = new WatchStream();
      stream.cancelFailure = broken;
      if (broken) f.allowCleanupFailure();
      child.mock.method(WatchClient.prototype, 'watch', async () => {
        await gate.promise;
        return stream as unknown as IDuplexStream<IWatchRequest, IWatchResponse>;
      });
      const opening = f.watch.open();
      const rejected = assert.rejects(opening, { code: 'EK_ABORTED' });
      f.parent.abort();
      gate.resolve();
      await rejected;
      if (broken) await assert.rejects(f.watch.close(), { code: 'EK_BACKEND_UNAVAILABLE' });
      else await f.watch.close();
      assert.equal(stream.cancels, 1);
    });
  }
});

test('watch terminates if disconnect cancellation fails and observes native close failures', async (context) => {
  const f = fixture(context),
    stream = await f.open();
  f.allowCleanupFailure();
  context.mock.method(Etcd3.prototype, 'close', () => {
    throw new Error('Native close failed');
  });
  stream.cancelFailure = true;
  stream.emit('end');
  await assert.rejects(f.watch.next(), { code: 'EK_BACKEND_UNAVAILABLE' });
  await assert.rejects(f.watch.close(), { code: 'EK_BACKEND_UNAVAILABLE' });
});

test('watch progress requests detect silent streams and bound the recovery interval', async (context) => {
  const timers: { callback: () => void; ms: number; handle: ReturnType<typeof setTimeout> }[] = [];
  const original = globalThis.setTimeout;
  context.mock.method(globalThis, 'setTimeout', (callback: () => void, ms?: number) => {
    const handle = original(callback, ms);
    timers.push({ callback, ms: ms ?? 0, handle });
    return handle;
  });
  const fire = (ms: number) => {
    const index = timers.findLastIndex((timer) => timer.ms === ms);
    assert.ok(index >= 0, 'The required owner timer was not scheduled');
    const timer = timers.splice(index, 1)[0]!;
    clearTimeout(timer.handle);
    timer.callback();
  };
  const f = fixture(context),
    stream = await f.open();
  const before = stream.requests.length;
  fire(5000);
  assert.equal(stream.requests.length, before + 1);
  const now = performance.now();
  context.mock.method(performance, 'now', () => now + 20_000);
  fire(5000);
  assert.equal(stream.cancels, 1);
  fire(15_000);
  await assert.rejects(f.watch.next(), { code: 'EK_TIMEOUT' });
  await f.watch.close();
});

test('watch recovers stream-open and progress-write failures through the same bounded path', async (context) => {
  await context.test('permanent stream-open failure ends setup', async (child) => {
    const f = fixture(child);
    child.mock.method(WatchClient.prototype, 'watch', async () => {
      throw new EtcdPermissionDeniedError('Denied');
    });
    await assert.rejects(f.watch.open(), { code: 'EK_BACKEND_UNAVAILABLE' });
  });
  await context.test('progress-write failure schedules recovery', async (child) => {
    const callbacks: (() => void)[] = [],
      original = globalThis.setTimeout;
    child.mock.method(globalThis, 'setTimeout', (callback: () => void, ms?: number) => {
      const handle = original(callback, ms);
      if (ms === 5000)
        callbacks.push(() => {
          clearTimeout(handle);
          callback();
        });
      return handle;
    });
    const f = fixture(child),
      stream = await f.open();
    stream.writeFailure = true;
    callbacks.at(-1)!();
    assert.equal(stream.cancels, 1);
    await f.watch.close();
  });
});

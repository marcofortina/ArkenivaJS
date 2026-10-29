// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as immediate } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import { SubscriptionStream } from '../../dist/subscription-stream.js';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function source(
  next: () => Promise<IteratorResult<unknown>>,
  close: () => Promise<IteratorResult<unknown>>,
): AsyncIterableIterator<unknown> {
  return {
    next,
    return: close,
    [Symbol.asyncIterator]() {
      return this;
    },
  };
}

const denied = (error: unknown) =>
  error instanceof KitError && error.code === 'EK_GQL_SUBSCRIPTION';

test('Late source acquisition is closed exactly once before cancelled ownership settles', async () => {
  const acquired = deferred<AsyncIterable<unknown>>();
  let closes = 0,
    completed = false;
  const owner = new AbortController();
  const stream = new SubscriptionStream(() => acquired.promise, owner.signal);
  const opening = stream.open();
  const rejected = assert.rejects(opening, denied);
  await immediate();
  void stream.completion.then(() => {
    completed = true;
  });
  owner.abort();
  await immediate();
  assert.equal(completed, false);
  acquired.resolve(
    source(
      async () => ({ done: true, value: undefined }),
      async () => {
        closes++;
        return { done: true, value: undefined };
      },
    ),
  );
  await rejected;
  await stream.return();
  await stream.return();
  assert.equal(closes, 1);
  assert.equal(completed, true);
});

test('Logical iterator close retains a noncooperative pending read and discards its late event', async () => {
  const read = deferred<IteratorResult<unknown>>();
  let closes = 0,
    completed = false;
  const stream = new SubscriptionStream(
    () =>
      source(
        () => read.promise,
        async () => {
          closes++;
          return { done: true, value: undefined };
        },
      ),
    new AbortController().signal,
  );
  await stream.open();
  const pending = stream.next();
  await immediate();
  const returned = stream.return();
  void stream.completion.then(() => {
    completed = true;
  });
  await immediate();
  assert.equal(closes, 1);
  assert.equal(completed, false);
  assert.equal(stream.controller.signal.aborted, true);
  read.resolve({ done: false, value: 'late-private-event' });
  assert.deepEqual(await pending, { done: true, value: undefined });
  await returned;
  assert.equal(completed, true);
});

test('Natural exhaustion and repeated native cleanup retire a source once without sharing it with another stream', async () => {
  let index = 0,
    closes = 0;
  const stream = new SubscriptionStream(
    () =>
      source(
        async () =>
          index++ === 0
            ? { done: false, value: 'event' }
            : { done: true, value: 'discarded-return-value' },
        async () => {
          closes++;
          return { done: true, value: undefined };
        },
      ),
    new AbortController().signal,
  );
  const independent = new SubscriptionStream(async function* () {
    yield 'independent';
  }, new AbortController().signal);
  assert.equal(stream[Symbol.asyncIterator](), stream);
  assert.deepEqual(await stream.next(), { done: false, value: 'event' });
  assert.deepEqual(await stream.next(), { done: true, value: undefined });
  await stream.return();
  await stream.return();
  assert.equal(closes, 1);
  assert.equal(stream.hasFailure(), false);
  assert.deepEqual(await independent.next(), { done: false, value: 'independent' });
  await independent.return();
});

test('Acquisition, malformed sources, read and cleanup failures remain safe and physically observed', async () => {
  for (const mode of ['acquire', 'malformed', 'read', 'cleanup'] as const) {
    let closes = 0;
    const stream = new SubscriptionStream(() => {
      if (mode === 'acquire') throw new Error('Private provider acquisition detail');
      if (mode === 'malformed') return {} as AsyncIterable<unknown>;
      return source(
        async () => {
          throw new Error('Private provider read detail');
        },
        async () => {
          closes++;
          if (mode === 'cleanup') throw new Error('Private provider cleanup detail');
          return { done: true, value: undefined };
        },
      );
    }, new AbortController().signal);
    if (mode === 'acquire' || mode === 'malformed') await assert.rejects(stream.open(), denied);
    else if (mode === 'read') await assert.rejects(stream.next(), denied);
    else await stream.open();
    await stream.return();
    assert.equal(stream.hasFailure(), true);
    assert.equal(stream.retirementFailed(), mode === 'malformed' || mode === 'cleanup');
    assert.equal(closes, mode === 'read' || mode === 'cleanup' ? 1 : 0);
  }
});

test('Pre-abort never acquires a source and overlapping next calls cannot create an implicit read queue', async () => {
  let acquisitions = 0;
  const before = new SubscriptionStream(async function* () {
    acquisitions++;
    yield true;
  }, AbortSignal.abort());
  await assert.rejects(before.open(), denied);
  assert.deepEqual(await before.next(), { done: true, value: undefined });
  await before.return();
  assert.equal(acquisitions, 0);
  const read = deferred<IteratorResult<unknown>>();
  const live = new SubscriptionStream(
    () =>
      source(
        () => read.promise,
        async () => ({ done: true, value: undefined }),
      ),
    new AbortController().signal,
  );
  const first = live.next();
  await immediate();
  await assert.rejects(
    live.next(),
    (error: unknown) => error instanceof KitError && error.code === 'EK_GQL_BACKPRESSURE',
  );
  read.resolve({ done: false, value: 'one-read' });
  assert.deepEqual(await first, { done: false, value: 'one-read' });
  await live.return();
});

test('Abort between open and source invocation never allocates or reports a provider failure', async () => {
  let acquisitions = 0;
  const owner = new AbortController();
  const stream = new SubscriptionStream(async function* () {
    acquisitions++;
    yield true;
  }, owner.signal);
  const opening = stream.open();
  const rejected = assert.rejects(opening, denied);
  owner.abort();
  await rejected;
  await stream.return();
  assert.equal(acquisitions, 0);
  assert.equal(stream.hasFailure(), false);
});

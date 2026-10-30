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

test('Malformed provider completion flags cannot fabricate a valid subscription event or exhaustion', async () => {
  for (const done of [null, 0, 1, '', 'false', {}, []]) {
    let closes = 0;
    const stream = new SubscriptionStream(
      () =>
        source(
          async () => ({ done, value: 'untrusted-event' }) as IteratorResult<unknown>,
          async () => {
            closes++;
            return { done: true, value: undefined };
          },
        ),
      new AbortController().signal,
    );
    try {
      await assert.rejects(stream.next(), denied);
      await stream.return();
      assert.equal(stream.hasFailure(), true);
      assert.equal(stream.retirementFailed(), false);
      assert.equal(closes, 1);
    } finally {
      await stream.return();
    }
  }
});

test('A real async generator yielding during return cannot be reported as successfully retired', async () => {
  let released = false;
  const provider = (async function* () {
    try {
      yield 'first-event';
    } finally {
      try {
        yield 'cleanup-not-finished';
      } finally {
        released = true;
      }
    }
  })();
  const stream = new SubscriptionStream(() => provider, new AbortController().signal);
  try {
    assert.deepEqual(await stream.next(), { done: false, value: 'first-event' });
    await stream.return();
    assert.equal(released, false);
    assert.equal(stream.hasFailure(), true);
    assert.equal(stream.retirementFailed(), true);
  } finally {
    await provider.return(undefined);
  }
  assert.equal(released, true);
});

test('Malformed source cleanup receipts fail retirement once without retrying provider work', async () => {
  for (const result of [
    undefined,
    null,
    1,
    {},
    { done: false, value: 'pending' },
    { done: 'true' },
  ]) {
    let closes = 0;
    const stream = new SubscriptionStream(
      () =>
        source(
          async () => ({ done: false, value: 'event' }),
          async () => {
            closes++;
            return result as IteratorResult<unknown>;
          },
        ),
      new AbortController().signal,
    );
    await stream.open();
    await stream.return();
    await stream.return();
    assert.equal(stream.hasFailure(), true);
    assert.equal(stream.retirementFailed(), true);
    assert.equal(closes, 1);
  }
});

test('A standard yield result without an optional done field remains compatible', async () => {
  const stream = new SubscriptionStream(
    () =>
      source(
        async () => ({ value: 'valid-event' }),
        async () => ({ done: true, value: undefined }),
      ),
    new AbortController().signal,
  );
  try {
    assert.deepEqual(await stream.next(), { value: 'valid-event', done: false });
  } finally {
    await stream.return();
  }
  assert.equal(stream.hasFailure(), false);
  assert.equal(stream.retirementFailed(), false);
});

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

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { MongoServerError, BSON } from 'mongodb';
import type { CommandStartedEvent, CommandSucceededEvent, CommandFailedEvent } from 'mongodb';
import { KitError } from '@arkenivajs/core';
import { MongoTransport, mongoNativeBudget } from '../../dist/transport.js';
import type { MongoCallScope } from '../../dist/transport.js';

function scope(input: Partial<MongoCallScope> = {}): MongoCallScope {
  return {
    signal: new AbortController().signal,
    timeoutMs: 15000,
    began: performance.now(),
    write: true,
    submitted: false,
    acknowledged: false,
    cleanupFailures: [],
    ...input,
  };
}
function fixture(context: TestContext, diagnostic: () => void = () => {}) {
  const transport = new MongoTransport(
    {
      url: 'mongodb://127.0.0.1:1/unit',
      database: 'unit',
      prefix: 'scope_',
      native: { retryReads: false, retryWrites: false, maxAdaptiveRetries: 0 },
    },
    diagnostic,
  );
  context.after(() => transport.client.close());
  return transport;
}
// Synthetic public monitoring events isolate error handling; live relay tests verify the corresponding real wire outcomes.
const started = (
  requestId: number,
  commandName: string,
  command: Record<string, unknown> = {},
): CommandStartedEvent => ({ requestId, commandName, command }) as unknown as CommandStartedEvent;
const succeeded = (requestId: number, reply: unknown = { ok: 1 }): CommandSucceededEvent =>
  ({ requestId, reply }) as unknown as CommandSucceededEvent;
const failed = (requestId: number, failure: unknown): CommandFailedEvent =>
  ({ requestId, failure }) as unknown as CommandFailedEvent;

test('MongoDB native budgets use monotonic remaining milliseconds, preserve deadlines and avoid timer overflow', () => {
  assert.ok(mongoNativeBudget(scope()) <= 15000);
  assert.equal(mongoNativeBudget(scope({ timeoutMs: Number.MAX_SAFE_INTEGER })), 0);
  assert.throws(() => mongoNativeBudget(scope({ began: performance.now() - 100, timeoutMs: 1 })), {
    code: 'EK_TIMEOUT',
  });
  const controller = new AbortController();
  controller.abort(new Error('Caller cancelled'));
  assert.throws(() => mongoNativeBudget(scope({ signal: controller.signal })), {
    code: 'EK_ABORTED',
  });
  const timed = new AbortController();
  timed.abort(new KitError({ code: 'EK_TIMEOUT', message: 'Deadline expired' }));
  assert.throws(() => mongoNativeBudget(scope({ signal: timed.signal })), { code: 'EK_TIMEOUT' });
});

test('MongoDB tracks commit/abort acknowledgments only for the actual owned native session', async (context) => {
  const t = fixture(context),
    owned = t.client.startSession(),
    s = scope({ session: owned });
  try {
    t.client.emit('commandStarted', started(1, 'insert'));
    assert.equal(s.submitted, false);
    await t.run(s, async () => {
      t.client.emit(
        'commandStarted',
        started(2, 'insert', { lsid: { id: new BSON.UUID() }, autocommit: false }),
      );
      assert.equal(s.transactionUsed, undefined);
      t.client.emit('commandStarted', started(3, 'insert', { lsid: owned.id, autocommit: false }));
      assert.equal(s.transactionUsed, true);
      t.client.emit('commandStarted', started(4, 'commitTransaction', { lsid: owned.id }));
      t.client.emit('commandSucceeded', succeeded(4));
      assert.equal(s.commitSubmitted, true);
      assert.equal(s.commitAcknowledged, true);
      t.client.emit('commandStarted', started(5, 'abortTransaction', { lsid: owned.id }));
      t.client.emit(
        'commandFailed',
        failed(5, new MongoServerError({ code: 251, message: 'Transaction already gone' })),
      );
      assert.equal(s.abortAcknowledged, true);
      t.client.emit('commandStarted', started(6, 'abortTransaction', { lsid: owned.id }));
      t.client.emit('commandSucceeded', succeeded(6));
      t.client.emit('commandFailed', failed(999, new Error('Untracked error')));
      t.client.emit('commandSucceeded', succeeded(999));
    });
  } finally {
    await owned.endSession();
  }
});

test('MongoDB distinguishes command success envelopes from missing cleanup write concern and bounds retained failures', async (context) => {
  let diagnostic = 0;
  const t = fixture(context, () => {
      diagnostic++;
    }),
    s = scope();
  await t.run(s, async () => {
    t.client.emit('commandStarted', started(1, 'killCursors'));
    t.client.emit('commandFailed', failed(1, new Error('Not an owned cursor cleanup')));
    assert.equal(s.cleanupFailures.length, 0);
    s.closingCursor = true;
    t.client.emit('commandStarted', started(2, 'killCursors'));
    t.client.emit('commandFailed', failed(2, new Error('Owned cursor cleanup failed')));
    assert.equal(s.cleanupFailures.length, 1);
    for (let index = 3; index < 24; index++) {
      t.client.emit('commandStarted', started(index, 'abortTransaction'));
      t.client.emit(
        'commandSucceeded',
        succeeded(index, { ok: 1, writeConcernError: { code: 64 } }),
      );
    }
    assert.equal(s.cleanupFailures.length, 16);
    assert.ok(diagnostic > 0);
    t.client.emit('commandStarted', started(24, 'commitTransaction'));
    t.client.emit('commandFailed', failed(24, new Error('Commit acknowledgment lost')));
    assert.equal(s.commitAcknowledged, undefined);
  });
});

test('MongoDB monitoring saturation and broken diagnostics cannot throw through native submission or results', async (context) => {
  let faults = 0;
  const t = fixture(context, () => {
      faults++;
      throw new Error('Broken diagnostic');
    }),
    s = scope();
  const answer = await t.run(s, async () => {
    t.client.emit('error', new Error('Observed native error'));
    const malformed = Object.defineProperty({ requestId: 1, command: {} }, 'commandName', {
      get() {
        throw new Error('Malformed public event');
      },
    }) as unknown as CommandStartedEvent;
    t.client.emit('commandStarted', malformed);
    for (let index = 1; index <= 257; index++)
      t.client.emit('commandStarted', started(index, 'commitTransaction'));
    for (let index = 1; index <= 256; index++) t.client.emit('commandSucceeded', succeeded(index));
    return 42;
  });
  assert.equal(answer, 42);
  assert.ok(faults >= 3);
});

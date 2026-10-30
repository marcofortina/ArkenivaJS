// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import type WebSocket from 'ws';
import type { Message } from 'graphql-ws';
import { SubscriptionEgress } from '../../dist/subscription-egress.js';

function wire(
  options: { maxResultBytes?: number; maxQueuedEvents?: number; timeoutMs?: number } = {},
  faults: { write?: boolean; acknowledge?: boolean } = {},
) {
  const callbacks: ((error?: Error) => void)[] = [],
    encoded: string[] = [],
    notices: Message[] = [],
    changes: number[] = [];
  let terminations = 0;
  const socket = Object.assign(new EventEmitter(), {
    bufferedAmount: 0,
    send(data: string, callback: (error?: Error) => void) {
      if (faults.write) throw new Error('Private native transport failure');
      encoded.push(data);
      callbacks.push(callback);
    },
    terminate() {
      terminations++;
    },
  });
  const egress: SubscriptionEgress = new SubscriptionEgress(
    socket as unknown as WebSocket,
    { maxResultBytes: 1024, maxQueuedEvents: 2, timeoutMs: 1000, ...options },
    (message) => {
      if (faults.acknowledge) throw new Error('Private admission observer failure');
      notices.push(message);
    },
    () => changes.push(egress.stats().pendingWrites),
  );
  return { socket, callbacks, encoded, notices, changes, egress, terminations: () => terminations };
}

test('Native writes retain bounded physical ownership until callbacks and notify admission exactly once', () => {
  const w = wire();
  let notified = 0;
  w.socket.send('{"type":"connection_ack"}', (error) => {
    assert.equal(error, undefined);
    notified++;
  });
  assert.equal(w.egress.stats().pendingWrites, 1);
  assert.equal(w.notices.length, 0);
  w.callbacks[0]!();
  w.callbacks[0]!();
  assert.equal(w.egress.stats().pendingWrites, 0);
  assert.equal(w.notices[0]?.type, 'connection_ack');
  assert.equal(notified, 1);
  assert.equal(w.terminations(), 0);
  assert.deepEqual(w.changes, [1, 0]);
});

test('Synchronous transport and admission failures retire physical writes without leaking causes or duplicate callbacks', () => {
  for (const fault of ['write', 'acknowledge'] as const) {
    const w = wire({}, { [fault]: true });
    const failures: Error[] = [];
    w.socket.send('{"type":"connection_ack"}', (error) => {
      assert.ok(error);
      failures.push(error);
      throw new Error('Private consumer callback failure');
    });
    if (fault === 'acknowledge') {
      w.callbacks[0]!();
      w.callbacks[0]!();
    }
    assert.equal(failures.length, 1);
    assert.doesNotMatch(failures[0]!.message, /Private|transport|observer|consumer/);
    assert.deepEqual(w.egress.stats(), { pendingWrites: 0, closed: true });
    assert.equal(w.notices.length, 0);
    assert.equal(w.terminations(), 1);
    w.socket.emit('close');
    assert.equal(failures.length, 1);
  }
});

test('Wire budgets include the next frame and the complete sanitized error array before writing', () => {
  for (const mode of ['buffer-plus-frame', 'error-array', 'envelope'] as const) {
    const w = wire({ maxQueuedEvents: 1, maxResultBytes: 100 });
    if (mode === 'buffer-plus-frame') w.socket.bufferedAmount = 2148;
    const message =
      mode === 'error-array'
        ? {
            type: 'error',
            id: 'one',
            payload: [{ message: 'private-one' }, { message: 'private-two' }],
          }
        : mode === 'envelope'
          ? { type: 'complete', id: 'x'.repeat(2200) }
          : { type: 'pong' };
    let failures = 0;
    w.socket.send(JSON.stringify(message), (error) => {
      assert.ok(error);
      failures++;
    });
    assert.equal(w.encoded.length, 0);
    assert.equal(w.notices.length, 0);
    assert.equal(w.egress.stats().pendingWrites, 0);
    assert.equal(w.terminations(), 1);
    assert.equal(failures, 1);
  }
});

test('A failed native callback closes admission and a later write cannot reopen the socket', () => {
  const w = wire();
  const failures: Error[] = [];
  const failed = (error?: Error) => {
    assert.ok(error);
    failures.push(error);
  };
  w.socket.send('{"type":"pong"}', failed);
  w.callbacks[0]!(new Error('Private driver endpoint'));
  w.callbacks[0]!();
  w.socket.send('{"type":"pong"}', failed);
  assert.equal(w.encoded.length, 1);
  assert.equal(w.notices.length, 0);
  assert.equal(failures.length, 2);
  assert.ok(failures.every((error) => !/Private|endpoint/.test(error.message)));
  assert.deepEqual(w.egress.stats(), { pendingWrites: 0, closed: true });
});

test('Native start errors are sanitized while successful payloads preserve the standard wire dialect', () => {
  const w = wire();
  const errors: (Error | undefined)[] = [];
  w.socket.send(
    JSON.stringify({
      type: 'error',
      id: 'one',
      payload: [
        { message: 'Private provider URI', extensions: { code: 'private', secret: 'excluded' } },
      ],
    }),
    (error) => errors.push(error),
  );
  assert.doesNotMatch(w.encoded[0]!, /Private|provider URI|secret|excluded|private/);
  assert.deepEqual(JSON.parse(w.encoded[0]!), {
    type: 'error',
    id: 'one',
    payload: [{ message: 'GraphQL operation failed', extensions: { code: 'EK_GQL_SUBSCRIPTION' } }],
  });
  w.callbacks[0]!();
  const next = { type: 'next', id: 'one', payload: { data: { notice: 'tenant-isolated' } } };
  w.socket.send(JSON.stringify(next), (error) => errors.push(error));
  assert.deepEqual(JSON.parse(w.encoded[1]!), next);
  w.callbacks[1]!();
  assert.deepEqual(errors, [undefined, undefined]);
});

test('Queue pressure, payload bytes, buffered socket bytes and unsupported messages fail before another write', () => {
  for (const mode of ['queue', 'payload', 'buffer', 'protocol'] as const) {
    const w = wire({ maxQueuedEvents: 1, maxResultBytes: 100 });
    let failed = 0;
    if (mode === 'queue') w.socket.send('{"type":"connection_ack"}', () => {});
    if (mode === 'buffer') w.socket.bufferedAmount = 100000;
    const data =
      mode === 'payload'
        ? JSON.stringify({
            type: 'next',
            id: 'one',
            payload: { data: { notice: 'x'.repeat(101) } },
          })
        : mode === 'protocol'
          ? '{"type":"connection_init"}'
          : '{"type":"pong"}';
    w.socket.send(data, (error) => {
      assert.ok(error);
      failed++;
    });
    assert.equal(w.encoded.length, mode === 'queue' ? 1 : 0);
    assert.equal(w.terminations(), 1);
    assert.equal(w.egress.stats().closed, true);
    assert.equal(failed, 1);
    w.socket.emit('close');
    assert.equal(w.egress.stats().pendingWrites, 0);
  }
});

test('A missing native callback times out, terminates the socket and cannot later acknowledge admission', async () => {
  const w = wire({ timeoutMs: 15 });
  let failures = 0;
  w.socket.send('{"type":"connection_ack"}', (error) => {
    assert.ok(error);
    failures++;
  });
  await delay(40);
  assert.equal(w.terminations(), 1);
  assert.equal(w.egress.stats().pendingWrites, 0);
  assert.equal(failures, 1);
  w.callbacks[0]!();
  assert.equal(failures, 1);
  assert.equal(w.notices.length, 0);
});

test('Close and late failed callbacks settle each owned write once without exposing driver errors', () => {
  const w = wire();
  const errors: Error[] = [];
  for (let index = 0; index < 2; index++)
    w.socket.send('{"type":"pong"}', (error) => {
      assert.ok(error);
      errors.push(error);
    });
  w.socket.emit('close');
  for (const callback of w.callbacks) callback(new Error('Private driver detail'));
  assert.equal(errors.length, 2);
  assert.equal(w.egress.stats().pendingWrites, 0);
  assert.equal(w.notices.length, 0);
  for (const error of errors) assert.doesNotMatch(error.message, /Private|driver detail/);
});

test('Long native write deadlines preserve queued ownership without overflowing the Node timer delay', async () => {
  const w = wire({ timeoutMs: 2147483648 });
  let complete = 0;
  w.socket.send('{"type":"connection_ack"}', (error) => {
    assert.equal(error, undefined);
    complete++;
  });
  await delay(20);
  assert.equal(w.terminations(), 0);
  assert.equal(w.egress.stats().pendingWrites, 1);
  w.callbacks[0]!();
  assert.equal(complete, 1);
  assert.equal(w.egress.stats().pendingWrites, 0);
});

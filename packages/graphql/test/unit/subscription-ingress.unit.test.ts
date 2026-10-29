// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type WebSocket from 'ws';
import { MessageType } from 'graphql-ws';
import { KitError } from '@arkenivajs/core';
import { capture } from '../../dist/policy.js';
import { installSubscriptionIngress, subscriptionFrame } from '../../dist/subscription-ingress.js';

const limits = capture({
  schema: 'type Query { ping: String }',
  resolvers: {},
  security: { authorizeField: () => false },
}).security.limits;
const encoded = (input: unknown) => Buffer.from(JSON.stringify(input));
const rejected = (work: () => unknown, code: string) =>
  assert.throws(work, (error: unknown) => error instanceof KitError && error.code === code);

test('Subscription ingress uses the standard client dialect with finite text, control, credential and identifier envelopes', () => {
  for (const frame of [
    { type: 'connection_init', payload: { authorization: 'Bearer synthetic-session' } },
    {
      id: 'operation',
      type: 'subscribe',
      payload: { query: 'subscription { notice }', variables: { id: 1 } },
    },
    { id: 'operation', type: 'complete' },
    { type: 'ping', payload: { nonce: 1 } },
    { type: 'pong' },
  ])
    assert.deepEqual(subscriptionFrame(encoded(frame), false, limits), frame);
  for (const raw of [Buffer.from('{'), Buffer.from([0xc0, 0xaf]), '{}', null])
    rejected(() => subscriptionFrame(raw, false, limits), 'EK_GQL_SUBSCRIPTION');
  rejected(() => subscriptionFrame(encoded({ type: 'ping' }), true, limits), 'EK_GQL_SUBSCRIPTION');
  rejected(() => subscriptionFrame(Buffer.alloc(800000), false, limits), 'EK_GQL_INPUT_LIMIT');
  rejected(
    () =>
      subscriptionFrame(
        encoded({ type: 'pong', payload: { value: 'x'.repeat(1024) } }),
        false,
        limits,
      ),
    'EK_GQL_INPUT_LIMIT',
  );
  for (const payload of [
    undefined,
    {},
    { authorization: '' },
    { authorization: 'bad\nheader' },
    { authorization: 'x'.repeat(8193) },
    { authorization: 'valid', tenant: 'tenant-b' },
  ])
    rejected(
      () => subscriptionFrame(encoded({ type: 'connection_init', payload }), false, limits),
      'EK_GQL_AUTH',
    );
  rejected(
    () =>
      subscriptionFrame(
        encoded({
          id: 'operation',
          type: 'subscribe',
          payload: { query: '{ ping }', extensions: {} },
        }),
        false,
        limits,
      ),
    'EK_GQL_VALIDATION',
  );
});

test('Failed synchronous admission and physically closed sockets never forward a frame into the native iterator', () => {
  for (const mode of ['deny', 'asynchronous', 'closed'] as const) {
    const wire = new EventEmitter();
    const closures: { code: number; reason: string }[] = [];
    const socket = Object.assign(wire, {
      close(code: number, reason: string) {
        closures.push({ code, reason });
      },
    }) as unknown as WebSocket;
    let delivered = 0,
      admitted = 0;
    wire.on('message', () => {
      delivered++;
    });
    const admit = () => {
      admitted++;
      if (mode === 'deny')
        throw new KitError({
          code: 'EK_GQL_BACKPRESSURE',
          message: 'Admission capacity is exhausted',
        });
      return mode === 'asynchronous'
        ? Promise.reject(new Error('Private asynchronous admission failure'))
        : undefined;
    };
    installSubscriptionIngress(
      socket,
      limits,
      admit as (frame: { type: MessageType }) => undefined,
    );
    if (mode === 'closed') wire.emit('close');
    wire.emit('message', encoded({ type: 'ping' }), false);
    wire.emit('message', encoded({ type: 'ping' }), false);
    assert.equal(delivered, 0);
    assert.equal(admitted, mode === 'closed' ? 0 : 1);
    assert.deepEqual(
      closures,
      mode === 'closed'
        ? []
        : [{ code: 4400, reason: mode === 'deny' ? 'EK_GQL_BACKPRESSURE' : 'EK_GQL_SUBSCRIPTION' }],
    );
  }
});

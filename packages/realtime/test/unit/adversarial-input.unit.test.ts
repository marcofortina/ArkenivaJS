// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { realtimePlugin } from '../../dist/index.js';
import { policy } from '../fixture.js';

test('Hostile catalogs and provider accessors fail configuration without evaluating executable input', () => {
  let evaluated = 0;
  const base = {
    routes: [],
    websocketHandlers: {},
    sseSources: {},
    policies: { standard: policy },
    policy: { maxConcurrent: 1, timeoutMs: 1000 },
  };
  const hostile = new Proxy(
    {},
    {
      ownKeys() {
        evaluated++;
        throw new Error('The proxy must not execute');
      },
    },
  );
  const sourceAccessor = {
    kind: 'durable',
    get subscribe() {
      evaluated++;
      throw new Error('The accessor must not execute');
    },
  };
  const sparse = new Array(1),
    extra = Object.assign([], { extra: true });
  for (const input of [
    { ...base, websocketHandlers: hostile },
    { ...base, sseSources: { events: sourceAccessor } },
    {
      ...base,
      identityAuthority: {
        get authenticate() {
          evaluated++;
          return async () => ({});
        },
      },
    },
    { ...base, routes: sparse },
    { ...base, routes: extra },
    { ...base, policies: { standard: { ...policy, maxMessageBytes: 1048577 } } },
    { ...base, sseSources: { events: { kind: 'unknown', subscribe() {} } } },
    { ...base, sseSources: { events: { kind: 'pubsub', usage: 'unknown', subscribe() {} } } },
    { ...base, pubsub: { provider: 'nats', connectionName: 'bad name' } },
    { ...base, allowedOrigins: ['file:///tmp'] },
    {
      ...base,
      routes: [
        { kind: 'websocket', path: '/socket', handlerKey: 'missing', policyKey: 'standard' },
      ],
    },
    {
      ...base,
      routes: [{ kind: 'sse', path: '/events', sourceKey: 'missing', policyKey: 'standard' }],
    },
    {
      ...base,
      routes: [{ kind: 'sse', path: '/events', sourceKey: 'missing', policyKey: 'missing' }],
    },
  ])
    assert.throws(() => realtimePlugin(input as never), { code: 'EK_CONFIG_INVALID' });
  assert.equal(evaluated, 0);
});

test('Byte ingress snapshots native slots and rejects shared buffers or accessor-backed options before publication', async () => {
  const { bytes, fields, text, method } = await import('../../dist/validation.js');
  let evaluated = 0;
  const input = new Uint8Array([1, 2, 255]);
  Object.defineProperty(input, Symbol.iterator, {
    value() {
      evaluated++;
      throw new Error('The iterator must not execute');
    },
  });
  const snapshot = bytes(input, 3);
  input[0] = 42;
  assert.deepEqual([...snapshot], [1, 2, 255]);
  assert.equal(evaluated, 0);
  for (const value of [[], {}, new Uint16Array(2), new Uint8Array(new SharedArrayBuffer(4))])
    assert.throws(() => bytes(value, 3));
  assert.throws(() => bytes(new Uint8Array(4), 3), { code: 'EK_REALTIME_BACKPRESSURE' });
  for (const value of [
    Object.create({ inherited: true }),
    { [Symbol('unknown')]: true },
    {
      get signal() {
        evaluated++;
        return undefined;
      },
    },
  ])
    assert.throws(() => fields(value, ['signal']), { code: 'EK_CONFIG_INVALID' });
  for (const value of ['\ud800', '\r', '\0', '\x7f'])
    assert.throws(() => text(value, 10), { code: 'EK_CONFIG_INVALID' });
  assert.throws(() => method(null, 'subscribe'));
  assert.throws(() => method({ subscribe: 1 }, 'subscribe'));
  assert.equal(evaluated, 0);
});

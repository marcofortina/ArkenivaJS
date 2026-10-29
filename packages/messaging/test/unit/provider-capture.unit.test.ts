// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { messagingPlugin } from '../../dist/index.js';
import type { NatsBusOptions } from '../../dist/index.js';
import { natsPolicy } from '../../dist/config.js';

test('Messaging captures the error strategy without evaluating callable metadata', () => {
  let effects = 0;
  const options: NatsBusOptions = { async onError() {} };
  for (const key of ['bind', 'name', 'length'])
    Object.defineProperty(options.onError, key, {
      get() {
        effects++;
        throw new Error('Callable metadata must not run');
      },
    });
  assert.doesNotThrow(() => messagingPlugin(options));
  assert.equal(effects, 0);
});

test('Messaging error policy preserves the original method receiver, arguments and rejection after late replacement', async () => {
  let calls = 0,
    redirected = 0;
  const failure = {
    kind: 'wire' as const,
    error: new KitError({ code: 'EK_CONFIG_INVALID', message: 'Owned malformed frame' }),
  };
  const operation = { signal: new AbortController().signal, timeoutMs: 1000 };
  const options: NatsBusOptions = {
    async onError(input, supplied) {
      assert.equal(this, options);
      assert.equal(input, failure);
      assert.equal(supplied, operation);
      calls++;
      throw new Error('The original strategy rejects');
    },
  };
  Object.defineProperty(options.onError, 'bind', {
    value: () => async () => {
      redirected++;
    },
  });
  const captured = natsPolicy(options);
  Object.defineProperty(options, 'onError', {
    value: async () => {
      redirected++;
    },
  });
  await assert.rejects(captured.onError(failure, operation), {
    message: 'The original strategy rejects',
  });
  assert.equal(calls, 1);
  assert.equal(redirected, 0);
});

test('Messaging rejects proxy and inherited accessor policy inputs without inspection effects', () => {
  let effects = 0;
  const fail = () => {
    effects++;
    throw new Error('Executable policy inspection must not run');
  };
  const handler: ProxyHandler<object> = {
    get: fail,
    ownKeys: fail,
    getOwnPropertyDescriptor: fail,
    getPrototypeOf: fail,
  };
  const options: NatsBusOptions = { async onError() {} };
  const inherited = Object.create(Object.defineProperty({}, 'onError', { get: fail }));
  const connection = Object.create(Object.defineProperty({}, 'connectionStringEnv', { get: fail }));
  connection.onError = options.onError;
  let deep: object = options;
  for (let index = 0; index < 33; index++) deep = Object.create(deep);
  for (const value of [
    new Proxy(options, handler),
    { onError: new Proxy(options.onError, handler) },
    inherited,
    connection,
    deep,
  ])
    assert.throws(() => natsPolicy(value as NatsBusOptions), { code: 'EK_CONFIG_INVALID' });
  assert.throws(() => messagingPlugin(new Proxy(options, handler) as NatsBusOptions), {
    code: 'EK_CONFIG_INVALID',
  });
  assert.equal(effects, 0);
});

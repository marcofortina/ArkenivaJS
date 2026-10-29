// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GraphQLError } from 'graphql';
import type { ExecutionResult } from 'graphql';
import { KitError } from '@arkenivajs/core';
import { sealSubscriptionResult, subscriptionError } from '../../dist/subscription-output.js';

const denied = (work: () => unknown, code: string) =>
  assert.throws(work, (error: unknown) => error instanceof KitError && error.code === code);

test('Subscription materialization invokes application JSON semantics once and fixes later native sends to the bounded snapshot', () => {
  let serializations = 0,
    getters = 0;
  const execution: ExecutionResult = {
    data: {
      scalar: {
        toJSON() {
          serializations++;
          return serializations === 1
            ? {
                get value() {
                  getters++;
                  return 'first';
                },
              }
            : 'x'.repeat(1000000);
        },
      },
    },
  };
  const expected = '{"data":{"scalar":{"value":"first"}}}';
  sealSubscriptionResult(execution, Buffer.byteLength(expected));
  assert.equal(JSON.stringify(execution), expected);
  assert.equal(
    JSON.stringify({ type: 'next', id: 'one', payload: execution }),
    '{"type":"next","id":"one","payload":' + expected + '}',
  );
  assert.equal(serializations, 1);
  assert.equal(getters, 1);
  assert.equal(Object.isFrozen(execution), true);
  assert.throws(() => {
    execution.data = { scalar: 'changed' };
  });
});

test('Subscription result byte limits include escapes, extensions and normalized errors before native allocation', () => {
  for (const value of ['x'.repeat(1000), '\0'.repeat(1000), '😀'.repeat(1000)])
    denied(() => sealSubscriptionResult({ data: { value } }, 80), 'EK_GQL_RESPONSE_LIMIT');
  denied(
    () =>
      sealSubscriptionResult({ data: { value: 1 }, extensions: { detail: 'x'.repeat(1000) } }, 80),
    'EK_GQL_RESPONSE_LIMIT',
  );
  const error = new GraphQLError('Private SQL, provider URL and subject must not be published', {
    path: ['notice', 0, 'secret'],
    extensions: { code: 'EK_GQL_FORBIDDEN', privateDetail: 'excluded' },
  });
  const execution: ExecutionResult = { data: null, errors: [error] };
  const safe = {
    data: null,
    errors: [
      {
        message: 'GraphQL access is forbidden',
        path: ['notice', 0, 'secret'],
        extensions: { code: 'EK_GQL_FORBIDDEN' },
      },
    ],
  };
  const bytes = Buffer.byteLength(JSON.stringify(safe));
  denied(
    () => sealSubscriptionResult({ data: null, errors: [error] }, bytes - 1),
    'EK_GQL_RESPONSE_LIMIT',
  );
  sealSubscriptionResult(execution, bytes);
  assert.deepEqual(JSON.parse(JSON.stringify(execution)), safe);
  assert.doesNotMatch(
    JSON.stringify(execution),
    /Private SQL|provider URL|subject|privateDetail|excluded/,
  );
});

test('Native error sanitation never evaluates accessors or proxies and never copies unknown messages or extension fields', () => {
  let invoked = 0;
  const error = Object.defineProperty({}, 'extensions', {
    get() {
      invoked++;
      throw new Error('Private error accessor');
    },
  });
  const proxy = new Proxy(
    {},
    {
      getOwnPropertyDescriptor() {
        invoked++;
        throw new Error('Private proxy detail');
      },
    },
  );
  for (const input of [
    error,
    proxy,
    { message: 'Private raw text', extensions: { code: 'private-code', detail: 'hidden' } },
  ]) {
    const safe = subscriptionError(input, 1024);
    assert.equal(safe.extensions.code, 'EK_GQL_SUBSCRIPTION');
    assert.doesNotMatch(JSON.stringify(safe), /Private|private-code|hidden|detail/);
  }
  assert.equal(invoked, 0);
  denied(() => subscriptionError({ path: Array(1025) }, 1024), 'EK_GQL_RESPONSE_LIMIT');
  denied(() => subscriptionError({ path: [false] }, 1024), 'EK_GQL_EXECUTION');
  denied(
    () =>
      sealSubscriptionResult(
        Object.defineProperty({}, 'data', {
          get() {
            invoked++;
            return {};
          },
        }),
        1024,
      ),
    'EK_GQL_EXECUTION',
  );
  assert.equal(invoked, 0);
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { performance } from 'node:perf_hooks';
import { encodeResult } from '../../dist/encoding.js';
import { base, fixture, send } from '../fixture.js';

test('GraphQL bounded encoding matches standard JSON and rejects the exact first excess byte', () => {
  fc.assert(
    fc.property(fc.jsonValue({ maxDepth: 5 }), (value) => {
      const expected = JSON.stringify(value),
        bytes = Buffer.byteLength(expected);
      assert.equal(encodeResult(value, bytes), expected);
      if (bytes > 1)
        assert.throws(() => encodeResult(value, bytes - 1), { code: 'EK_GQL_RESPONSE_LIMIT' });
    }),
    { seed: 6238, numRuns: 200 },
  );
});

test('GraphQL bounded encoding retains escaping, omitted keys, array nulls and repeated object semantics', () => {
  const shared = { value: '\ud800\\"\n🙂' };
  for (const value of [
    shared,
    { first: shared, second: shared },
    [undefined, NaN, Infinity, -Infinity],
    { missing: undefined, fn: () => true, symbol: Symbol('omitted'), present: null },
    Object.assign(Object.create(null), { safe: 'value' }),
  ]) {
    const expected = JSON.stringify(value),
      bytes = Buffer.byteLength(expected);
    assert.equal(encodeResult(value, bytes), expected);
    assert.throws(() => encodeResult(value, bytes - 1), { code: 'EK_GQL_RESPONSE_LIMIT' });
  }
});

test('GraphQL bounded encoding stops before reading later fields after an oversized scalar', () => {
  let read = 0;
  const value = {
    huge: 'x'.repeat(8 * 1024 * 1024),
    get later() {
      read++;
      return 'must-not-read';
    },
  };
  assert.throws(() => encodeResult(value, 1024), { code: 'EK_GQL_RESPONSE_LIMIT' });
  assert.equal(read, 0);
});

test('GraphQL malformed or non-JSON result values cannot expose serializer causes', () => {
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  for (const value of [undefined, 1n, cycle, new String('boxed'), new Proxy({}, {})])
    assert.throws(() => encodeResult(value, 1024), { code: 'EK_GQL_EXECUTION' });
  const date = new Date('2026-01-01T00:00:00Z');
  assert.equal(encodeResult({ date }, 1024), JSON.stringify({ date }));
});

test('GraphQL large responses fail as a complete safe transport error without partial data', async () => {
  const f = await fixture({
    ...base(),
    resolvers: { Query: { ping: () => 'private-large-value'.repeat(100000) } },
    security: { authorizeField: () => true, limits: { maxResultBytes: 256 } },
  });
  try {
    const result = await send(
      f.origin,
      { query: '{ ping }' },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(result.status, 500);
    assert.match(result.body, /EK_GQL_RESPONSE_LIMIT/);
    assert.equal(result.json().data, undefined);
    assert.ok(Buffer.byteLength(result.body) <= 256);
    assert.doesNotMatch(result.body + f.logs(), /private-large-value/);
  } finally {
    await f.close();
  }
});

test('GraphQL rechecks the total deadline after result encoding without claiming mutation rollback', async (context) => {
  let now = performance.now();
  const f = await fixture({
    schema: 'scalar Payload type Query { ping: String! } type Mutation { update: Payload! }',
    resolvers: {
      Query: { ping: () => 'pong' },
      Mutation: {
        update: () => ({
          toJSON() {
            now += 1001;
            return 'committed-before-encoding';
          },
        }),
      },
    },
    security: { authorizeField: () => true, limits: { maxOperationMs: 1000 } },
  });
  context.mock.method(performance, 'now', () => now);
  try {
    const result = await send(
      f.origin,
      { query: 'mutation { update }' },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(result.status, 504, result.body);
    assert.match(result.body, /EK_GQL_TIMEOUT/);
    assert.equal(result.json().data, undefined);
    assert.doesNotMatch(result.body, /committed-before-encoding|rollback|rolled.back/);
  } finally {
    context.mock.restoreAll();
    await f.close();
  }
});

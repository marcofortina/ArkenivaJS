// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tenantRoutingPlugin, type TenantRoutingPluginSettings } from '../../dist/index.js';
import { jsonSnapshot } from '../../dist/json.js';
import { OperationSchemas } from '../../dist/schemas.js';
import { RoutingOperation } from '../../dist/operation.js';
import { registry, settings } from '../http-fixture.js';

test('Plugin options reject invalid capability limits, executable catalogs and conflicting aliases', () => {
  let effects = 0;
  const source = settings(),
    proxy = new Proxy(
      {},
      {
        ownKeys() {
          effects++;
          return [];
        },
      },
    );
  const getter = Object.defineProperty({}, 'north', {
    enumerable: true,
    get() {
      effects++;
      return () => ({});
    },
  });
  for (const patch of [
    ...[0, -1, 1.5, NaN, Infinity, 5001, '1000', 1n].map((maxCapabilities) => ({
      maxCapabilities,
    })),
    { handlers: proxy },
    { handlers: getter },
    { handlers: { north: 'source code' } },
    { authorize: undefined },
    { registry: {} },
    { activation: 'hot' },
    { responseTransformers: {}, transformers: {} },
    { responseTransformers: null },
    { requestTransformers: null },
    { capabilitiesPath: '/graphql/ide' },
    { capabilitiesPath: '/api/:tenant/capabilities' },
    { capabilitiesPath: '/api/../capabilities' },
  ])
    assert.throws(
      () => tenantRoutingPlugin({ ...source, ...patch } as TenantRoutingPluginSettings),
      { code: 'EK_TROUTE_CONFIG' },
    );
  assert.equal(effects, 0);
  for (const maxCapabilities of [1, 5000])
    assert.equal(tenantRoutingPlugin({ ...source, maxCapabilities }).id, 'tenant-routing');
});

test('Exact JSON byte preflight matches native encoding for escaped Unicode keys, strings and numeric extremes', () => {
  for (const value of [
    null,
    true,
    false,
    0,
    -0,
    1e30,
    Number.MIN_VALUE,
    '€😀"\\\n\u0000',
    { '€\n"': [-1.5, true, null, '\t\b\r\f'], empty: {}, array: [] },
    ['one', { text: 'é' }, [1, 2, 3]],
  ]) {
    const text = JSON.stringify(value),
      bytes = Buffer.byteLength(text);
    assert.equal(JSON.stringify(jsonSnapshot(value, bytes)), text);
    if (bytes > 1) assert.throws(() => jsonSnapshot(value, bytes - 1));
  }
});

test('Oversized escaped strings are rejected before native encoding allocates their representation', (context) => {
  const native = JSON.stringify;
  let calls = 0;
  context.mock.method(JSON, 'stringify', ((...args: Parameters<typeof JSON.stringify>) => {
    calls++;
    return Reflect.apply(native, JSON, args);
  }) as typeof JSON.stringify);
  assert.throws(() => jsonSnapshot('\u0000'.repeat(4096), 4096));
  assert.equal(calls, 0);
});

test('Compiled local schema references survive native cache removal without contaminating another operation', () => {
  const [first, second] = registry().operations;
  assert.ok(first && second);
  const make = (type: string) => ({
    $id: 'https://schema.example.test/owned',
    type: 'object',
    properties: { id: { $ref: '#/$defs/id' } },
    required: ['id'],
    $defs: { id: { type } },
    additionalProperties: false,
  });
  const compiled = new OperationSchemas([
    { ...first, schemas: { response: make('string') } },
    { ...second, schemas: { response: make('integer') } },
  ]);
  assert.equal(compiled.accepts(first.id, 'response', { id: 'valid' }), true);
  assert.equal(compiled.accepts(first.id, 'response', { id: 1 }), false);
  assert.equal(compiled.accepts(second.id, 'response', { id: 1 }), true);
  assert.equal(compiled.accepts(second.id, 'response', { id: 'invalid' }), false);
  assert.equal(compiled.accepts('unknown', 'response', {}), false);
});

test('An already expired operation relinquishes a newly proposed permit instead of leaking capacity', () => {
  const owner = new AbortController(),
    operation = new RoutingOperation(1000, owner.signal);
  let releases = 0;
  owner.abort();
  try {
    assert.throws(
      () =>
        operation.own(() => {
          releases++;
        }),
      { code: 'EK_TROUTE_TIMEOUT' },
    );
    assert.equal(releases, 1);
  } finally {
    operation.end();
  }
});

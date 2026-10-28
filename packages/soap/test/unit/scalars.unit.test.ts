// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { NativeParser } from '../../dist/parser.js';
import { input } from '../../dist/input.js';
import { contract, response } from '../fixture.js';

const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
test('Actual native scalar hooks preserve long and decimal lexical values and reject invalid conversions', async () => {
  for (const [type, value, expected] of [
    ['long', '9223372036854775807', '9223372036854775807'],
    ['integer', '123456789012345678901234567890', '123456789012345678901234567890'],
    ['decimal', '0012345678901234567890.1234500', '0012345678901234567890.1234500'],
    ['string', '  0007  ', '  0007  '],
    ['boolean', '1', true],
    ['int', '0012', 12],
  ] as const) {
    const parser = await NativeParser.create(
      {
        source: contract.replace('type="xs:int"', 'type="xs:' + type + '"'),
        protocol: '1.1',
        timeoutMs: 10000,
        maxBytes: 4096,
      },
      new AbortController().signal,
    );
    try {
      const result = parser.parse(response.replace('quantity>12', 'quantity>' + value)) as {
        Body: { ReadStockResponse: { quantity: unknown } };
      };
      assert.equal(result.Body.ReadStockResponse.quantity, expected);
    } finally {
      await parser.close();
    }
  }
  for (const [type, value] of [
    ['long', '9223372036854775808'],
    ['int', '2147483648'],
    ['int', '1.2'],
    ['boolean', 'TRUE'],
    ['decimal', '1e20'],
    ['double', '1e999'],
    ['dateTime', 'invalid-date'],
  ]) {
    const parser = await NativeParser.create(
      {
        source: contract.replace('type="xs:int"', 'type="xs:' + type + '"'),
        protocol: '1.1',
        timeoutMs: 10000,
        maxBytes: 4096,
      },
      new AbortController().signal,
    );
    try {
      assert.throws(
        () => parser.parse(response.replace('quantity>12', 'quantity>' + value)),
        code('EK_SOAP_SCHEMA'),
      );
    } finally {
      await parser.close();
    }
  }
});
test('Native deserializers receive complete scalar text across CDATA and comments without losing chunks', async () => {
  const parser = await NativeParser.create(
    { source: contract, protocol: '1.1', timeoutMs: 10000, maxBytes: 4096 },
    new AbortController().signal,
  );
  try {
    for (const value of ['1<![CDATA[2]]>', '1<!--safe-->2']) {
      const result = parser.parse(response.replace('quantity>12', 'quantity>' + value)) as {
        Body: { ReadStockResponse: { quantity: number } };
      };
      assert.equal(result.Body.ReadStockResponse.quantity, 12);
    }
    assert.throws(
      () => parser.parse(response.replace('quantity>12', 'quantity>1 <!--gap-->2')),
      code('EK_SOAP_SCHEMA'),
    );
  } finally {
    await parser.close();
  }
});
test('Portable input snapshots reject accessors, proxies, cycles, sparse arrays and native raw XML controls', () => {
  let getters = 0;
  const getter = Object.defineProperty({}, 'sku', {
    enumerable: true,
    get() {
      getters++;
      return 'private';
    },
  });
  const cyclic: { cycle?: unknown } = {};
  cyclic.cycle = cyclic;
  const sparse = new Array(2);
  sparse[0] = 'one';
  Object.defineProperty(sparse, 'other', { value: 'two', enumerable: true });
  for (const value of [
    getter,
    new Proxy({}, {}),
    cyclic,
    sparse,
    { $xml: '<unsafe/>' },
    { attributes: { xmlns: 'urn:foreign' } },
    { sku: NaN },
    { sku: 9007199254740992 },
  ])
    assert.throws(() => input(value, 4096), code('EK_SOAP_SCHEMA'));
  assert.equal(getters, 0);
  assert.throws(() => input(Buffer.from('abc'), 4096), code('EK_UNSUPPORTED_CAPABILITY'));
  const source = { sku: '0007', nested: [{ quantity: 12 }] },
    copy = input(source, 4096) as typeof source;
  source.nested[0]!.quantity = 99;
  assert.equal(copy.nested[0]!.quantity, 12);
});

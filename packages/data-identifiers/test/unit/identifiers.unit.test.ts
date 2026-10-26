// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import { validate, version } from 'uuid';
import {
  createIdentifiersService,
  dataIdentifiersPlugin,
  IDENTIFIERS_CAPABILITY,
} from '../../dist/index.js';
import type { IdentifiersService } from '../../dist/index.js';

test('Identifiers accept the RFC 9562 Appendix A v4/v7 values and preserve canonical bytes', () => {
  const ids = createIdentifiersService({ allowVersions: [4, 7] });
  for (const [value, kind] of [
    ['919108f7-52d1-4320-9bac-f847db4148a8', 4],
    ['017f22e2-79b0-7cc3-98c4-dc0c0c07398f', 7],
  ] as const) {
    const parsed = ids.parseUuid(value);
    assert.deepEqual(parsed, { canonical: value, version: kind });
    assert.ok(Object.isFrozen(parsed));
    assert.equal(ids.isUuid(value, kind), true);
  }
});
test('Identifiers reject ambiguous, noncanonical, unsupported and malformed values without coercion', () => {
  const ids = createIdentifiersService({ allowVersions: [4, 7] });
  let called = 0;
  for (const value of [
    undefined,
    null,
    {},
    {
      toString() {
        called++;
        return 'invalid';
      },
    },
    '',
    '919108F7-52D1-4320-9BAC-F847DB4148A8',
    '919108f752d143209bacf847db4148a8',
    'urn:uuid:919108f7-52d1-4320-9bac-f847db4148a8',
    '00000000-0000-0000-0000-000000000000',
    'ffffffff-ffff-ffff-ffff-ffffffffffff',
    'c232ab00-9414-11ec-b3c8-9f6bdeced846',
    '919108f7-52d1-4320-0bac-f847db4148a8',
    '919108f7-52d1-4320-9bac-f847db4148a8\n',
    'x'.repeat(10000),
  ]) {
    assert.equal(ids.isUuid(value as never), false);
    assert.throws(
      () => ids.parseUuid(value as never),
      (error) => error instanceof KitError && error.code === 'EK_IDENTIFIER_INVALID',
    );
  }
  assert.equal(called, 0);
  assert.equal(ids.isUuid(ids.uuidV4(), 5 as never), false);
});
test('Identifiers use native cryptographic generation and show no collisions in a bounded sanity corpus', (t) => {
  const ids = createIdentifiersService({ allowVersions: [4, 7] });
  t.mock.method(Math, 'random', () => {
    throw new Error('Non-cryptographic randomness must not be used');
  });
  const corpus = new Set<string>();
  for (let i = 0; i < 5000; i++)
    for (const [value, kind] of [
      [ids.uuidV4(), 4],
      [ids.uuidV7(), 7],
    ] as const) {
      assert.equal(validate(value), true);
      assert.equal(version(value), kind);
      assert.equal(corpus.has(value), false);
      corpus.add(value);
    }
  assert.equal(corpus.size, 10000);
});
test('UUIDv7 follows increasing wall-clock milliseconds without claiming same-tick or distributed order', (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1700000000000 });
  const ids = createIdentifiersService({ allowVersions: [7] });
  const first = ids.uuidV7();
  t.mock.timers.tick(1);
  const second = ids.uuidV7();
  assert.ok(first < second);
});
test('Identifier version policy is captured once and never silently relaxed', () => {
  const versions: Array<4 | 7> = [4],
    ids = createIdentifiersService({ allowVersions: versions });
  versions.push(7);
  assert.equal(ids.isUuid('017f22e2-79b0-7cc3-98c4-dc0c0c07398f'), false);
  assert.throws(() => ids.uuidV7());
  const onlyV7 = createIdentifiersService({ allowVersions: [7] });
  assert.throws(() => onlyV7.uuidV4());
  let invoked = 0;
  const getter = Object.defineProperty({}, 'allowVersions', {
    get() {
      invoked++;
      return [4];
    },
  });
  for (const input of [
    undefined,
    null,
    [],
    {},
    getter,
    { allowVersions: [] },
    { allowVersions: [4, 4] },
    { allowVersions: [1] },
    { allowVersions: [4, 7, 4] },
    { allowVersions: [4], extra: true },
    { allowVersions: new Array(1) },
  ])
    assert.throws(() => createIdentifiersService(input as never));
  assert.equal(invoked, 0);
});
test('Reused identifier plugins keep application lifetimes isolated and closed handles fail', async () => {
  const plugin = dataIdentifiersPlugin({ allowVersions: [4, 7] }),
    options = {
      service: { name: 'identifier-fixture', version: '1.0.0', environment: 'test' as const },
      plugins: [plugin],
    },
    a = await createApplication(options),
    b = await createApplication(options);
  try {
    await a.start();
    await b.start();
    const first = a.resolve<IdentifiersService>(IDENTIFIERS_CAPABILITY),
      second = b.resolve<IdentifiersService>(IDENTIFIERS_CAPABILITY);
    assert.notEqual(first, second);
    assert.ok(first.isUuid(first.uuidV4()));
    await a.stop();
    for (const operation of [
      () => first.uuidV4(),
      () => first.uuidV7(),
      () => first.parseUuid('invalid'),
      () => first.isUuid('invalid'),
    ])
      assert.throws(
        operation,
        (error) => error instanceof KitError && error.code === 'EK_RESOURCE_CLOSED',
      );
    assert.ok(second.isUuid(second.uuidV7()));
  } finally {
    await a.stop();
    await b.stop();
  }
});

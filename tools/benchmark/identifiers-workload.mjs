// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { validate, version, v7 } from 'uuid';

/** Match the public canonical/version policy while delegating randomness and parsing upstream. */
export function nativeIdentifiers() {
  const kind = (value) => {
    if (
      typeof value !== 'string' ||
      value.length !== 36 ||
      value !== value.toLowerCase() ||
      !validate(value)
    )
      return undefined;
    const found = version(value);
    return found === 4 || found === 7 ? found : undefined;
  };
  return Object.freeze({
    uuidV4: () => randomUUID(),
    uuidV7: () => v7({}),
    parseUuid(value) {
      const found = kind(value);
      if (found === undefined) throw new Error('A canonical supported UUID is required');
      return Object.freeze({ canonical: value, version: found });
    },
    isUuid(value, requested) {
      if (requested !== undefined && requested !== 4 && requested !== 7) return false;
      const found = kind(value);
      return found !== undefined && (requested === undefined || found === requested);
    },
  });
}

/** Fixed inputs are shared by every isolated mode; results never enter report labels. */
export function identifierWorkload(service, fixture) {
  assert.equal(version(fixture.v4), 4);
  assert.equal(version(fixture.v7), 7);
  return Object.freeze({
    uuidV4: () => service.uuidV4(),
    uuidV7: () => service.uuidV7(),
    parseV4: () => service.parseUuid(fixture.v4),
    parseV7: () => service.parseUuid(fixture.v7),
    validateV4: () => service.isUuid(fixture.v4, 4),
    validateV7: () => service.isUuid(fixture.v7, 7),
    rejectNoncanonical: () => service.isUuid(fixture.v4.toUpperCase()),
  });
}

/** Functional preflight is separate from timing and checks actual upstream entropy and canonical outputs. */
export function verifyIdentifiers(service, fixture) {
  const observed = new Set();
  for (const [name, expected] of [
    ['uuidV4', 4],
    ['uuidV7', 7],
  ])
    for (let index = 0; index < 100; index++) {
      const value = service[name]();
      assert.ok(validate(value));
      assert.equal(version(value), expected);
      assert.equal(value, value.toLowerCase());
      assert.equal(observed.has(value), false);
      observed.add(value);
    }
  for (const [value, expected] of [
    [fixture.v4, 4],
    [fixture.v7, 7],
  ]) {
    const parsed = service.parseUuid(value);
    assert.deepEqual(parsed, { canonical: value, version: expected });
    assert.ok(Object.isFrozen(parsed));
    assert.equal(service.isUuid(value), true);
    assert.equal(service.isUuid(value, expected === 4 ? 7 : 4), false);
  }
  for (const value of [
    '',
    'not-a-uuid',
    fixture.v4.toUpperCase(),
    '00000000-0000-0000-0000-000000000000',
    '00000000-0000-1000-8000-000000000000',
  ]) {
    assert.equal(service.isUuid(value), false);
    assert.throws(() => service.parseUuid(value));
  }
  return { checkedFreshIdentifiers: observed.size, canonicalFixtures: 2, invalidFixtures: 5 };
}

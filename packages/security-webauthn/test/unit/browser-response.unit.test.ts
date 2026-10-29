// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { readUnverifiedResponse } from '../../dist/browser-response.js';
import { authenticator } from '../support/authenticator.js';

const invalid = (error: unknown) => error instanceof KitError && error.code === 'EK_MFA_INVALID';
const challenge = () => randomBytes(32).toString('base64url');

test('Executable proxy wrappers are rejected without invoking traps at any browser JSON depth', () => {
  const device = authenticator(),
    response = device.authentication(challenge());
  let calls = 0;
  const handler: ProxyHandler<object> = {
    get(target, name, receiver) {
      calls++;
      return Reflect.get(target, name, receiver);
    },
    getPrototypeOf(target) {
      calls++;
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      calls++;
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, name) {
      calls++;
      return Reflect.getOwnPropertyDescriptor(target, name);
    },
  };
  for (const input of [
    new Proxy(response, handler),
    { ...response, response: new Proxy(response.response, handler) },
    { ...response, clientExtensionResults: new Proxy({}, handler) },
    { ...response, extra: new Proxy([], handler) },
    { ...response, extra: [{ value: new Proxy({ harmless: true }, handler) }] },
  ])
    assert.throws(() => readUnverifiedResponse(input, false), invalid);
  assert.equal(calls, 0);
  const revoked = Proxy.revocable(response, handler);
  revoked.revoke();
  assert.throws(() => readUnverifiedResponse(revoked.proxy, false), invalid);
  assert.equal(calls, 0);
});

test('Browser snapshots retain JSON data and distinguish absent, null and exact account handles', () => {
  const device = authenticator(),
    proof = challenge();
  for (const registration of [false, true]) {
    const response = registration ? device.registration(proof) : device.authentication(proof);
    const parsed = readUnverifiedResponse(response, registration);
    assert.equal(parsed.challenge, proof);
    assert.equal(parsed.credentialId, device.id);
    assert.deepEqual(JSON.parse(parsed.serialized), response);
    assert.ok(Object.isFrozen(parsed));
  }
  const response = device.authentication(proof);
  for (const userHandle of [null, randomBytes(32).toString('base64url')]) {
    const parsed = readUnverifiedResponse(
      { ...response, response: { ...response.response, userHandle } },
      false,
    );
    assert.equal(parsed.userHandle, userHandle);
  }
  const extension = {
    yes: true,
    none: null,
    number: 0.5,
    list: [1, false, 'value'],
    omitted: undefined,
  };
  const parsed = readUnverifiedResponse({ ...response, clientExtensionResults: extension }, false);
  assert.deepEqual(JSON.parse(parsed.serialized).clientExtensionResults, {
    yes: true,
    none: null,
    number: 0.5,
    list: [1, false, 'value'],
  });
  response.response.signature = 'changed-after-snapshot';
  assert.equal(parsed.serialized.includes(response.response.signature), false);
});

test('Browser serialization never invokes getters, toJSON or hostile proxy traps for diagnostics', () => {
  const device = authenticator(),
    response = device.authentication(challenge());
  let calls = 0;
  const getter = {
    ...response,
    get extra() {
      calls++;
      throw new Error('Sensitive getter');
    },
  };
  const toJSON = {
    ...response,
    toJSON() {
      calls++;
      throw new Error('Sensitive serializer');
    },
  };
  const array: unknown[] = [];
  Object.defineProperty(array, '0', {
    get() {
      calls++;
      return 1;
    },
    enumerable: true,
  });
  const proxy = new Proxy(
    {},
    {
      ownKeys() {
        throw new Error('Sensitive proxy diagnostic');
      },
    },
  );
  for (const input of [getter, toJSON, proxy, { ...response, extra: array }])
    assert.throws(
      () => readUnverifiedResponse(input, false),
      (error) => {
        assert.ok(invalid(error));
        assert.equal(inspect(error).includes('Sensitive'), false);
        return true;
      },
    );
  assert.equal(calls, 0);
});

test('Non-JSON values, prototypes, cycles, sparse arrays and dangerous keys are rejected', () => {
  const device = authenticator(),
    response = device.authentication(challenge());
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  const sparse = new Array(2);
  sparse[0] = 1;
  const hidden = Object.defineProperty({}, 'value', { value: 1, enumerable: false });
  for (const extra of [
    NaN,
    Infinity,
    1n,
    () => 1,
    Symbol('untrusted'),
    new Date(),
    cyclic,
    sparse,
    hidden,
    Object.assign([], { named: true }),
    Object.create({ inherited: true }),
    { [Symbol('untrusted')]: 1 },
    JSON.parse('{"__proto__":{"value":true}}'),
    { constructor: 'forbidden' },
    { prototype: 'forbidden' },
  ])
    assert.throws(() => readUnverifiedResponse({ ...response, extra }, false), invalid);
  for (const input of [null, undefined, [], 1, 'not an object'])
    assert.throws(() => readUnverifiedResponse(input, false), invalid);
});

test('Byte, node, depth and client-data bounds are checked before upstream crypto', () => {
  const device = authenticator(),
    response = device.authentication(challenge());
  const overhead = Buffer.byteLength(JSON.stringify({ ...response, extra: '' }));
  const exact = readUnverifiedResponse(
    { ...response, extra: 'x'.repeat(1048576 - overhead) },
    false,
  );
  assert.equal(Buffer.byteLength(exact.serialized), 1048576);
  assert.throws(
    () => readUnverifiedResponse({ ...response, extra: 'x'.repeat(1048577 - overhead) }, false),
    invalid,
  );
  assert.throws(
    () => readUnverifiedResponse({ ...response, extra: 'é'.repeat(524289) }, false),
    invalid,
  );
  let deep: unknown = 1;
  for (let index = 0; index < 18; index++) deep = { next: deep };
  for (const extra of [
    'x'.repeat(1048577),
    '\u0000'.repeat(200000),
    new Array(4097).fill(1),
    { a: new Array(2100).fill(1), b: new Array(2100).fill(1) },
    deep,
    Object.fromEntries(Array.from({ length: 4098 }, (_, index) => ['key' + index, 1])),
  ])
    assert.throws(() => readUnverifiedResponse({ ...response, extra }, false), invalid);
  const oversized = Buffer.alloc(16385, 32).toString('base64url');
  assert.throws(
    () =>
      readUnverifiedResponse(
        { ...response, response: { ...response.response, clientDataJSON: oversized } },
        false,
      ),
    invalid,
  );
});

test('Credential, challenge and account handles require canonical bounded base64url', () => {
  const device = authenticator(),
    response = device.authentication(challenge());
  for (const id of ['', 1, 'A'.repeat(42) + 'B', randomBytes(1025).toString('base64url'), 'bad='])
    assert.throws(() => readUnverifiedResponse({ ...response, id, rawId: id }, false), invalid);
  assert.throws(() => readUnverifiedResponse({ ...response, rawId: challenge() }, false), invalid);
  assert.throws(() => readUnverifiedResponse({ ...response, type: 'other' }, false), invalid);
  for (const value of [null, [], {}, { challenge: 'short' }, { challenge: 'A'.repeat(42) + 'B' }]) {
    const clientDataJSON = Buffer.from(JSON.stringify(value)).toString('base64url');
    assert.throws(
      () =>
        readUnverifiedResponse(
          { ...response, response: { ...response.response, clientDataJSON } },
          false,
        ),
      invalid,
    );
  }
  for (const clientDataJSON of [
    'invalid=',
    Buffer.from([255]).toString('base64url'),
    Buffer.from('not JSON').toString('base64url'),
  ])
    assert.throws(
      () =>
        readUnverifiedResponse(
          { ...response, response: { ...response.response, clientDataJSON } },
          false,
        ),
      invalid,
    );
  for (const userHandle of [
    '',
    1,
    randomBytes(16).toString('base64url'),
    randomBytes(64).toString('base64url'),
  ])
    assert.throws(
      () =>
        readUnverifiedResponse(
          { ...response, response: { ...response.response, userHandle } },
          false,
        ),
      invalid,
    );
});

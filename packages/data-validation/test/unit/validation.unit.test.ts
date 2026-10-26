// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { createApplication, KitError } from '@arkenivajs/core';
import {
  createValidationService,
  dataValidationPlugin,
  VALIDATION_CAPABILITY,
} from '../../dist/index.js';
import type { ValidationService, DataValidationPluginSettings } from '../../dist/index.js';

const options = (): DataValidationPluginSettings => ({
  schemas: {},
  policy: { maxConcurrent: 2, timeoutMs: 1000 },
});
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
test('Email validation preserves local-part identity, uses native IDNA and requires explicit EAI permission', () => {
  const validation = createValidationService(options());
  assert.deepEqual(validation.email('User@EXAMPLE.ORG'), {
    valid: true,
    value: 'User@example.org',
    errors: [],
  });
  assert.deepEqual(validation.email('User@bücher.example', { allowInternationalized: true }), {
    valid: true,
    value: 'User@xn--bcher-kva.example',
    errors: [],
  });
  assert.equal(validation.email('δοκιμή@example.org').valid, false);
  assert.equal(
    validation.email('δοκιμή@example.org', { allowInternationalized: true }).valid,
    true,
  );
  assert.equal(validation.email('"a@b"@example.org').valid, true);
  for (const value of [
    'a@localhost',
    'a..b@example.org',
    '.a@example.org',
    'User <a@example.org>',
    'a@example.org\r\nBcc:x@example.org',
    'a@[127.0.0.1]',
    'a\ud800@example.org',
    ' a@example.org',
    '',
    'a@' + 'a'.repeat(250) + '.org',
    null,
    {},
    123,
  ])
    assert.equal(validation.email(value as never).valid, false);
  assert.equal(validation.email('a@example.org', { maxLength: 5 }).valid, false);
});
test('URL validation enforces exact canonical hosts, explicit schemes and native address ranges without DNS', (t) => {
  t.mock.method(globalThis, 'fetch', () => {
    throw new Error('Validation must not perform network work');
  });
  const validation = createValidationService(options()),
    policy = {
      schemes: ['https:'] as const,
      allowedHosts: ['BÜCHER.example'],
    };
  const valid = validation.url('https://bücher.example/a?b=1', policy);
  assert.equal(valid.valid, true);
  if (valid.valid) assert.equal(valid.value.href, 'https://xn--bcher-kva.example/a?b=1');
  for (const value of [
    'https://bücher.example.evil.org',
    'http://bücher.example',
    'https://user:pass@bücher.example',
    '//bücher.example',
    'https:bücher.example',
    'https://bücher.example./',
    'https://bücher.example\\@evil.org',
    'https://bücher.example/\n',
    'javascript:alert(1)',
    'file:///tmp/a',
    'invalid',
    null,
    {},
  ])
    assert.equal(validation.url(value as never, policy).valid, false);
  const internet = { schemes: ['https:', 'http:'] as const };
  for (const host of [
    'localhost',
    'x.localhost',
    'test.local',
    'singlelabel',
    '127.0.0.1',
    '2130706433',
    '0x7f000001',
    '10.0.0.1',
    '169.254.169.254',
    '100.64.0.1',
    '[::1]',
    '[::ffff:127.0.0.1]',
    '[fe80::1]',
    '[fc00::1]',
    '[2001:db8::1]',
  ])
    assert.equal(validation.url('https://' + host, internet).valid, false, host);
  assert.equal(validation.url('https://8.8.8.8', internet).valid, true);
  assert.equal(validation.url('https://[2606:4700:4700::1111]', internet).valid, true);
  assert.equal(
    validation.url('http://localhost:8080', { schemes: ['http:'], denyPrivateNetworks: false })
      .valid,
    true,
  );
  // An unresolved public-looking name is only syntactically valid, never a DNS/SSRF assertion.
  assert.equal(validation.url('https://unresolved.example', internet).valid, true);
});
test('IP validation uses strict Node syntax, canonical IPv6 and an explicit mapped-address policy', () => {
  const validation = createValidationService(options());
  assert.deepEqual(validation.ip('2001:0DB8:0000:0000:0000:0000:0000:0001'), {
    valid: true,
    value: '2001:db8::1',
    errors: [],
  });
  assert.deepEqual(validation.ip('192.0.2.1', { version: 4 }), {
    valid: true,
    value: '192.0.2.1',
    errors: [],
  });
  assert.equal(validation.ip('::ffff:192.0.2.1').valid, false);
  assert.deepEqual(validation.ip('::ffff:192.0.2.1', { version: 6, allowMappedIPv4: true }), {
    valid: true,
    value: '::ffff:c000:201',
    errors: [],
  });
  assert.equal(
    validation.ip('::ffff:192.0.2.1', { version: 4, allowMappedIPv4: true }).valid,
    false,
  );
  for (const value of [
    'fe80::1%eth0',
    '[::1]',
    '2001:::1',
    '127.1',
    '010.0.0.1',
    '0x7f000001',
    '192.0.2.1/24',
    '256.0.0.1',
    '::1 ',
    'x'.repeat(46),
    undefined,
    [],
  ])
    assert.equal(validation.ip(value as never).valid, false);
});
test('UUID validation reuses the identifier canonical/version policy without coercion', () => {
  const validation = createValidationService(options()),
    uuid = '919108f7-52d1-4320-9bac-f847db4148a8';
  assert.deepEqual(validation.uuid(uuid, 4), { valid: true, value: uuid, errors: [] });
  for (const value of [uuid.toUpperCase(), 'invalid', null, {}])
    assert.equal(validation.uuid(value as never).valid, false);
  assert.equal(validation.uuid(uuid, 7).valid, false);
  assert.equal(validation.uuid(uuid, 5 as never).valid, false);
  const failure = validation.uuid('private-rejected-value');
  assert.ok(!JSON.stringify(failure).includes('private-rejected-value'));
  assert.ok(Object.isFrozen(failure));
  assert.ok(Object.isFrozen(failure.errors));
});
test('Ajv validates a captured deployment catalog, standard formats and local references without coercion or defaults', () => {
  const schema = {
    type: 'object',
    additionalProperties: false,
    required: ['id', 'contact'],
    properties: {
      id: { type: 'integer' },
      contact: { $ref: '#/definitions/email' },
      optional: { type: 'string', default: 'unused' },
    },
    definitions: { email: { type: 'string', format: 'email' } },
  };
  const settings = { ...options(), schemas: { customer: schema } },
    validation = createValidationService(settings);
  schema.properties.id.type = 'string';
  const data = { id: 7, contact: 'user@example.org' };
  validation.assertSchema(data, 'customer');
  assert.deepEqual(data, { id: 7, contact: 'user@example.org' });
  for (const invalid of [
    { id: '7', contact: 'user@example.org' },
    { id: 7, contact: 'invalid' },
    { id: 7, contact: 'user@example.org', extra: true },
    { id: 7 },
    null,
  ])
    assert.throws(
      () => validation.assertSchema(invalid, 'customer'),
      code('EK_VALIDATION_INVALID'),
    );
  assert.throws(() => validation.assertSchema(data, 'missing'), code('EK_VALIDATION_POLICY'));
  assert.throws(() => validation.assertSchema(data, null as never), code('EK_VALIDATION_POLICY'));
  const literal = createValidationService({
    ...options(),
    schemas: { literal: { enum: [{ $ref: 'literal text', $async: 'literal text' }] } },
  });
  literal.assertSchema({ $ref: 'literal text', $async: 'literal text' }, 'literal');
});
test('Schema input rejects pollution, accessors, cycles, foreign prototypes and excessive size without exposing payloads', () => {
  const validation = createValidationService({ ...options(), schemas: { any: {} } });
  let accessed = 0;
  const getter = Object.defineProperty({}, 'payload', {
    enumerable: true,
    get() {
      accessed++;
      return 'private-payload';
    },
  });
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  let deep: unknown = null;
  for (let i = 0; i < 34; i++) deep = { child: deep };
  const hole = new Array(1),
    hidden = Object.defineProperty({}, 'secret', { value: 1 }),
    arrayProperty = Object.assign(new Array(1), { payload: 7 });
  for (const input of [
    getter,
    cycle,
    deep,
    hole,
    hidden,
    arrayProperty,
    new Date(),
    JSON.parse('{"__proto__":{"polluted":true}}'),
    { constructor: {} },
    { toString: 'private-payload' },
    { valueOf: 'private-payload' },
    { value: Infinity },
    { value: undefined },
    { value: 1n },
    Symbol('data'),
    () => 1,
    'x'.repeat(65537),
    { [Symbol('data')]: 1 },
    Array.from({ length: 4097 }, () => 1),
  ]) {
    assert.throws(
      () => validation.assertSchema(input, 'any'),
      (error) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_VALIDATION_INVALID');
        assert.ok(!JSON.stringify(error.toSafeJSON()).includes('private-payload'));
        return true;
      },
    );
  }
  assert.equal(accessed, 0);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  validation.assertSchema(
    { null: null, boolean: true, number: 1.5, array: ['value', false] },
    'any',
  );
});
test('Malformed deployment and operation policies fail explicitly before any validation', () => {
  const validation = createValidationService(options());
  for (const policy of [
    null,
    [],
    { maxLength: null },
    { maxLength: 0 },
    { maxLength: 255 },
    { allowInternationalized: 'true' },
    { normalize: true },
  ])
    assert.throws(
      () => validation.email('a@example.org', policy as never),
      code('EK_VALIDATION_POLICY'),
    );
  for (const policy of [
    null,
    {},
    { schemes: [] },
    { schemes: ['https:', 'https:'] },
    { schemes: ['file:'] },
    { schemes: ['https:'], allowedHosts: ['example.org:443'] },
    { schemes: ['https:'], allowedHosts: ['*.example.org'] },
    { schemes: ['https:'], allowedHosts: ['example.org', 'EXAMPLE.ORG'] },
    { schemes: ['https:'], allowedHosts: ['user@example.org'] },
    { schemes: ['https:'], denyPrivateNetworks: null },
  ])
    assert.throws(
      () => validation.url('https://example.org', policy as never),
      code('EK_VALIDATION_POLICY'),
    );
  for (const policy of [null, { version: 5 }, { allowMappedIPv4: 1 }, { normalize: true }])
    assert.throws(() => validation.ip('::1', policy as never), code('EK_VALIDATION_POLICY'));
  let called = 0;
  const accessor = Object.defineProperty({}, 'maxLength', {
    get() {
      called++;
      return 254;
    },
  });
  assert.throws(() => validation.email('a@example.org', accessor), code('EK_VALIDATION_POLICY'));
  const proxy = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new Error('private-policy-value');
      },
    },
  );
  assert.throws(() => validation.ip('::1', proxy), code('EK_VALIDATION_POLICY'));
  assert.equal(called, 0);
  for (const input of [
    null,
    {},
    { ...options(), extra: true },
    { ...options(), schemas: null },
    { ...options(), policy: { maxConcurrent: 1, timeoutMs: 0 } },
    { ...options(), policy: { maxConcurrent: 0, timeoutMs: 1 } },
    { ...options(), policy: { maxConcurrent: 1, timeoutMs: 1, maxInputBytes: null } },
    { ...options(), schemas: { remote: { $ref: 'https://schemas.invalid/untrusted' } } },
    { ...options(), schemas: { async: { $async: true, type: 'string' } } },
    { ...options(), schemas: { unknown: { unknownKeyword: true } } },
    { ...options(), schemas: { invalid: [] } },
  ])
    assert.throws(() => createValidationService(input as never), code('EK_CONFIG_INVALID'));
});
test('Input/output budgets are captured, schema byte limits are exact and expired work cannot return success', (t) => {
  const input = { maxConcurrent: 1, timeoutMs: 100, maxInputBytes: 10, maxOutputBytes: 5 },
    validation = createValidationService({ schemas: { any: {} }, policy: input });
  input.maxInputBytes = 10000;
  input.maxOutputBytes = 10000;
  assert.equal(validation.email('a@example.org').valid, false);
  assert.equal(validation.ip('192.0.2.1').valid, false);
  assert.equal(validation.uuid('919108f7-52d1-4320-9bac-f847db4148a8').valid, false);
  validation.assertSchema('12345678', 'any');
  assert.throws(() => validation.assertSchema('123456789', 'any'), code('EK_VALIDATION_INVALID'));
  assert.throws(
    () => validation.assertSchema('\n'.repeat(5), 'any'),
    code('EK_VALIDATION_INVALID'),
  );
  let calls = 0;
  t.mock.method(performance, 'now', () => (++calls === 1 ? 0 : 101));
  assert.throws(() => validation.ip('::1'), code('EK_TIMEOUT'));
});
test('Optional validation capabilities remain isolated across applications and disappear after shutdown', async () => {
  const plugin = dataValidationPlugin(options()),
    configuration = {
      service: { name: 'validation-fixture', version: '1.0.0', environment: 'test' as const },
      plugins: [plugin],
    };
  const a = await createApplication(configuration),
    b = await createApplication(configuration);
  try {
    await a.start();
    await b.start();
    const first = a.resolve<ValidationService>(VALIDATION_CAPABILITY),
      second = b.resolve<ValidationService>(VALIDATION_CAPABILITY);
    assert.notEqual(first, second);
    await a.stop();
    for (const call of [
      () => first.email('a@example.org'),
      () => first.url('https://example.org', { schemes: ['https:'] }),
      () => first.ip('::1'),
      () => first.uuid('invalid'),
      () => first.assertSchema({}, 'any'),
    ])
      assert.throws(call, code('EK_RESOURCE_CLOSED'));
    assert.equal(second.ip('::1').valid, true);
  } finally {
    await a.stop();
    await b.stop();
  }
});

test('Reentrant validation cannot exceed admission and duplicate/absent optional capabilities fail explicitly', async () => {
  const settings = { schemas: {}, policy: { maxConcurrent: 1, timeoutMs: 1000 } },
    validation = createValidationService(settings);
  let denials = 0;
  const reentrant = new Proxy(
    {},
    {
      getPrototypeOf() {
        assert.throws(() => validation.ip('::1'), code('EK_VALIDATION_POLICY'));
        denials++;
        return Object.prototype;
      },
    },
  );
  assert.equal(validation.email('a@example.org', reentrant).valid, true);
  assert.ok(denials > 0);
  assert.equal(validation.ip('::1').valid, true);
  const config = {
    service: { name: 'validation-fixture', version: '1.0.0', environment: 'test' as const },
  };
  await assert.rejects(() =>
    createApplication({
      ...config,
      plugins: [dataValidationPlugin(settings), dataValidationPlugin(settings)],
    }),
  );
  const app = await createApplication(config);
  try {
    await app.start();
    assert.equal(app.tryResolve(VALIDATION_CAPABILITY), undefined);
    assert.throws(() => app.resolve(VALIDATION_CAPABILITY), code('EK_UNSUPPORTED_CAPABILITY'));
  } finally {
    await app.stop();
  }
});

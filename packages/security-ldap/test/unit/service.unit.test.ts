// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { Writable } from 'node:stream';
import { KitError, createApplication } from '@arkenivajs/core';
import {
  ApproximateFilter,
  GreaterThanEqualsFilter,
  LessThanEqualsFilter,
  NotFilter,
  PresenceFilter,
  SubstringFilter,
  ExtensibleFilter,
} from 'ldapts';
import { loggingPlugin } from '@arkenivajs/logging';
import { createLdapService, ldapPlugin, LDAP_CAPABILITY } from '../../dist/index.js';
import type { LdapService, LdapSettings } from '../../dist/index.js';
import { capture, query } from '../../dist/settings.js';
import { boundFilter } from '../../dist/filter.js';
import { fields, array, attribute, method, integer, text } from '../../dist/validation.js';

function fixture() {
  const password = randomBytes(32).toString('base64url'),
    bytes = Buffer.from(password);
  const state = { calls: 0, hold: undefined as Promise<void> | undefined, unavailable: false };
  const settings: LdapSettings = {
    url: 'ldaps://127.0.0.1:9',
    baseDn: 'ou=people,dc=fixture,dc=invalid',
    groupSearchBaseDn: 'ou=groups,dc=fixture,dc=invalid',
    userFilterTemplate: '(uid={username})',
    serviceBindDnRef: 'fixture://bind-dn',
    serviceBindPasswordRef: 'fixture://bind-password',
    environment: 'test',
    timeoutMs: 1000,
    secretProvider: {
      async get(reference) {
        state.calls++;
        await state.hold;
        if (state.unavailable) throw new Error(password);
        return {
          bytes: reference.endsWith('bind-dn')
            ? Buffer.from('cn=service,dc=fixture,dc=invalid')
            : bytes,
          keyVersion: 'fixture-version',
        };
      },
    },
  };
  return { settings, state, bytes, password };
}
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
test('LDAP factories capture policy without I/O and expose only the prescribed capability', () => {
  const f = fixture(),
    service = createLdapService(f.settings),
    plugin = ldapPlugin(f.settings);
  assert.equal(f.state.calls, 0);
  assert.ok(Object.isFrozen(service));
  assert.deepEqual(Object.keys(service).sort(), [
    'findUser',
    'getGroups',
    'ping',
    'search',
    'verifyCredentials',
  ]);
  assert.ok(plugin.capabilities.has('security-ldap'));
  assert.equal(typeof LDAP_CAPABILITY, 'symbol');
});
test('LDAP deployment rejects insecure URLs, malformed limits, credentials and test providers in production', () => {
  const f = fixture();
  for (const change of [
    { url: 'ldap://localhost:389' },
    { url: 'http://localhost' },
    { url: 'ldaps://user:pass@localhost' },
    { url: 'ldaps://localhost/path' },
    { url: 'ldaps://localhost?x=y' },
    { requireStartTls: 'true' },
    { maxEntries: 0 },
    { maxEntries: 5001 },
    { maxGroupDepth: 33 },
    { timeoutMs: 30001 },
    { timeoutMs: 1.5 },
    { environment: 'unknown' },
    { allowedAttributes: ['uid', 'cn', 'userPassword'] },
    { allowedAttributes: [] },
    { allowedAttributes: ['cn'] },
    { userFilterTemplate: '(uid=literal)' },
    {
      environment: 'production',
      secretProvider: { usage: 'test-only', get: f.settings.secretProvider.get },
    },
  ])
    assert.throws(
      () => createLdapService({ ...f.settings, ...change } as LdapSettings),
      code('EK_LDAP_FILTER'),
    );
  assert.ok(
    createLdapService({ ...f.settings, url: 'ldap://localhost:389', requireStartTls: true }),
  );
});
test('LDAP bound filters keep hostile strings and Unicode inside native equality assertions', () => {
  const payload = '*)(|(uid=*))\\\u00e9';
  const filter = boundFilter('(uid={username})', { username: payload }, ['uid']);
  assert.equal(filter.matches({ uid: payload }), true);
  assert.equal(filter.matches({ uid: 'alice' }), false);
  assert.equal(
    boundFilter(
      '(&(objectClass=inetOrgPerson)(|(uid={username})(cn={username})))',
      { username: 'étoile' },
      ['uid', 'cn'],
    ).matches({ objectclass: 'inetOrgPerson', uid: 'étoile' }),
    true,
  );
});
test('LDAP filter grammar and projection reject unused parameters, syntax placeholders and credential attributes', () => {
  for (const [template, values] of [
    ['(uid={missing})', {}],
    ['({name}=x)', { name: 'uid' }],
    ['(uid=prefix{username})', { username: 'alice' }],
    ['(userPassword={username})', { username: 'x' }],
    ['(uid=x)', { username: 'x' }],
    ['(uid={username})', { username: 'x', unused: 'x' }],
    ['('.repeat(33) + ')'.repeat(33), {}],
    ['(uid=arkenivajs_ldap_bound_0)', {}],
    ['(uid={username}', { username: 'x' }],
  ] as const)
    assert.throws(() => boundFilter(template, values, ['uid']), code('EK_LDAP_FILTER'));
  const s = capture(fixture().settings),
    normal = {
      baseDn: s.baseDn,
      filter: { template: '(uid={name})', values: { name: 'alice' } },
      attributes: ['uid'],
    };
  assert.ok(Object.isFrozen(query(normal, s).filter.values));
  for (const change of [
    { baseDn: 'dc=foreign,dc=invalid' },
    { attributes: ['*'] },
    { attributes: [] },
    { attributes: ['cn', 'cn'] },
    { pageSize: 257 },
    { maxEntries: 1001 },
  ])
    assert.throws(() => query({ ...normal, ...change }, s));
});
test('LDAP native filter families retain bound data without permitting structural substitution', () => {
  const payload = '*)(uid=*)',
    values = { value: payload };
  for (const [template, Type] of [
    ['(uid~={value})', ApproximateFilter],
    ['(uid>={value})', GreaterThanEqualsFilter],
    ['(uid<={value})', LessThanEqualsFilter],
    ['(uid:caseExactMatch:={value})', ExtensibleFilter],
  ] as const) {
    const filter = boundFilter(template, values, ['uid']);
    assert.ok(filter instanceof Type);
    assert.equal((filter as ApproximateFilter).value, payload);
  }
  assert.ok(boundFilter('(!(uid={value}))', values, ['uid']) instanceof NotFilter);
  assert.ok(boundFilter('(uid=*)', {}, ['uid']) instanceof PresenceFilter);
  const substring = boundFilter(
    '(uid={first}*{middle}*{last})',
    { first: payload, middle: 'étoile', last: 'tail' },
    ['uid'],
  );
  assert.ok(substring instanceof SubstringFilter);
  assert.equal(substring.initial, payload);
  assert.deepEqual(substring.any, ['étoile']);
  assert.equal(substring.final, 'tail');
});
test('LDAP invalid secret envelopes and expired versions cannot start native directory work', async () => {
  const f = fixture();
  for (const value of [
    null,
    { bytes: new Uint8Array(), keyVersion: 'fixture-version' },
    { bytes: Buffer.from('x'), keyVersion: '' },
    { bytes: Buffer.from('x'), keyVersion: 'fixture-version', expiresAt: 'invalid' },
    {
      bytes: Buffer.from('x'),
      keyVersion: 'fixture-version',
      expiresAt: new Date(0).toISOString(),
    },
    { bytes: Buffer.from([0xff]), keyVersion: 'fixture-version' },
  ]) {
    const directory = createLdapService({
      ...f.settings,
      secretProvider: {
        async get() {
          return value as never;
        },
      },
    });
    await assert.rejects(directory.ping(), (error: unknown) => error instanceof KitError);
  }
});
test('LDAP rejects inherited test-only markers in production without executing provider getters', () => {
  const f = fixture(),
    provider = Object.assign(Object.create({ usage: 'test-only' }), {
      get: f.settings.secretProvider.get,
    });
  assert.throws(() =>
    createLdapService({ ...f.settings, environment: 'production', secretProvider: provider }),
  );
  let invoked = false;
  const getter = Object.defineProperty({ get: f.settings.secretProvider.get }, 'usage', {
    get() {
      invoked = true;
      return 'production';
    },
  });
  assert.throws(() => createLdapService({ ...f.settings, secretProvider: getter }));
  assert.equal(invoked, false);
});
test('LDAP validation does not invoke accessors or accept sparse, poisoned or unbounded input', () => {
  let called = false;
  const getter = Object.defineProperty({}, 'url', {
    get() {
      called = true;
      return 'ldaps://localhost';
    },
  });
  for (const value of [null, [], getter, JSON.parse('{"__proto__":1}'), { [Symbol('x')]: 1 }])
    assert.throws(() => fields(value));
  assert.equal(called, false);
  assert.throws(() => array(new Array(1), 2));
  assert.throws(() => array([1, 2], 1));
  for (const value of ['\0', '\ud800', 'x'.repeat(1025)]) assert.throws(() => text(value, 1024));
  for (const value of [NaN, Infinity, -1, 1.5, '1']) assert.throws(() => integer(value, 10));
  assert.throws(() => attribute('unicodePwd'));
  assert.equal(attribute('sAMAccountName'), 'samaccountname');
  assert.equal(
    method<() => number>(
      {
        get() {
          return 1;
        },
      },
      'get',
    )(),
    1,
  );
  assert.throws(() =>
    method(
      Object.defineProperty({}, 'get', {
        get() {
          throw new Error('Accessor invoked');
        },
      }),
      'get',
    ),
  );
  assert.throws(() => method({}, 'get'));
  assert.throws(() => method(null, 'get'));
});
test('LDAP empty or NUL passwords never bind and invalid request objects never reach providers', async () => {
  const f = fixture(),
    service = createLdapService(f.settings);
  for (const password of ['', '\0', 'x\0y'])
    assert.equal(await service.verifyCredentials({ username: 'alice' }, password), false);
  assert.throws(() => service.findUser({ username: 'alice', url: 'ldaps://foreign' } as never));
  assert.throws(() =>
    service.search({
      baseDn: f.settings.baseDn,
      filter: { template: '(uid={name})', values: { name: 'a' } },
      attributes: ['userPassword'],
    }),
  );
  await assert.rejects(service.verifyCredentials({ username: 'a' }, 42 as never));
  assert.equal(f.state.calls, 0);
});
test('LDAP rejects forged signals and pre-abort without provider or network activity', async () => {
  const f = fixture(),
    service = createLdapService(f.settings),
    controller = new AbortController();
  controller.abort();
  await assert.rejects(service.ping({ signal: controller.signal }), code('EK_ABORTED'));
  await assert.rejects(
    service.verifyCredentials({ username: 'a' }, '', { signal: controller.signal }),
    code('EK_ABORTED'),
  );
  assert.throws(() => service.ping({ signal: {} as AbortSignal }));
  const forged = new AbortController().signal;
  Object.defineProperty(forged, 'aborted', { value: false });
  assert.throws(() => service.ping({ signal: forged }));
  assert.equal(f.state.calls, 0);
});
test('LDAP provider errors are sanitized and provider-owned bytes are never erased', async () => {
  const f = fixture();
  f.state.unavailable = true;
  await assert.rejects(createLdapService(f.settings).ping(), (error: unknown) => {
    assert.ok(error instanceof KitError);
    assert.equal(error.code, 'EK_LDAP_BIND');
    assert.equal(JSON.stringify(error).includes(f.password), false);
    return true;
  });
  f.state.unavailable = false;
  await assert.rejects(createLdapService(f.settings).ping(), code('EK_LDAP_CONNECT'));
  assert.equal(f.bytes.toString(), f.password);
});
test('LDAP deadlines retain finite admission until an uncooperative secret provider actually settles', async () => {
  const f = fixture();
  let release!: () => void;
  f.state.hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  const service = createLdapService(f.settings),
    requests = Array.from({ length: 4 }, () => service.ping({ timeoutMs: 20 }));
  const settled = Promise.allSettled(requests);
  assert.throws(() => service.ping(), code('EK_BACKEND_UNAVAILABLE'));
  const outcomes = await settled;
  assert.ok(
    outcomes.every((item) => item.status === 'rejected' && code('EK_TIMEOUT')(item.reason)),
  );
  assert.throws(() => service.ping(), code('EK_BACKEND_UNAVAILABLE'));
  release();
  await delay(10);
  f.state.hold = undefined;
  await assert.rejects(service.ping(), code('EK_LDAP_CONNECT'));
  assert.equal(f.state.calls, 6);
});
test('LDAP native connection timeout physically closes a stalled owned socket', async () => {
  let accepted = false;
  const sockets = new Set<import('node:net').Socket>(),
    server = createServer((socket) => {
      accepted = true;
      sockets.add(socket);
      socket.resume();
      socket.once('close', () => sockets.delete(socket));
    });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const f = fixture(),
      service = createLdapService({ ...f.settings, url: 'ldaps://127.0.0.1:' + address.port });
    await assert.rejects(service.ping({ timeoutMs: 1000 }), code('EK_TIMEOUT'));
    assert.equal(accepted, true);
    for (let i = 0; sockets.size && i < 50; i++) await delay(10);
    assert.equal(sockets.size, 0);
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
test('LDAP plugin shares core readiness and shutdown and rejects environment mismatches', async () => {
  const f = fixture(),
    logs: string[] = [],
    destination = new Writable({
      write(chunk: Buffer, _encoding, done) {
        logs.push(chunk.toString());
        done();
      },
    });
  const app = await createApplication({
    service: { name: 'ldap-fixture', version: '1.0.0', environment: 'test' },
    plugins: [loggingPlugin({ destination }), ldapPlugin(f.settings)],
  });
  try {
    await app.start();
    const service = app.resolve<LdapService>(LDAP_CAPABILITY);
    await assert.rejects(service.ping());
    await app.stop();
    assert.throws(() => service.ping(), code('EK_RESOURCE_CLOSED'));
    assert.equal(logs.join('').includes(f.password), false);
  } finally {
    await app.stop();
    destination.destroy();
  }
  const mismatch = await createApplication({
    service: { name: 'ldap-fixture', version: '1.0.0', environment: 'test' },
    plugins: [
      loggingPlugin({
        destination: new Writable({
          write(_chunk, _encoding, done) {
            done();
          },
        }),
      }),
      ldapPlugin({ ...f.settings, environment: 'production' }),
    ],
  });
  await assert.rejects(mismatch.start());
  await mismatch.stop();
});
test('LDAP search is lazy, single-pass and validates policy before starting native work', async () => {
  const f = fixture(),
    service = createLdapService(f.settings),
    iterable = service.search({
      baseDn: f.settings.baseDn,
      filter: { template: '(uid={name})', values: { name: 'alice' } },
      attributes: ['uid'],
    });
  assert.equal(f.state.calls, 0);
  const iterator = iterable[Symbol.asyncIterator]();
  assert.throws(() => iterable[Symbol.asyncIterator]());
  await iterator.return!();
  assert.deepEqual(await iterator.next(), { done: true, value: undefined });
  assert.equal(f.state.calls, 0);
});

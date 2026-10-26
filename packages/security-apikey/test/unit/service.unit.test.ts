// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { KitError, COMPONENTS, createApplication } from '@arkenivajs/core';
import { APIKEY_CAPABILITY } from '../../dist/index.js';
import type { ApiKeyService } from '../../dist/index.js';
import { apiKeyPlugin } from '../../dist/index.js';
import type { ApiKeyPluginSettings, IdentitySubject } from '../../dist/index.js';
import { application, fixtureSettings, grant } from './fixture.js';
import type { TenantId, Telemetry } from '@arkenivajs/core';
import { createTelemetry } from '@arkenivajs/telemetry';
import { loggingPlugin } from '@arkenivajs/logging';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { snapshot, policy as validatePolicy, strings } from '../../dist/validation.js';

const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
test('API keys issue once, retain only keyed verifiers and return immutable metadata without secrets', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, grant());
    assert.match(issued.value, new RegExp('^ak1\\.' + issued.id + '\\.[A-Za-z0-9_-]{43}$'));
    assert.equal(Buffer.from(issued.value.split('.')[2]!, 'base64url').length, 32);
    assert.ok(!JSON.stringify([...f.rows.values()]).includes(issued.value.split('.')[2]!));
    const result = await keys.verify(issued.value, {});
    assert.deepEqual(result.subject, f.owner);
    assert.deepEqual(result.scopes, ['orders.read']);
    assert.equal(result.keyId, issued.id);
    const listed = await keys.list(f.owner);
    assert.equal(listed.length, 1);
    assert.ok(Object.isFrozen(listed));
    assert.ok(Object.isFrozen(listed[0]?.scopes));
    assert.equal('value' in listed[0]!, false);
    assert.equal('digest' in listed[0]!, false);
  } finally {
    await app.stop();
  }
});
test('API key policy approval rejects forged accounts, anonymous management and unauthorized scope grants', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    f.state.authenticated = false;
    await assert.rejects(keys.issue({ ...f.owner }, grant()), code('EK_APIKEY_INVALID'));
    await assert.rejects(keys.list({ ...f.owner }), code('EK_APIKEY_INVALID'));
    f.state.authenticated = true;
    await assert.rejects(
      keys.issue({ ...f.owner, subject: randomUUID() }, grant()),
      code('EK_APIKEY_INVALID'),
    );
    await assert.rejects(keys.issue(f.owner, grant(['admin'])), code('EK_APIKEY_INVALID'));
    assert.equal(f.rows.size, 0);
    const issued = await keys.issue(f.owner, grant());
    f.state.authenticated = false;
    await assert.rejects(keys.rotate(issued.id, f.owner), code('EK_APIKEY_INVALID'));
    await assert.rejects(keys.revoke(issued.id, f.owner), code('EK_APIKEY_INVALID'));
    assert.equal((await keys.verify(issued.value, {})).keyId, issued.id);
    f.state.enabled = false;
    await assert.rejects(keys.verify(issued.value, {}), code('EK_APIKEY_INVALID'));
  } finally {
    await app.stop();
  }
});
test('API key negative lookups and wrong secrets perform an HMAC check without trusting the public prefix', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, grant()),
      before = f.state.hmacChecks;
    for (const raw of [
      'malformed',
      issued.keyPrefix + '.' + randomBytes(32).toString('base64url'),
      'ak1.' + randomUUID() + '.' + randomBytes(32).toString('base64url'),
      issued.value.toUpperCase(),
    ])
      await assert.rejects(keys.verify(raw, {}), code('EK_APIKEY_INVALID'));
    assert.equal(f.state.hmacChecks - before, 4);
    assert.equal((await keys.verify(issued.value, {})).keyId, issued.id);
  } finally {
    await app.stop();
  }
});
test('API key rotation invalidates the old credential atomically and revocation has no cached acceptance', async () => {
  const f = fixtureSettings(),
    first = await application(f.settings),
    second = await application(f.settings);
  try {
    const issued = await first.keys.issue(f.owner, grant()),
      rotated = await second.keys.rotate(issued.id, f.owner);
    assert.notEqual(rotated.id, issued.id);
    assert.notEqual(rotated.value, issued.value);
    await assert.rejects(first.keys.verify(issued.value, {}), code('EK_APIKEY_INVALID'));
    assert.equal((await first.keys.verify(rotated.value, {})).keyId, rotated.id);
    await first.keys.revoke(rotated.id, f.owner);
    await assert.rejects(second.keys.verify(rotated.value, {}), code('EK_APIKEY_INVALID'));
    await second.keys.revoke(rotated.id, f.owner);
    assert.deepEqual(await second.keys.list(f.owner), []);
  } finally {
    await first.app.stop();
    await second.app.stop();
  }
});
test('API key quota and rotation races admit one transactional winner across separate instances', async () => {
  const f = fixtureSettings();
  const settings = { ...f.settings, maxActiveKeysPerSubject: 1 },
    a = await application(settings),
    b = await application(settings);
  try {
    const issued = await Promise.allSettled([
      a.keys.issue(f.owner, grant()),
      b.keys.issue(f.owner, grant()),
    ]);
    assert.equal(issued.filter((x) => x.status === 'fulfilled').length, 1);
    const first = issued.find((x) => x.status === 'fulfilled')!;
    assert.equal(first.status, 'fulfilled');
    const rotations = await Promise.allSettled([
      a.keys.rotate(first.value.id, f.owner),
      b.keys.rotate(first.value.id, f.owner),
    ]);
    assert.equal(rotations.filter((x) => x.status === 'fulfilled').length, 1);
    assert.equal((await a.keys.list(f.owner)).length, 1);
    await assert.rejects(b.keys.verify(first.value.value, {}));
    await assert.rejects(a.keys.issue(f.owner, grant()));
  } finally {
    await a.app.stop();
    await b.app.stop();
  }
});
test('API key source-network policy uses native IPv4 and IPv6 subnet checks and requires a trusted client address', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, {
      ...grant(),
      allowedIpRanges: ['192.0.2.0/24', '2001:db8::/32'],
    });
    for (const clientIp of ['192.0.2.15', '2001:db8::2', '2001:db8:ffff::1'])
      assert.equal((await keys.verify(issued.value, { clientIp })).keyId, issued.id);
    for (const context of [{}, { clientIp: '198.51.100.2' }, { clientIp: '2001:db9::1' }])
      await assert.rejects(keys.verify(issued.value, context), code('EK_APIKEY_INVALID'));
    for (const clientIp of [
      'fe80::1%eth0',
      '::ffff:192.0.2.15',
      '0:0:0:0:0:ffff:c000:020f',
      '127.000.0.1',
    ])
      await assert.rejects(keys.verify(issued.value, { clientIp }), code('EK_CONFIG_INVALID'));
    await assert.rejects(
      keys.issue(f.owner, { ...grant(), allowedIpRanges: ['192.0.2.0/33'] }),
      code('EK_CONFIG_INVALID'),
    );
  } finally {
    await app.stop();
  }
});
test('API key HMAC rotation retains active verifiers and a stable domain-separated owner index', async () => {
  const f = fixtureSettings(),
    a = await application(f.settings);
  try {
    const issued = await a.keys.issue(f.owner, grant());
    f.rotateHmac();
    assert.equal((await a.keys.verify(issued.value, {})).keyId, issued.id);
    assert.equal((await a.keys.list(f.owner)).length, 1);
    const rotated = await a.keys.rotate(issued.id, f.owner);
    assert.equal((await a.keys.verify(rotated.value, {})).keyId, rotated.id);
  } finally {
    await a.app.stop();
  }
});
test('API key verification has one shared finite attempt budget across instances and guessed identifiers', async () => {
  const f = fixtureSettings(),
    settings = { ...f.settings, maxVerifyAttemptsPerMinute: 2 },
    a = await application(settings),
    b = await application(settings);
  try {
    const issued = await a.keys.issue(f.owner, grant());
    await assert.rejects(a.keys.verify('missing', {}));
    await assert.rejects(
      b.keys.verify('ak1.' + randomUUID() + '.' + randomBytes(32).toString('base64url'), {}),
    );
    const before = f.state.hmacChecks;
    await assert.rejects(a.keys.verify(issued.value, {}), code('EK_APIKEY_INVALID'));
    assert.equal(f.state.hmacChecks, before);
  } finally {
    await a.app.stop();
    await b.app.stop();
  }
});
test('API key factories reject incomplete stores, getters, unsafe settings and test providers outside test', async () => {
  const f = fixtureSettings();
  let called = 0;
  const getter = Object.defineProperty({}, 'store', {
    get() {
      called++;
      throw new Error('Getter must not execute');
    },
  });
  for (const input of [
    getter,
    { ...f.settings, unknown: true },
    { ...f.settings, maxActiveKeysPerSubject: 0 },
    { ...f.settings, maxVerifyAttemptsPerMinute: 1.5 },
    { ...f.settings, store: { ...f.settings.store, operationTimeoutMs: 0 } },
    { ...f.settings, store: { ...f.settings.store, store: { read: async () => null } } },
    { ...f.settings, hmac: { ...f.settings.hmac, algorithm: 'SHA256' } },
  ])
    assert.throws(() => apiKeyPlugin(input as ApiKeyPluginSettings), code('EK_CONFIG_INVALID'));
  assert.equal(called, 0);
  for (const environment of ['production', 'development'] as const)
    await assert.rejects(
      application(
        { ...f.settings, store: { ...f.settings.store, securityLevel: 'production' } },
        { service: { name: 'apikey-fixture', version: '1.0.0', environment } },
      ),
    );
});
test('API key validation rejects accessors, invalid dates, unknown options and zero deadlines before persistence', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    let getters = 0;
    const accessor = Object.defineProperty({}, 'scopes', {
      get() {
        getters++;
        return ['admin'];
      },
    });
    for (const value of [
      accessor,
      { ...grant(), expiresAt: '2026-02-30T00:00:00Z' },
      { ...grant(), scopes: Array(1) },
      { ...grant(), allowedIpRanges: [] },
      { ...grant(), scopes: ['admin', 'admin'] },
      { ...grant(), scope: 'admin' },
    ])
      await assert.rejects(keys.issue(f.owner, value as never), code('EK_CONFIG_INVALID'));
    for (const options of [
      { timeoutMs: 0 },
      { timeoutMs: 5001 },
      { timeoutMs: 1.2 },
      { signal: {} },
      { now: 0 },
    ])
      await assert.rejects(keys.list(f.owner, options as never), code('EK_CONFIG_INVALID'));
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(keys.list(f.owner, { signal: controller.signal }), code('EK_ABORTED'));
    assert.equal(getters, 0);
    assert.equal(f.rows.size, 0);
    await assert.rejects(
      keys.issue(f.owner, { ...grant(), expiresAt: '2020-01-01T00:00:00Z' }),
      code('EK_APIKEY_EXPIRED'),
    );
  } finally {
    await app.stop();
  }
});
test('API key provider outages and uncertain commits cannot yield authority or expose private causes', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, grant());
    f.state.fail = true;
    for (const operation of [
      () => keys.verify(issued.value, {}),
      () => keys.rotate(issued.id, f.owner),
      () => keys.revoke(issued.id, f.owner),
    ])
      await assert.rejects(operation(), (error) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_APIKEY_STORE');
        assert.equal(error.cause, undefined);
        assert.ok(!JSON.stringify(error.toSafeJSON()).includes('Private'));
        return true;
      });
    f.state.fail = false;
    assert.equal((await keys.verify(issued.value, {})).keyId, issued.id);
  } finally {
    await app.stop();
  }
});
test('API key closed handles and isolated applications retain no global credential state', async () => {
  const f = fixtureSettings(),
    other = fixtureSettings(),
    a = await application(f.settings),
    b = await application(other.settings);
  const issued = await a.keys.issue(f.owner, grant());
  try {
    await assert.rejects(b.keys.verify(issued.value, {}), code('EK_APIKEY_INVALID'));
    await a.app.stop();
    await assert.rejects(a.keys.list(f.owner), code('EK_RESOURCE_CLOSED'));
  } finally {
    await a.app.stop();
    await b.app.stop();
  }
});
test('API key authority cannot substitute a different account after checking a caller-built subject', async () => {
  const f = fixtureSettings(),
    settings = {
      ...f.settings,
      authority: {
        async require() {
          return { ...f.owner, subject: randomUUID() } as IdentitySubject;
        },
      },
    },
    { app, keys } = await application(settings);
  try {
    await assert.rejects(keys.issue(f.owner, grant()), code('EK_APIKEY_INVALID'));
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
  }
});

test('API key account indexes and authorization cannot cross runtime-verified tenant boundaries', async () => {
  const f = fixtureSettings(),
    identity = {
      issuer: f.owner.issuer,
      subject: f.owner.subject,
      audience: ['fixture'],
      scopes: [],
      claims: { private: 'Do not persist arbitrary claims' },
    };
  const tenant = (name: string): IdentitySubject => ({
    ...f.owner,
    tenant: {
      tenantId: name as TenantId,
      identity,
      verifiedAt: new Date().toISOString(),
      source: 'oidc',
    },
  });
  const a = tenant('tenant-a'),
    b = tenant('tenant-b');
  let current = 'tenant-a';
  const settings = {
    ...f.settings,
    authority: {
      async require(_action: string, hint: IdentitySubject | undefined) {
        if (
          !f.state.authenticated ||
          hint?.tenant?.tenantId !== current ||
          hint.issuer !== f.owner.issuer ||
          hint.subject !== f.owner.subject
        )
          throw new Error('Independent tenant policy denied');
        return current === 'tenant-a' ? a : b;
      },
    },
  };
  const { app, keys } = await application(settings);
  try {
    const issued = await keys.issue(a, grant());
    assert.ok(!JSON.stringify([...f.rows.values()]).includes('Do not persist arbitrary claims'));
    current = 'tenant-b';
    const other = await keys.issue(b, grant());
    assert.equal((await keys.list(b))[0]?.id, other.id);
    await assert.rejects(keys.list({ ...a }), code('EK_APIKEY_INVALID'));
    await assert.rejects(keys.rotate(issued.id, b), code('EK_APIKEY_INVALID'));
    await assert.rejects(keys.revoke(issued.id, b), code('EK_APIKEY_INVALID'));
    await assert.rejects(keys.verify(issued.value, {}), code('EK_APIKEY_INVALID'));
    current = 'tenant-a';
    assert.equal((await keys.verify(issued.value, {})).subject.tenant?.tenantId, 'tenant-a');
    assert.equal((await keys.list(a)).length, 1);
  } finally {
    await app.stop();
  }
});
test('API key absolute expiry uses the server clock and cannot be overridden by operation input', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, grant());
    t.mock.timers.tick(60001);
    await assert.rejects(keys.verify(issued.value, {}), code('EK_APIKEY_INVALID'));
    assert.equal((await keys.list(f.owner)).length, 0);
    await assert.rejects(
      keys.verify(issued.value, {}, { now: 0 } as never),
      code('EK_CONFIG_INVALID'),
    );
  } finally {
    await app.stop();
  }
});
test('API key cancellation retains finite permits until uncooperative providers settle and close prevents late authority', async () => {
  const f = fixtureSettings();
  let release!: () => void,
    entered = 0,
    ready!: () => void;
  const held = new Promise<void>((resolve) => {
      release = resolve;
    }),
    allEntered = new Promise<void>((resolve) => {
      ready = resolve;
    });
  f.settings.authority.require = async () => {
    if (++entered === 32) ready();
    await held;
    return f.owner;
  };
  const { app, keys } = await application(f.settings),
    controller = new AbortController();
  try {
    const pending = Array.from({ length: 32 }, () =>
      keys.list(f.owner, { signal: controller.signal }),
    );
    const rejected = pending.map((promise) => assert.rejects(promise, code('EK_ABORTED')));
    await allEntered;
    await assert.rejects(keys.list(f.owner), code('EK_BACKEND_UNAVAILABLE'));
    controller.abort();
    await Promise.all(rejected);
    await assert.rejects(keys.list(f.owner), code('EK_BACKEND_UNAVAILABLE'));
    await app.stop();
    release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    await assert.rejects(keys.list(f.owner), code('EK_RESOURCE_CLOSED'));
  } finally {
    release();
    await app.stop();
  }
});
test('API key late durable commits report uncertainty and never return a timed-out one-time secret', async () => {
  const f = fixtureSettings(),
    commit = f.store.atomicBatch.bind(f.store);
  let release!: () => void, entered!: () => void;
  const held = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      entered = resolve;
    });
  f.store.atomicBatch = async (mutations) => {
    entered();
    await held;
    return commit(mutations);
  };
  const { app, keys } = await application(f.settings),
    controller = new AbortController();
  try {
    const pending = keys.issue(f.owner, grant(), { signal: controller.signal });
    const rejected = assert.rejects(pending, (error) => {
      assert.ok(error instanceof KitError);
      assert.equal(error.code, 'EK_ABORTED');
      assert.equal(error.details.outcome, 'unknown');
      return true;
    });
    await started;
    controller.abort();
    await rejected;
    release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal((await keys.list(f.owner)).length, 1);
  } finally {
    release();
    await app.stop();
  }
});
test('API key deadline rejects late provider results and authority failures cannot start credential persistence', async () => {
  const f = fixtureSettings();
  f.settings.authority.require = async () => {
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    return f.owner;
  };
  const { app, keys } = await application(f.settings);
  try {
    await assert.rejects(keys.issue(f.owner, grant(), { timeoutMs: 2 }), code('EK_TIMEOUT'));
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
    assert.equal(f.rows.size, 0);
  } finally {
    await app.stop();
  }
});
test('API key malformed durable versions, owner metadata and provider responses fail closed', async () => {
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    const issued = await keys.issue(f.owner, grant()),
      entry = JSON.stringify(['apikey.records.v1', issued.id]),
      original = f.rows.get(entry)!;
    for (const change of [
      { ownerKey: '0'.repeat(64) },
      { version: '' },
      { digest: null },
      { policy: { ...grant(), scopes: ['read', 'read'] } },
      { expiresAt: 'invalid' },
    ]) {
      f.rows.set(entry, { ...original, ...change });
      await assert.rejects(keys.verify(issued.value, {}));
    }
    f.rows.set(entry, original);
    assert.equal((await keys.verify(issued.value, {})).keyId, issued.id);
  } finally {
    await app.stop();
  }
});

test('API key bounded data rejects prototype pollution, deep graphs, malformed Unicode and lossy values', () => {
  const deep = (depth: number): unknown => (depth ? { nested: deep(depth - 1) } : null);
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  const accessor = Object.defineProperty({}, 'value', {
    get() {
      throw new Error('Getter must not execute');
    },
  });
  const arrayAccessor = Object.defineProperty([true], '0', {
    get() {
      throw new Error('Array getter must not execute');
    },
  });
  for (const value of [
    cycle,
    deep(14),
    new Date(),
    { value: undefined },
    { value: 1n },
    { value: -0 },
    { value: NaN },
    { value: '\ud800' },
    { value: '\u0000' },
    { value: 'x'.repeat(8193) },
    { value: Array(129) },
    { value: arrayAccessor },
    accessor,
    JSON.parse('{"__proto__":{}}'),
    Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['x' + i, true])),
    { ['x'.repeat(129)]: true },
    { ['\ud800']: true },
    { [Symbol('private')]: true },
    { value: Array.from({ length: 128 }, () => ({ a: 1, b: 2, c: 3, d: 4 })) },
  ])
    assert.throws(() => snapshot(value), code('EK_CONFIG_INVALID'));
  for (const value of [[], [true], ['read', 'read'], Array(1), ['x'.repeat(129)]]) {
    if (Array.isArray(value) && value.length === 0) assert.deepEqual(strings(value, 64), []);
    else assert.throws(() => strings(value, 64), code('EK_CONFIG_INVALID'));
  }
  for (const allowedIpRanges of [
    ['1.2.3.4'],
    ['::/129'],
    ['192.0.2.0/-1'],
    ['::/01'],
    ['::ffff:c000:0201/120'],
    ['fe80::1%eth0/64'],
  ])
    assert.throws(() => validatePolicy({ ...grant(), allowedIpRanges }), code('EK_CONFIG_INVALID'));
  assert.throws(
    () => validatePolicy({ ...grant(), scopes: ['read space'] }),
    code('EK_CONFIG_INVALID'),
  );
});
test('API key startup rejects malformed provider methods, labels and unavailable HMAC without invoking getters', async () => {
  const f = fixtureSettings();
  let invoked = 0;
  const accessor = () => {
    invoked++;
    throw new Error('Getter must not execute');
  };
  for (const hmac of [
    Object.defineProperty({ ...f.settings.hmac }, 'algorithm', { get: accessor }),
    Object.defineProperty({ ...f.settings.hmac }, 'usage', { get: accessor }),
    { ...f.settings.hmac, usage: 'unknown' },
    { ...f.settings.hmac, verify: null },
  ])
    assert.throws(() => apiKeyPlugin({ ...f.settings, hmac } as never), code('EK_CONFIG_INVALID'));
  assert.equal(invoked, 0);
  const unavailable = {
    ...f.settings.hmac,
    async digest() {
      throw new Error('Private HMAC failure');
    },
  };
  await assert.rejects(application({ ...f.settings, hmac: unavailable }), code('EK_PLUGIN_FAILED'));
  for (const digest of [null, '', 'x'.repeat(2049)])
    await assert.rejects(
      application({
        ...f.settings,
        hmac: {
          ...f.settings.hmac,
          async digest() {
            return digest as string;
          },
        },
      }),
    );
});
test('API key malformed indexed responses, absent backend versions and overflow never produce partial lists', async () => {
  for (const result of [null, Array(5).fill({}), [{}], Array(1)]) {
    const f = fixtureSettings();
    f.store.listByOwner = async () => result as never;
    const { app, keys } = await application(f.settings);
    try {
      await assert.rejects(keys.list(f.owner), code('EK_APIKEY_STORE'));
    } finally {
      await app.stop();
    }
  }
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings);
  try {
    await keys.issue(f.owner, grant());
    const ownerRow = [...f.rows.entries()].find(([, value]) => value.kind === 'api-key-owner-v1')!;
    f.rows.set(ownerRow[0], { ...ownerRow[1], version: '' });
    await assert.rejects(keys.issue(f.owner, grant()), code('EK_APIKEY_STORE'));
  } finally {
    await app.stop();
  }
});
test('API key HMAC verifier must return an actual boolean and authorization is not called after failure', async () => {
  const f = fixtureSettings(),
    hmac = {
      ...f.settings.hmac,
      async verify() {
        return 'true' as never;
      },
    },
    { app, keys } = await application({ ...f.settings, hmac });
  try {
    const issued = await keys.issue(f.owner, grant()),
      before = f.state.calls.length;
    await assert.rejects(keys.verify(issued.value, {}), code('EK_APIKEY_STORE'));
    assert.equal(f.state.calls.length, before);
  } finally {
    await app.stop();
  }
});

test('API key authenticated management shares a finite durable owner budget across instances', async () => {
  const f = fixtureSettings(),
    a = await application(f.settings),
    b = await application(f.settings);
  try {
    await a.keys.list(f.owner);
    const entry = [...f.rows.entries()].find(([key]) =>
      JSON.parse(key)[1].startsWith('management-'),
    )!;
    assert.ok(entry);
    f.rows.set(entry[0], { ...entry[1], count: 1000 });
    await assert.rejects(b.keys.list(f.owner), code('EK_APIKEY_INVALID'));
    await assert.rejects(a.keys.issue(f.owner, grant()), code('EK_APIKEY_INVALID'));
    assert.equal([...f.rows.values()].filter((row) => row.kind === 'api-key-v1').length, 0);
  } finally {
    await a.app.stop();
    await b.app.stop();
  }
});
test('API key actual SDK exports fixed diagnostics while audit logs exclude credentials and account data', async () => {
  const bodies: unknown[] = [],
    lines: string[] = [];
  let total = 0;
  const destination = new Writable({
    write(chunk, _encoding, callback) {
      lines.push(String(chunk));
      callback();
    },
  });
  const receiver = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 4194304) request.destroy();
      else chunks.push(chunk);
    });
    request.on('end', () => {
      bodies.push(JSON.parse(Buffer.concat(chunks).toString()) as unknown);
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{}');
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
  const address = receiver.address();
  assert.ok(address && typeof address !== 'string');
  const service = { name: 'apikey-sdk-fixture', version: '1.0.0', environment: 'test' } as const;
  const telemetry = createTelemetry({
    service,
    mode: 'detailed',
    samplingRatio: 1,
    endpoint: 'http://127.0.0.1:' + address.port,
    allowInsecureLoopback: true,
    exportIntervalMs: 1000,
    exportTimeoutMs: 1000,
  });
  const f = fixtureSettings(),
    { app, keys } = await application(f.settings, {
      service,
      logging: { level: 'info' },
      plugins: [
        loggingPlugin({ destination }),
        apiKeyPlugin(f.settings),
        {
          id: 'apikey-sdk',
          version: '1.0.0',
          capabilities: new Set(['telemetry']),
          init(context) {
            context.provide(COMPONENTS.telemetry, telemetry);
          },
          close() {},
        },
      ],
    });
  try {
    const issued = await keys.issue(f.owner, grant());
    await keys.verify(issued.value, {});
    await assert.rejects(keys.verify('missing', {}));
    await keys.list(f.owner);
    const rotated = await keys.rotate(issued.id, f.owner);
    await keys.revoke(rotated.id, f.owner);
    await telemetry.flush();
    const objects: Record<string, unknown>[] = [];
    const visit = (value: unknown): void => {
      if (!value || typeof value !== 'object') return;
      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }
      objects.push(value as Record<string, unknown>);
      Object.values(value).forEach(visit);
    };
    bodies.forEach(visit);
    for (const name of ['issue', 'verify', 'rotate', 'revoke', 'list']) {
      assert.ok(objects.some((value) => value.name === 'apikey.' + name));
      assert.ok(
        objects.some(
          (value) => value.name === 'apikey.' + name + '.duration' && value.unit === 'ms',
        ),
      );
      assert.ok(objects.some((value) => value.name === 'apikey.' + name + '.completed.ok'));
    }
    assert.ok(objects.some((value) => value.name === 'apikey.verify.completed.error'));
    assert.equal(telemetry.stats().droppedMetrics, 0);
    assert.equal(telemetry.stats().droppedSpans, 0);
    assert.equal(telemetry.stats().exportFailures, 0);
    assert.ok(lines.some((line) => line.includes('API key operation completed')));
    const serialized = JSON.stringify(bodies) + lines.join('');
    for (const secret of [
      issued.value,
      issued.id,
      rotated.value,
      rotated.id,
      f.owner.subject,
      f.owner.issuer,
      ...[...f.rows.values()].filter((row) => row.digest).map((row) => String(row.digest)),
    ])
      assert.equal(serialized.includes(secret), false);
  } finally {
    try {
      await app.stop();
      await telemetry.close();
    } finally {
      receiver.closeAllConnections();
      await new Promise<void>((resolve) => receiver.close(() => resolve()));
      destination.end();
    }
  }
});

test('API key diagnostic failures cannot substitute authorization, stall deadlines or repeat a credential transition', async () => {
  for (const behavior of ['throw', 'substitute', 'repeat', 'hang'] as const) {
    const f = fixtureSettings();
    let writes = 0;
    const commit = f.store.atomicBatch.bind(f.store);
    f.store.atomicBatch = async (mutations) => {
      writes++;
      return commit(mutations);
    };
    const telemetry: Telemetry = {
      async measure(_name, fn) {
        return fn();
      },
      withSpan<T>(_name: string, fn: () => Promise<T> | T): Promise<T> {
        if (behavior === 'throw') throw new Error('Private diagnostic failure');
        if (behavior === 'substitute') return Promise.resolve({ forged: true } as T);
        if (behavior === 'hang') return new Promise<T>(() => undefined);
        const first = Promise.resolve(fn());
        void Promise.resolve(fn()).catch(() => undefined);
        return first;
      },
      addCounter() {
        throw new Error('Private diagnostic counter');
      },
      recordHistogram() {
        throw new Error('Private diagnostic histogram');
      },
      setGauge() {},
      async flush() {},
    };
    const { app, keys } = await application(f.settings, {
      plugins: [
        loggingPlugin(),
        apiKeyPlugin(f.settings),
        {
          id: 'apikey-failing-observer',
          version: '1.0.0',
          capabilities: new Set(['telemetry']),
          init(context) {
            context.provide(COMPONENTS.telemetry, telemetry);
          },
          close() {},
        },
      ],
    });
    try {
      const issued = await keys.issue(f.owner, grant());
      assert.equal(writes, 1);
      assert.equal((await keys.verify(issued.value, {})).keyId, issued.id);
      f.state.enabled = false;
      await assert.rejects(keys.verify(issued.value, {}), code('EK_APIKEY_INVALID'));
      assert.equal(writes, 1);
    } finally {
      await app.stop();
    }
  }
});

test('API key registration rejects duplicates and one reused plugin preserves independent application lifetimes', async () => {
  const f = fixtureSettings(),
    plugin = apiKeyPlugin(f.settings),
    service = { name: 'apikey-lifecycle', version: '1.0.0', environment: 'test' } as const;
  await assert.rejects(
    createApplication({ service, plugins: [loggingPlugin(), plugin, plugin] }),
    code('EK_PLUGIN_DUPLICATE'),
  );
  const a = await createApplication({
      service,
      logging: { level: 'silent' },
      plugins: [loggingPlugin(), plugin],
    }),
    b = await createApplication({
      service,
      logging: { level: 'silent' },
      plugins: [loggingPlugin(), plugin],
    });
  try {
    await a.start();
    await b.start();
    const first = a.resolve<ApiKeyService>(APIKEY_CAPABILITY),
      second = b.resolve<ApiKeyService>(APIKEY_CAPABILITY);
    assert.notEqual(first, second);
    await a.stop();
    await assert.rejects(first.list(f.owner), code('EK_RESOURCE_CLOSED'));
    const issued = await second.issue(f.owner, grant());
    assert.equal((await second.verify(issued.value, {})).keyId, issued.id);
  } finally {
    await a.stop();
    await b.stop();
  }
});

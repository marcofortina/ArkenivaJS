// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import { CRYPTO_CAPABILITY } from '@arkenivajs/security-crypto';
import type { CryptoService } from '@arkenivajs/security-crypto';
import { captureSettings, runtime } from '../../dist/runtime.js';
import { createStateCodec } from '../../dist/state.js';
import { createService } from '../../dist/service.js';
import {
  data,
  id,
  instant,
  integer,
  snapshot,
  strings,
  subject,
  text,
} from '../../dist/validation.js';
import { fixture } from './fixture.js';
import type { OAuthClientPluginSettings } from '../../dist/index.js';

type Fixture = Awaited<ReturnType<typeof fixture>>;
const input = (f: Fixture) => ({
  audience: f.server.audience,
  scopes: ['openid', 'orders.read'],
  returnPath: '/orders',
});
const begin = async (f: Fixture) => {
  const start = await f.first.oauth.beginAuthorization(input(f));
  return { start, callback: await f.server.authorize(start.authorizationUrl) };
};
const rejection = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;

test('OAuth bounded snapshots reject executable, sparse, cyclic and noncanonical authority hints', () => {
  let effects = 0;
  const accessor = Object.defineProperty({}, 'issuer', {
    enumerable: true,
    get() {
      effects++;
      return 'issuer';
    },
  });
  const arrayAccessor = Object.defineProperty([1], '0', {
    get() {
      effects++;
      return 'scope';
    },
  });
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  let deep: unknown = null;
  for (let i = 0; i < 14; i++) deep = { nested: deep };
  for (const value of [
    undefined,
    () => true,
    Symbol(),
    NaN,
    Infinity,
    -0,
    new Date(),
    accessor,
    arrayAccessor,
    new Array(1),
    Array(129).fill(null),
    cycle,
    deep,
    { [Symbol()]: 1 },
    JSON.parse('{"__proto__":1}'),
    { ['x'.repeat(129)]: 1 },
    { ['\0']: 1 },
    { ['\ud800']: 1 },
    { value: '\0' },
    { value: '\ud800' },
    { value: 'x'.repeat(8193) },
    Object.fromEntries(Array.from({ length: 65 }, (_, i) => [String(i), 1])),
    Array.from({ length: 6 }, () => Array(100).fill(1)),
    { a: 'x'.repeat(8192), b: 'x'.repeat(8192) },
  ])
    assert.throws(() => snapshot(value), rejection('EK_CONFIG_INVALID'));
  for (const value of [null, [], accessor, { unknown: true }, { [Symbol()]: true }])
    assert.throws(() => data(value, ['issuer']));
  for (const value of ['', 'a b', '\u007f', '\ud800', 1]) assert.throws(() => text(value));
  for (const value of [0, 1.5, 11, NaN]) assert.throws(() => integer(value, 10));
  for (const value of [
    'invalid',
    '2026-02-30T00:00:00Z',
    '1969-12-31T23:59:59Z',
    '2026-01-01T00:00:00+00:00',
  ])
    assert.throws(() => instant(value));
  assert.equal(instant('2026-01-01T00:00:00Z'), '2026-01-01T00:00:00.000Z');
  assert.throws(() => id('not-a-uuid'));
  id(randomUUID());
  for (const value of [null, new Array(1), arrayAccessor, ['same', 'same'], ['x', 'y']])
    assert.throws(() => strings(value, 1));
  const captured = snapshot({ empty: null, enabled: false, count: 1, list: ['value'] });
  assert.equal(Object.getPrototypeOf(captured), null);
  assert.ok(Object.isFrozen(captured));
  assert.deepEqual(
    { ...(captured as object) },
    {
      empty: null,
      enabled: false,
      count: 1,
      list: ['value'],
    },
  );
  assert.equal(effects, 0);
});

test('OAuth tenant authority hints enforce identity binding, canonical time, claims and assurance', () => {
  const owner = {
    issuer: 'issuer',
    subject: 'subject',
    tenant: {
      tenantId: 'tenant',
      source: 'oidc',
      verifiedAt: '2026-01-01T00:00:00Z',
      identity: {
        issuer: 'issuer',
        subject: 'subject',
        audience: [],
        scopes: [],
        claims: {},
        assurance: 'mfa',
      },
    },
  };
  assert.equal(subject(owner).tenant?.tenantId, 'tenant');
  for (const change of [
    { source: 'unverified' },
    { verifiedAt: 'yesterday' },
    { identity: { ...owner.tenant.identity, issuer: 'foreign' } },
    { identity: { ...owner.tenant.identity, subject: 'foreign' } },
    { identity: { ...owner.tenant.identity, claims: null } },
    { identity: { ...owner.tenant.identity, claims: [] } },
    { identity: { ...owner.tenant.identity, assurance: 'unknown' } },
  ])
    assert.throws(() => subject({ ...owner, tenant: { ...owner.tenant, ...change } }));
});

test('OAuth deployment captures only bounded canonical clients, key separation and complete classified providers', async () => {
  const f = await fixture();
  try {
    const client = f.settings.clients[0]!,
      original = f.server.counts.discovery;
    for (const change of [
      { clients: [] },
      { clients: Array(33).fill(client) },
      { clients: new Array(1) },
      { clients: [client, client] },
      { allowInsecureLoopback: 'true' },
      { stateEncryptionKeyRefs: [] },
      { stateMacKeyRefs: [] },
      { stateEncryptionKeyRefs: f.settings.stateMacKeyRefs },
      { stateStore: { ...f.settings.stateStore, securityLevel: 'unknown' } },
      { stateStore: { ...f.settings.stateStore, operationTimeoutMs: 0 } },
      { secretProvider: { ...f.settings.secretProvider, usage: 'unknown' } },
      { authority: { require: false } },
      {
        authority: Object.defineProperty({}, 'require', {
          get() {
            throw new Error('Executable OAuth authority accessor');
          },
        }),
      },
      { maxStateTtlMs: 600001 },
      { refreshTtlMs: 0 },
      ...[
        { issuer: 'http://untrusted.invalid' },
        { issuer: 'https://issuer.invalid?query=1' },
        { issuer: 'https://user:password@issuer.invalid' },
        { redirectUri: 'https://client.invalid/callback#fragment' },
        { redirectUri: 'https://client.invalid/callback?code=value' },
        { allowedAudiences: [] },
        { allowedScopes: [] },
        { allowedEndpointOrigins: [] },
        { allowedEndpointOrigins: ['https://elsewhere.invalid'] },
        { allowedEndpointOrigins: [new URL(client.issuer).origin + '/'] },
        { idTokenAlgorithm: 'none' },
        { clientSecretRef: '' },
      ].map((patch) => ({ clients: [{ ...client, ...patch }] })),
    ])
      assert.throws(
        () => captureSettings({ ...f.settings, ...change } as OAuthClientPluginSettings),
        rejection('EK_CONFIG_INVALID'),
      );
    assert.equal(f.server.counts.discovery, original);
    const canonical = captureSettings({
      ...f.settings,
      clients: [
        {
          ...client,
          allowedEndpointOrigins: [new URL(client.issuer).origin],
          idTokenAlgorithm: 'RS256',
        },
      ],
      refreshTtlMs: 60000,
    });
    assert.equal(canonical.refreshTtlMs, 60000);
    assert.ok(Object.isFrozen(canonical.clients));
  } finally {
    await f.close();
  }
});

test('OAuth rejects malformed native discovery documents and authentication policy without a token request', async () => {
  const f = await fixture();
  try {
    const baseline = (await fetch(f.server.issuer + '/.well-known/openid-configuration').then(
      (response) => response.json(),
    )) as Record<string, unknown>;
    let deep: unknown = null;
    for (let i = 0; i < 18; i++) deep = { child: deep };
    for (const payload of [
      null,
      [],
      1,
      'metadata',
      { ...baseline, extra: 'x'.repeat(16385) },
      { ...baseline, extra: Array(2049).fill(null) },
      { ...baseline, extra: deep },
      {
        ...baseline,
        extra: Object.fromEntries(Array.from({ length: 257 }, (_, i) => [String(i), null])),
      },
      { ...baseline, extra: Array.from({ length: 2048 }, () => [null, null]) },
      { ...baseline, extra: JSON.parse('{"__proto__":1}') },
      { ...baseline, issuer: 'https://foreign.invalid' },
      { ...baseline, token_endpoint: null },
      { ...baseline, token_endpoint: f.server.issuer + '/token#fragment' },
      {
        ...baseline,
        token_endpoint: f.server.issuer.replace('://', '://user:password@') + '/token',
      },
      { ...baseline, token_endpoint_auth_methods_supported: [] },
      { ...baseline, token_endpoint_auth_methods_supported: 'client_secret_basic' },
      { ...baseline, jwks_uri: null },
      { ...baseline, id_token_signing_alg_values_supported: [] },
      { ...baseline, code_challenge_methods_supported: null },
    ]) {
      f.server.mode.discoveryPayload = payload;
      await assert.rejects(f.instance());
    }
    f.server.mode.discoveryPayload = undefined;
    f.server.mode.discoveryStatus = 503;
    await assert.rejects(f.instance());
    f.server.mode.discoveryStatus = 200;
    const current = await f.instance();
    assert.ok((await current.oauth.beginAuthorization(input(f))).stateRef);
    assert.equal(f.server.counts.token, 0);
  } finally {
    await f.close();
  }
});

test('OAuth malformed persisted authorization metadata and envelope fields cannot reach the token endpoint', async () => {
  const f = await fixture();
  try {
    const { callback } = await begin(f),
      [key, original] = [...f.memory.rows].find(([, row]) => row.kind === 'authorization')!,
      sealed = original.sealed as Record<string, unknown>;
    for (const change of [
      { kind: 'refresh' },
      { id: randomUUID() },
      { status: 'unknown' },
      { ownerKey: 'z'.repeat(64) },
      { digest: 'x' },
      { version: '' },
      { clientId: '' },
      { issuer: '' },
      { audience: '' },
      { encRef: 'unapproved' },
      { macRef: 'unapproved' },
      { familyId: randomUUID() },
      { epoch: 0 },
      { scopes: ['openid', 'openid'] },
      { expiresAt: 'invalid' },
      { owner: { issuer: 'issuer' } },
      ...[
        { version: 2 },
        { algorithm: 'none' },
        { keyId: '' },
        { nonce: '%' },
        { nonce: 'AA' },
        { nonce: 'A'.repeat(17) },
        { tag: 'AB' },
        { tag: 'A'.repeat(22) },
        { ciphertext: '' },
      ].map((value) => ({ sealed: { ...sealed, ...value } })),
    ]) {
      f.memory.rows.set(key, { ...original, ...change });
      await assert.rejects(f.second.oauth.exchangeCode(callback));
      assert.equal(f.server.counts.token, 0);
    }
    f.memory.rows.set(key, original);
    const grant = await f.second.oauth.exchangeCode(callback);
    assert.ok(grant.refreshRef);
    await assert.rejects(f.first.oauth.exchangeCode(callback), rejection('EK_OAUTH_STATE'));
  } finally {
    await f.close();
  }
});

test('OAuth malformed refresh and family records fail closed before an upstream refresh', async () => {
  const f = await fixture();
  try {
    const { callback } = await begin(f),
      grant = await f.first.oauth.exchangeCode(callback);
    for (const kind of ['refresh', 'family']) {
      const [key, original] = [...f.memory.rows].find(([, row]) => row.kind === kind)!;
      for (const change of [
        { familyId: 'invalid' },
        { epoch: -1 },
        { epoch: 1.5 },
        { epoch: Number.MAX_SAFE_INTEGER + 1 },
        ...(kind === 'family' ? [{ familyId: randomUUID() }] : []),
      ]) {
        f.memory.rows.set(key, { ...original, ...change });
        await assert.rejects(f.second.oauth.refresh(grant.refreshRef!));
        assert.equal(f.server.counts.refresh, 0);
      }
      f.memory.rows.set(key, original);
    }
    const family = [...f.memory.rows].find(([, row]) => row.kind === 'family')!;
    f.memory.rows.delete(family[0]);
    await assert.rejects(f.second.oauth.refresh(grant.refreshRef!), rejection('EK_OAUTH_STATE'));
    f.memory.rows.set(...family);
    assert.ok((await f.second.oauth.refresh(grant.refreshRef!)).refreshRef);
  } finally {
    await f.close();
  }
});

test('OAuth current client policy rejects formerly valid encrypted state without consuming its signed grant', async () => {
  const f = await fixture(),
    crypto = f.first.app.resolve<CryptoService>(CRYPTO_CAPABILITY);
  try {
    const { callback } = await begin(f),
      client = f.settings.clients[0]!;
    for (const patch of [
      { id: 'replacement-client' },
      { allowedAudiences: ['https://other.fixture.invalid'] },
      { allowedScopes: ['replacement.scope'] },
    ]) {
      const current = createService(
        captureSettings({ ...f.settings, clients: [{ ...client, ...patch }] }),
        crypto,
        f.first.app.logger,
      );
      try {
        await current.bootstrap(new AbortController().signal);
        await assert.rejects(current.service.exchangeCode(callback), rejection('EK_OAUTH_POLICY'));
        assert.equal(f.server.counts.token, 0);
      } finally {
        await current.close();
      }
    }
    assert.ok((await f.second.oauth.exchangeCode(callback)).refreshRef);
  } finally {
    await f.close();
  }
});

test('OAuth runtime authority output cannot replace a hinted authenticated account or bypass canonical subject validation', async () => {
  const f = await fixture();
  let result: unknown;
  try {
    f.settings.authority.require = async () => result as never;
    const current = await f.instance();
    for (const value of [
      null,
      { issuer: 'missing-subject' },
      { ...f.owner(), subject: randomUUID() },
    ]) {
      result = value;
      await assert.rejects(
        current.oauth.beginAuthorization({ ...input(f), subject: f.owner() }),
        rejection('EK_OAUTH_POLICY'),
      );
      assert.equal(f.server.counts.token, 0);
    }
    result = f.owner();
    assert.ok(
      (await current.oauth.beginAuthorization({ ...input(f), subject: f.owner() })).stateRef,
    );
    await assert.rejects(
      current.oauth.clientCredentials(f.server.audience, []),
      rejection('EK_OAUTH_POLICY'),
    );
  } finally {
    await f.close();
  }
});

test('OAuth unavailable upstream refresh closes the durable family even when subsequent revocation persistence fails', async () => {
  const f = await fixture();
  try {
    const { callback } = await begin(f),
      grant = await f.first.oauth.exchangeCode(callback),
      store = f.memory.store;
    store.bumpOwnerEpoch = async () => {
      throw new Error('Private failed family revocation');
    };
    const current = await f.instance();
    f.server.mode.unavailable = true;
    await assert.rejects(current.oauth.refresh(grant.refreshRef!));
    f.server.mode.unavailable = false;
    const attempts = f.server.counts.refresh;
    await assert.rejects(f.first.oauth.refresh(grant.refreshRef!));
    assert.equal(f.server.counts.refresh, attempts);
  } finally {
    await f.close();
  }
});

test('OAuth malformed budget rows, saturation and eight rejected reservations never issue state', async () => {
  const f = await fixture();
  try {
    await f.first.oauth.beginAuthorization(input(f));
    const [key, original] = [...f.memory.rows].find(([, row]) => row.kind === 'oauth-budget-v1')!;
    for (const change of [
      { kind: 'other' },
      { ownerKey: 'foreign' },
      { minute: -1 },
      { count: -1 },
      { count: 1001 },
      { count: 1.5 },
      { expiresAt: new Date(Date.now() + 1000).toISOString() },
      { version: '' },
    ]) {
      f.memory.rows.set(key, { ...original, ...change });
      await assert.rejects(f.first.oauth.beginAuthorization(input(f)));
    }
    f.memory.rows.set(key, { ...original, count: 1000 });
    await assert.rejects(
      f.first.oauth.beginAuthorization(input(f)),
      rejection('EK_BACKEND_UNAVAILABLE'),
    );
    f.memory.rows.set(key, original);
    const store = f.memory.store,
      originalCas = store.compareAndSet;
    let attempts = 0;
    store.compareAndSet = async (...args) => {
      if (args[0] === 'oauth.budgets.v1') {
        attempts++;
        return { committed: false };
      }
      return originalCas(...args);
    };
    const next = await f.instance();
    await assert.rejects(
      next.oauth.beginAuthorization(input(f)),
      rejection('EK_BACKEND_UNAVAILABLE'),
    );
    assert.equal(attempts, 8);
    assert.equal(f.server.counts.token, 0);
  } finally {
    await f.close();
  }
});

test('OAuth malformed persistence acknowledgments and family epochs cannot return a grant', async () => {
  const f = await fixture();
  try {
    const store = f.memory.store,
      originalCas = store.compareAndSet;
    let mode: 'normal' | 'receipt' | 'batch' | 'epoch' = 'normal';
    store.compareAndSet = async (...args) =>
      mode === 'receipt' && args[0] === 'oauth.authorization.v1'
        ? ({ committed: 'yes' } as never)
        : originalCas(...args);
    const originalBatch = store.atomicBatch,
      originalEpoch = store.currentOwnerEpoch;
    store.atomicBatch = async (...args) =>
      mode === 'batch' ? { committed: false } : originalBatch(...args);
    store.currentOwnerEpoch = async (...args) => (mode === 'epoch' ? -1 : originalEpoch(...args));
    const current = await f.instance();
    mode = 'receipt';
    await assert.rejects(current.oauth.beginAuthorization(input(f)), rejection('EK_OAUTH_STATE'));
    for (const fault of ['batch', 'epoch'] as const) {
      mode = 'normal';
      const start = await current.oauth.beginAuthorization(input(f)),
        callback = await f.server.authorize(start.authorizationUrl);
      mode = fault;
      await assert.rejects(current.oauth.exchangeCode(callback), rejection('EK_OAUTH_STATE'));
      mode = 'normal';
      await assert.rejects(current.oauth.exchangeCode(callback), rejection('EK_OAUTH_STATE'));
    }
  } finally {
    await f.close();
  }
});

test('OAuth state codec rejects malformed cryptographic provider output and unauthenticated plaintext shapes', async () => {
  const f = await fixture(),
    settings = captureSettings(f.settings),
    run = runtime(settings),
    crypto = f.first.app.resolve<CryptoService>(CRYPTO_CAPABILITY),
    codec = createStateCodec(settings, crypto);
  try {
    const { start } = await begin(f),
      row = await run.run(undefined, false, (call) =>
        codec.read('authorization', start.stateRef.split('.')[1]!, call),
      );
    assert.ok(row);
    const { sealed, digest, ownerKey, version, ...meta } = row;
    void sealed;
    void digest;
    void ownerKey;
    void version;
    const native = await crypto.encrypt(Buffer.from('{}'), meta.encRef),
      secret = start.stateRef.split('.')[2]!;
    for (const change of [
      { version: 2 },
      { algorithm: 'none' },
      { keyId: '' },
      { nonce: Buffer.alloc(1) },
      { nonce: new Uint8Array(new SharedArrayBuffer(12)) },
      { tag: false },
      { ciphertext: Buffer.alloc(16385) },
    ]) {
      const broken = createStateCodec(settings, {
        ...crypto,
        async encrypt() {
          return { ...native, ...change } as never;
        },
      });
      await assert.rejects(
        run.run(undefined, false, (call) => broken.make(meta, { value: 'private' }, secret, call)),
      );
    }
    for (const output of [
      false,
      Buffer.alloc(1),
      Buffer.alloc(33),
      new Uint8Array(new SharedArrayBuffer(32)),
    ]) {
      const broken = createStateCodec(settings, {
        ...crypto,
        async hmac() {
          return output as never;
        },
      });
      await assert.rejects(
        run.run(undefined, false, (call) => broken.make(meta, {}, secret, call)),
        rejection('EK_OAUTH_STATE'),
      );
    }
    const nonBoolean = createStateCodec(settings, {
      ...crypto,
      async verifyMac() {
        return 1 as never;
      },
    });
    await assert.rejects(
      run.run(undefined, false, (call) => nonBoolean.prove(row, secret, call)),
      rejection('EK_OAUTH_STATE'),
    );
    for (const output of [
      Buffer.from('null'),
      Buffer.from('[]'),
      Buffer.from('{'),
      Buffer.alloc(16385),
      new Uint8Array(new SharedArrayBuffer(1)),
    ]) {
      const broken = createStateCodec(settings, {
        ...crypto,
        async decrypt() {
          return output as never;
        },
      });
      await assert.rejects(
        run.run(undefined, false, (call) => broken.open(row, call)),
        rejection('EK_OAUTH_STATE'),
      );
    }
    for (const receipt of [null, { committed: 'yes' }, { committed: true, version: '' }])
      assert.throws(() => codec.receipt(receipt));
    await assert.rejects(
      run.run(undefined, false, (call) => codec.familyKey(row, call)),
      rejection('EK_OAUTH_STATE'),
    );
    assert.equal(await run.run(undefined, false, (call) => codec.prove(row, secret, call)), true);
    assert.ok(await run.run(undefined, false, (call) => codec.open(row, call)));
  } finally {
    await run.close();
    await f.close();
  }
});

test('OAuth client secret envelopes fail closed before native authorization or token exchange', async () => {
  const f = await fixture(),
    original = f.settings.secretProvider.get;
  let corrupt: unknown;
  try {
    f.settings.secretProvider.get = async (...args) =>
      args[0] === 'client/secret' ? (corrupt as never) : original(...args);
    const current = await f.instance();
    for (const value of [
      null,
      { bytes: Buffer.alloc(1), keyVersion: '' },
      { bytes: Buffer.alloc(0), keyVersion: randomUUID() },
      { bytes: Buffer.alloc(4097), keyVersion: randomUUID() },
      { bytes: new Uint8Array(new SharedArrayBuffer(32)), keyVersion: randomUUID() },
      { bytes: Buffer.from([0xff]), keyVersion: randomUUID() },
      { bytes: Buffer.from('unsafe\nvalue'), keyVersion: randomUUID() },
      {
        bytes: Buffer.from(f.server.secret),
        keyVersion: randomUUID(),
        expiresAt: new Date(0).toISOString(),
      },
    ]) {
      corrupt = value;
      await assert.rejects(current.oauth.beginAuthorization(input(f)));
      assert.equal(f.server.counts.token, 0);
    }
    corrupt = {
      bytes: Buffer.from(f.server.secret),
      keyVersion: randomUUID(),
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    };
    assert.ok((await current.oauth.beginAuthorization(input(f))).stateRef);
  } finally {
    await f.close();
  }
});

test('OAuth runtime rejects forged signals and sanitizes provider failures while preserving bounded physical ownership', async () => {
  const f = await fixture(),
    run = runtime(captureSettings(f.settings));
  try {
    let calls = 0;
    const work = async () => {
        calls++;
        return true;
      },
      controller = new AbortController();
    controller.abort();
    const overridden = new AbortController().signal;
    Object.defineProperty(overridden, 'reason', { value: 'forged' });
    for (const options of [
      { signal: {} },
      { signal: Object.create(AbortSignal.prototype) },
      { signal: overridden },
      { timeoutMs: 0 },
      { timeoutMs: 5001 },
    ])
      await assert.rejects(run.run(options as never, false, work));
    await assert.rejects(
      run.run({ signal: controller.signal }, false, work),
      rejection('EK_ABORTED'),
    );
    assert.equal(calls, 0);
    await assert.rejects(
      run.run({ timeoutMs: 5 }, false, async (call) => {
        const until = performance.now() + 15;
        while (performance.now() < until) {
          /* Preserve the real monotonic deadline. */
        }
        call.check();
      }),
      rejection('EK_TIMEOUT'),
    );
    for (const write of [false, true])
      await assert.rejects(
        run.run(undefined, write, (call) =>
          call.step('EK_OAUTH_PROVIDER', async () => {
            throw new Error('Private OAuth provider diagnostic');
          }),
        ),
        (error: unknown) => {
          assert.ok(error instanceof KitError);
          assert.equal(error.code, 'EK_OAUTH_PROVIDER');
          assert.equal(JSON.stringify(error).includes('Private OAuth'), false);
          assert.equal(error.details?.outcome, write ? 'unknown' : undefined);
          return true;
        },
      );
    await assert.rejects(
      run.run(undefined, false, async () => {
        throw new Error('Private raw operation failure');
      }),
      rejection('EK_OAUTH_POLICY'),
    );
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = Array.from({ length: 32 }, () => run.run({ timeoutMs: 20 }, true, () => held));
    const outcomes = await Promise.allSettled(pending);
    assert.ok(
      outcomes.every(
        (value) => value.status === 'rejected' && rejection('EK_TIMEOUT')(value.reason),
      ),
    );
    await assert.rejects(run.run(undefined, true, work), rejection('EK_BACKEND_UNAVAILABLE'));
    release();
    await delay(0);
    assert.equal(await run.run(undefined, false, work), true);
    await run.close();
    await assert.rejects(run.run(undefined, false, work), rejection('EK_RESOURCE_CLOSED'));
  } finally {
    await run.close();
    await f.close();
  }
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext, TenantId } from '@arkenivajs/core';
import type { TotpServiceOptions } from '../../dist/index.js';
import { createTotpRuntime } from '../../dist/runtime.js';
import { runtimeFixture as fixture } from '../support/runtime-fixture.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;

test('Runtime provenance and independent strong authorization reject fabricated subjects and grants', async () => {
  const f = fixture(),
    runtime = createTotpRuntime(f.options);
  await runtime.run(undefined, async (call) => {
    assert.equal(await runtime.resolve(f.subject, 'begin-enrollment', call), f.subject);
    await assert.rejects(
      runtime.resolve(Object.freeze({ ...f.subject }), 'verify', call),
      hasCode('EK_AUTH_FORBIDDEN'),
    );
    await assert.rejects(
      runtime.authorize(f.subject, 'enroll', undefined, call),
      hasCode('EK_MFA_POLICY'),
    );
    f.strong.add(f.subject);
    await runtime.authorize(f.subject, 'enroll', undefined, call);
    await runtime.authorize(f.subject, 'replace', undefined, call);
    await assert.rejects(
      runtime.authorize(f.subject, 'disable', undefined, call),
      hasCode('EK_MFA_POLICY'),
    );
    const grant = Object.freeze({
      action: 'disable' as const,
      subject: f.subject.subject,
      trustedSessionId: f.subject.primarySessionId,
      verifiedAt: f.subject.authenticatedAt,
    });
    await assert.rejects(
      runtime.authorize(f.subject, 'disable', grant, call),
      hasCode('EK_MFA_POLICY'),
    );
    f.grants.add(grant);
    await runtime.authorize(f.subject, 'disable', grant, call);
    await assert.rejects(
      runtime.authorize(f.subject, 'disable', { ...grant }, call),
      hasCode('EK_MFA_POLICY'),
    );
    await assert.rejects(
      runtime.authorize(f.subject, 'recovery-codes', grant, call),
      hasCode('EK_MFA_POLICY'),
    );
    f.setTime(Date.parse(f.subject.authenticatedAt) + 60001);
    await assert.rejects(
      runtime.authorize(f.subject, 'disable', grant, call),
      hasCode('EK_MFA_POLICY'),
    );
    f.setTime(Date.parse(f.subject.authenticatedAt) + 300001);
    await assert.rejects(
      runtime.authorize(f.subject, 'enroll', undefined, call),
      hasCode('EK_MFA_POLICY'),
    );
  });
});

test('Subject substitution, accessors and failing policies cannot become an authenticated owner', async () => {
  const f = fixture();
  let invoked = false;
  const accessor = Object.defineProperty({}, 'issuer', {
    enumerable: true,
    get() {
      invoked = true;
      return 'untrusted';
    },
  });
  const runtime = createTotpRuntime(f.options);
  await runtime.run(undefined, async (call) => {
    await assert.rejects(
      runtime.resolve(accessor as MfaSubjectContext, 'verify', call),
      hasCode('EK_MFA_POLICY'),
    );
    assert.equal(invoked, false);
  });
  const substituted = createTotpRuntime({
    ...f.options,
    trustPolicy: {
      ...f.options.trustPolicy,
      async resolveSubject() {
        return Object.freeze({ ...f.subject, primarySessionId: 'session-b' });
      },
    },
  });
  await assert.rejects(
    substituted.run(undefined, (call) => substituted.resolve(f.subject, 'verify', call)),
    hasCode('EK_MFA_POLICY'),
  );
  const failed = createTotpRuntime({
    ...f.options,
    trustPolicy: {
      ...f.options.trustPolicy,
      async resolveSubject() {
        throw new Error('Sensitive synthetic policy diagnostic');
      },
    },
  });
  await assert.rejects(
    failed.run(undefined, (call) => failed.resolve(f.subject, 'verify', call)),
    (error) => {
      assert.equal(hasCode('EK_MFA_POLICY')(error), true);
      assert.equal(JSON.stringify(error).includes('Sensitive synthetic'), false);
      return true;
    },
  );
});

test('Versioned standard HMAC matches an independent vector and separates owners and tenants', async () => {
  const f = fixture(),
    runtime = createTotpRuntime(f.options);
  await runtime.run(undefined, async (call) => {
    const code = 'first.synthetic-recovery';
    assert.equal(await runtime.activeRecoveryKey(call), 'first');
    const hash = await runtime.recoveryHash(f.subject, 'first', code, call);
    assert.equal(hash, 'first:26381c5ad2ac384f340ea936589ad8da172f0b5661a6b4a14b083118a8d5d2cd');
    for (const change of [{ issuer: 'https://foreign.example.test' }, { subject: 'other-account' }])
      assert.notEqual(
        await runtime.recoveryHash({ ...f.subject, ...change }, 'first', code, call),
        hash,
      );
    const identity = Object.freeze({
      subject: f.subject.subject,
      issuer: f.subject.issuer,
      audience: [],
      scopes: [],
      claims: {},
    });
    const tenant = {
      tenantId: 'tenant-a' as TenantId,
      identity,
      verifiedAt: f.subject.authenticatedAt,
      source: 'oidc',
    } as const;
    const a = { ...f.subject, tenant: Object.freeze(tenant) } as MfaSubjectContext;
    const b = {
      ...f.subject,
      tenant: Object.freeze({ ...tenant, tenantId: 'tenant-b' as TenantId }),
    } as MfaSubjectContext;
    assert.notEqual(
      await runtime.recoveryHash(a, 'first', code, call),
      await runtime.recoveryHash(b, 'first', code, call),
    );
    f.rotate();
    assert.equal(await runtime.activeRecoveryKey(call), 'second');
    assert.notEqual(await runtime.recoveryHash(f.subject, 'second', code, call), hash);
    assert.equal(await runtime.recoveryHash(f.subject, 'first', code, call), hash);
    assert.equal(
      f.keys.get('first')!.every((value) => value === 11),
      true,
    );
    f.keys.delete('first');
    await assert.rejects(
      runtime.recoveryHash(f.subject, 'first', code, call),
      hasCode('EK_MFA_STORAGE'),
    );
    f.keys.set('short', new Uint8Array(31));
    await assert.rejects(
      runtime.recoveryHash(f.subject, 'short', code, call),
      hasCode('EK_MFA_STORAGE'),
    );
  });
});

test('Production rejects every test-only component, injected clocks and incomplete configuration', () => {
  const f = fixture();
  const { clock: _clock, ...withoutClock } = f.options;
  void _clock;
  const production: TotpServiceOptions = {
    ...withoutClock,
    environment: 'production',
    stateStore: { ...f.options.stateStore, usage: 'production' },
    rateLimitStore: { ...f.options.rateLimitStore, usage: 'production' },
    secretProtector: { ...f.options.secretProtector, usage: 'production' },
    evidenceStore: { ...f.options.evidenceStore, usage: 'production' },
    trustPolicy: { ...f.options.trustPolicy, usage: 'production' },
    recoveryCodeHmac: {
      algorithm: 'HMAC-SHA256',
      keyProvider: { ...f.options.recoveryCodeHmac.keyProvider, usage: 'production' },
    },
  };
  assert.doesNotThrow(() => createTotpRuntime(production));
  for (const component of [
    'stateStore',
    'rateLimitStore',
    'secretProtector',
    'evidenceStore',
    'trustPolicy',
  ] as const)
    assert.throws(
      () => createTotpRuntime({ ...production, [component]: f.options[component] }),
      hasCode('EK_MFA_POLICY'),
    );
  assert.throws(
    () => createTotpRuntime({ ...production, recoveryCodeHmac: f.options.recoveryCodeHmac }),
    hasCode('EK_MFA_POLICY'),
  );
  assert.throws(
    () => createTotpRuntime({ ...production, clock: Date.now }),
    hasCode('EK_MFA_POLICY'),
  );
  for (const change of [
    { environment: 'unknown' },
    { trustPolicy: undefined },
    { stateStore: undefined },
    { recoveryCodeHmac: { algorithm: 'SHA256' } },
    { clock: () => NaN },
    { periodSeconds: 60 },
    { digits: 8 },
    { driftSteps: 2 },
    { enrollmentTtlMs: 300001 },
  ])
    assert.throws(
      () => createTotpRuntime({ ...f.options, ...change } as TotpServiceOptions),
      hasCode('EK_MFA_POLICY'),
    );
});

test('Provider cancellation/deadlines stop later work and policy configuration is captured once', async () => {
  const f = fixture();
  let released!: (value: MfaSubjectContext) => void,
    writes = 0;
  let entered!: () => void;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const response = new Promise<MfaSubjectContext>((resolve) => {
    released = resolve;
  });
  const trust = {
    ...f.options.trustPolicy,
    resolveSubject: () => {
      entered();
      return response;
    },
  };
  const runtime = createTotpRuntime({ ...f.options, trustPolicy: trust });
  const controller = new AbortController();
  const active = runtime.run({ signal: controller.signal }, async (call) => {
    await runtime.resolve(f.subject, 'verify', call);
    writes++;
  });
  await started;
  controller.abort();
  await assert.rejects(active, hasCode('EK_ABORTED'));
  released(f.subject);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(writes, 0);
  const unavailable = createTotpRuntime({
    ...f.options,
    trustPolicy: {
      ...f.options.trustPolicy,
      resolveSubject: () => new Promise<MfaSubjectContext>(() => {}),
    },
  });
  await assert.rejects(
    unavailable.run({ timeoutMs: 5 }, async (call) => {
      await unavailable.resolve(f.subject, 'verify', call);
      writes++;
    }),
    hasCode('EK_TIMEOUT'),
  );
  assert.equal(writes, 0);
  await assert.rejects(
    runtime.run({ signal: AbortSignal.abort() }, async () => {
      writes++;
    }),
    hasCode('EK_ABORTED'),
  );
  assert.equal(writes, 0);
  const captured = createTotpRuntime(f.options);
  f.options.trustPolicy.resolveSubject = async () => null;
  await captured.run(undefined, async (call) => {
    assert.equal(await captured.resolve(f.subject, 'verify', call), f.subject);
  });
});

test('A mistakenly asynchronous test clock is rejected without an unhandled promise rejection', async () => {
  const f = fixture();
  assert.throws(
    () =>
      createTotpRuntime({
        ...f.options,
        clock: (async () => {
          throw new Error('Synthetic invalid clock');
        }) as unknown as () => number,
      }),
    hasCode('EK_MFA_POLICY'),
  );
  await new Promise<void>((resolve) => setImmediate(resolve));
});

test('Provider methods may be inherited, but missing/accessor methods and late authorization are rejected', async () => {
  const f = fixture(),
    { getFactor, ...other } = f.options.stateStore;
  const inherited = Object.assign(
    Object.create({ getFactor }) as typeof f.options.stateStore,
    other,
  );
  assert.doesNotThrow(() => createTotpRuntime({ ...f.options, stateStore: inherited }));
  assert.throws(
    () => createTotpRuntime({ ...f.options, stateStore: other as typeof f.options.stateStore }),
    hasCode('EK_MFA_POLICY'),
  );
  let invoked = false;
  Object.defineProperty(inherited, 'getFactor', {
    get() {
      invoked = true;
      return getFactor;
    },
  });
  assert.throws(
    () => createTotpRuntime({ ...f.options, stateStore: inherited }),
    hasCode('EK_MFA_POLICY'),
  );
  assert.equal(invoked, false);
  assert.throws(
    () =>
      createTotpRuntime({
        ...f.options,
        clock() {
          throw new Error('Synthetic clock failure');
        },
      }),
    hasCode('EK_MFA_POLICY'),
  );
  const runtime = createTotpRuntime({
    ...f.options,
    trustPolicy: {
      ...f.options.trustPolicy,
      async authorize() {
        f.setTime(Date.parse(f.subject.authenticatedAt) + 300001);
        return true;
      },
    },
  });
  await assert.rejects(
    runtime.run(undefined, (call) => runtime.authorize(f.subject, 'enroll', undefined, call)),
    hasCode('EK_MFA_POLICY'),
  );
});

test('A tenant source object is rejected without invoking primitive coercion hooks', async () => {
  const f = fixture();
  let invoked = false;
  const subject = Object.freeze({
    ...f.subject,
    tenant: Object.freeze({
      tenantId: 'tenant-a',
      identity: Object.freeze({ subject: f.subject.subject, issuer: f.subject.issuer }),
      verifiedAt: f.subject.authenticatedAt,
      source: {
        [Symbol.toPrimitive]() {
          invoked = true;
          return 'oidc';
        },
      },
    }),
  }) as unknown as MfaSubjectContext;
  const runtime = createTotpRuntime(f.options);
  await assert.rejects(
    runtime.run(undefined, (call) => runtime.resolve(subject, 'verify', call)),
    hasCode('EK_MFA_POLICY'),
  );
  assert.equal(invoked, false);
});

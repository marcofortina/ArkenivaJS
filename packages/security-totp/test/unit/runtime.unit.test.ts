// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext } from '@arkenivajs/core';
import type { TotpServiceOptions } from '../../dist/index.js';
import { createTotpRuntime } from '../../dist/runtime.js';
import { runtimeFixture as fixture } from '../support/runtime-fixture.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;

test('Runtime provenance and independent strong authorization reject fabricated subjects and grants', async () => {
  const f = fixture(),
    runtime = createTotpRuntime(f.options);
  await runtime.run(undefined, async (call) => {
    assert.equal(await runtime.resolve(f.subject, call), f.subject);
    await assert.rejects(
      runtime.resolve(Object.freeze({ ...f.subject }), call),
      hasCode('EK_AUTH_FORBIDDEN'),
    );
    await assert.rejects(
      runtime.authorize(f.subject, 'begin-enrollment', undefined, call),
      hasCode('EK_MFA_POLICY'),
    );
    f.strong.add(f.subject);
    await runtime.authorize(f.subject, 'begin-enrollment', undefined, call);
    await runtime.authorize(f.subject, 'confirm-enrollment', undefined, call);
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
      runtime.authorize(f.subject, 'generate-recovery-codes', grant, call),
      hasCode('EK_MFA_POLICY'),
    );
    f.setTime(Date.parse(f.subject.authenticatedAt) + 60001);
    await assert.rejects(
      runtime.authorize(f.subject, 'disable', grant, call),
      hasCode('EK_MFA_POLICY'),
    );
    f.setTime(Date.parse(f.subject.authenticatedAt) + 300001);
    await assert.rejects(
      runtime.authorize(f.subject, 'begin-enrollment', undefined, call),
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
      runtime.resolve(accessor as MfaSubjectContext, call),
      hasCode('EK_MFA_POLICY'),
    );
    assert.equal(invoked, false);
  });
  const substituted = createTotpRuntime({
    ...f.options,
    subjectAuthority: {
      ...f.options.subjectAuthority,
      async resolveSubject() {
        return Object.freeze({ ...f.subject, primarySessionId: 'session-b' });
      },
    },
  });
  await assert.rejects(
    substituted.run(undefined, (call) => substituted.resolve(f.subject, call)),
    hasCode('EK_MFA_POLICY'),
  );
  const failed = createTotpRuntime({
    ...f.options,
    subjectAuthority: {
      ...f.options.subjectAuthority,
      async resolveSubject() {
        throw new Error('Sensitive synthetic policy diagnostic');
      },
    },
  });
  await assert.rejects(
    failed.run(undefined, (call) => failed.resolve(f.subject, call)),
    (error) => {
      assert.equal(hasCode('EK_MFA_POLICY')(error), true);
      assert.equal(JSON.stringify(error).includes('Sensitive synthetic'), false);
      return true;
    },
  );
});

test('Opaque versioned HMAC binds issuer, tenant, owner and active factor without exporting keys', async () => {
  const f = fixture(),
    runtime = createTotpRuntime(f.options);
  const input = {
    issuer: f.subject.issuer,
    subject: f.subject.subject,
    factorId: 'factor-a',
    code: 'synthetic-recovery-code',
  };
  await runtime.run(undefined, async (call) => {
    const hash = await runtime.recoveryVerifier(input, call);
    assert.match(hash, /^v1:first:[a-f0-9]{64}$/);
    for (const change of [
      { issuer: 'foreign' },
      { subject: 'other' },
      { tenantId: 'tenant-a' },
      { factorId: 'factor-b' },
    ])
      assert.notEqual(await runtime.recoveryVerifier({ ...input, ...change }, call), hash);
    f.rotate();
    assert.notEqual(await runtime.recoveryVerifier(input, call), hash);
    assert.equal((await runtime.recoveryCandidates(input, call)).includes(hash), true);
    f.keys.delete('first');
    assert.equal((await runtime.recoveryCandidates(input, call)).includes(hash), false);
    f.keys.delete('second');
    await assert.rejects(runtime.recoveryCandidates(input, call), hasCode('EK_MFA_STORAGE'));
  });
});

test('Recovery provider output is bounded and distinct before durable consumption', async () => {
  const f = fixture(),
    input = {
      issuer: f.subject.issuer,
      subject: f.subject.subject,
      factorId: 'factor',
      code: 'synthetic-plaintext-code',
    };
  for (const values of [
    [],
    Array(9).fill('v1:key:hash'),
    ['same', 'same'],
    [''],
    [input.code],
    [null],
    ['line\nbreak'],
    [42],
  ]) {
    const runtime = createTotpRuntime({
      ...f.options,
      recoveryHmac: {
        ...f.options.recoveryHmac,
        async candidateVerifiers() {
          return values as readonly string[];
        },
      },
    });
    await assert.rejects(
      runtime.run(undefined, (call) => runtime.recoveryCandidates(input, call)),
      hasCode('EK_MFA_STORAGE'),
    );
  }
  const runtime = createTotpRuntime({
    ...f.options,
    recoveryHmac: {
      ...f.options.recoveryHmac,
      async createVerifier() {
        return input.code;
      },
    },
  });
  await assert.rejects(
    runtime.run(undefined, (call) => runtime.recoveryVerifier(input, call)),
    hasCode('EK_MFA_STORAGE'),
  );
  for (const values of [
    Array(1),
    Object.defineProperty([], '0', {
      get() {
        throw new Error('Sensitive synthetic accessor');
      },
    }),
    new Proxy([], {
      get() {
        throw new Error('Sensitive synthetic proxy');
      },
    }),
  ]) {
    const unsafe = createTotpRuntime({
      ...f.options,
      recoveryHmac: {
        ...f.options.recoveryHmac,
        async candidateVerifiers() {
          return values as readonly string[];
        },
      },
    });
    await assert.rejects(
      unsafe.run(undefined, (call) => unsafe.recoveryCandidates(input, call)),
      (error) => {
        assert.equal(String(error).includes('Sensitive synthetic'), false);
        return hasCode('EK_MFA_STORAGE')(error);
      },
    );
  }
});

test('Recovery candidate iteration snapshots its bound once and accepts exactly eight versions', async () => {
  const f = fixture(),
    input = {
      issuer: f.subject.issuer,
      subject: f.subject.subject,
      factorId: 'factor',
      code: 'synthetic-code',
    };
  let lengthReads = 0;
  const dynamic = new Proxy(['v1:key:hash'], {
    get(target, name, receiver) {
      if (name === 'length' && ++lengthReads > 1) throw new Error('Unstable provider length');
      return Reflect.get(target, name, receiver) as unknown;
    },
  });
  for (const values of [
    dynamic,
    Array.from({ length: 8 }, (_, index) => 'v1:key' + index + ':hash'),
  ]) {
    const runtime = createTotpRuntime({
      ...f.options,
      recoveryHmac: {
        ...f.options.recoveryHmac,
        async candidateVerifiers() {
          return values;
        },
      },
    });
    const result = await runtime.run(undefined, (call) => runtime.recoveryCandidates(input, call));
    assert.equal(result.length, values === dynamic ? 1 : 8);
  }
  assert.equal(lengthReads, 1);
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
    subjectAuthority: { ...f.options.subjectAuthority, usage: 'production' },
    recoveryHmac: { ...f.options.recoveryHmac, securityLevel: 'production' },
  };
  assert.doesNotThrow(() => createTotpRuntime(production));
  const { environment: _environment, ...defaultProduction } = production;
  void _environment;
  assert.doesNotThrow(() => createTotpRuntime(defaultProduction));
  for (const environment of ['production', 'development'] as const)
    assert.throws(
      () => createTotpRuntime({ ...production, environment, clock: f.options.clock! }),
      hasCode('EK_MFA_POLICY'),
    );
  for (const recoveryCodeCount of [10, 20])
    assert.equal(
      createTotpRuntime({ ...f.options, recoveryCodeCount }).recoveryCodeCount,
      recoveryCodeCount,
    );
  for (const recoveryCodeCount of [null, 9, 21, 10.5, NaN, Infinity, '10'])
    assert.throws(
      () => createTotpRuntime({ ...f.options, recoveryCodeCount } as TotpServiceOptions),
      hasCode('EK_MFA_POLICY'),
    );
  for (const invalid of [-1, NaN, Infinity, 1.5])
    assert.throws(
      () => createTotpRuntime({ ...f.options, clock: { nowEpochMs: () => invalid } }),
      hasCode('EK_MFA_POLICY'),
    );
  for (const component of [
    'stateStore',
    'rateLimitStore',
    'secretProtector',
    'evidenceStore',
    'subjectAuthority',
  ] as const)
    assert.throws(
      () => createTotpRuntime({ ...production, [component]: f.options[component] }),
      hasCode('EK_MFA_POLICY'),
    );
  assert.throws(
    () => createTotpRuntime({ ...production, recoveryHmac: f.options.recoveryHmac }),
    hasCode('EK_MFA_POLICY'),
  );
  assert.throws(
    () => createTotpRuntime({ ...production, clock: { nowEpochMs: Date.now } }),
    hasCode('EK_MFA_POLICY'),
  );
  for (const change of [
    { environment: 'unknown' },
    { subjectAuthority: undefined },
    { stateStore: undefined },
    { recoveryHmac: { algorithm: 'SHA256' } },
    { clock: { nowEpochMs: () => NaN } },
    { periodSeconds: 60 },
    { digits: 8 },
    { driftSteps: 2 },
    { driftSteps: null },
    { enrollmentTtlMs: null },
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
    ...f.options.subjectAuthority,
    resolveSubject: () => {
      entered();
      return response;
    },
  };
  const runtime = createTotpRuntime({ ...f.options, subjectAuthority: trust });
  const controller = new AbortController();
  const active = runtime.run({ signal: controller.signal }, async (call) => {
    await runtime.resolve(f.subject, call);
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
    subjectAuthority: {
      ...f.options.subjectAuthority,
      resolveSubject: () => new Promise<MfaSubjectContext>(() => {}),
    },
  });
  await assert.rejects(
    unavailable.run({ timeoutMs: 5 }, async (call) => {
      await unavailable.resolve(f.subject, call);
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
  f.options.subjectAuthority.resolveSubject = async () => {
    throw new Error('Changed authority');
  };
  await captured.run(undefined, async (call) => {
    assert.equal(await captured.resolve(f.subject, call), f.subject);
  });
});

test('A mistakenly asynchronous test clock is rejected without an unhandled promise rejection', async () => {
  const f = fixture();
  assert.throws(
    () =>
      createTotpRuntime({
        ...f.options,
        clock: {
          nowEpochMs: (async () => {
            throw new Error('Synthetic invalid clock');
          }) as unknown as () => number,
        },
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
        clock: {
          nowEpochMs() {
            throw new Error('Synthetic clock failure');
          },
        },
      }),
    hasCode('EK_MFA_POLICY'),
  );
  const runtime = createTotpRuntime({
    ...f.options,
    subjectAuthority: {
      ...f.options.subjectAuthority,
      async authorize() {
        f.setTime(Date.parse(f.subject.authenticatedAt) + 300001);
      },
    },
  });
  await assert.rejects(
    runtime.run(undefined, (call) =>
      runtime.authorize(f.subject, 'begin-enrollment', undefined, call),
    ),
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
    runtime.run(undefined, (call) => runtime.resolve(subject, call)),
    hasCode('EK_MFA_POLICY'),
  );
  assert.equal(invoked, false);
});

test('Provider method capture preserves receiver and ignores executable bind/name/length properties', async () => {
  const f = fixture(),
    original = f.options.subjectAuthority.resolveSubject;
  let hooks = 0;
  const authority = {
    ...f.options.subjectAuthority,
    calls: 0,
    async resolveSubject(...args: Parameters<typeof original>) {
      this.calls++;
      return Reflect.apply(original, f.options.subjectAuthority, args);
    },
  };
  for (const field of ['bind', 'name', 'length'])
    Object.defineProperty(authority.resolveSubject, field, {
      configurable: true,
      get() {
        hooks++;
        throw new Error('Executable provider metadata');
      },
    });
  const runtime = createTotpRuntime({ ...f.options, subjectAuthority: authority });
  assert.equal(hooks, 0);
  authority.resolveSubject = async () => {
    throw new Error('The replacement method must not run');
  };
  await runtime.run(undefined, async (call) => {
    assert.equal(await runtime.resolve(f.subject, call), f.subject);
  });
  assert.equal(authority.calls, 1);
  assert.equal(hooks, 0);
});

test('Executable provider objects, prototypes and callable proxies are rejected before traps execute', () => {
  const f = fixture();
  let traps = 0;
  const handler: ProxyHandler<object> = {
    get(target, name, receiver) {
      traps++;
      return Reflect.get(target, name, receiver);
    },
    getPrototypeOf(target) {
      traps++;
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      traps++;
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, name) {
      traps++;
      return Reflect.getOwnPropertyDescriptor(target, name);
    },
  };
  for (const options of [
    new Proxy(f.options, handler),
    { ...f.options, subjectAuthority: new Proxy(f.options.subjectAuthority, handler) },
    {
      ...f.options,
      subjectAuthority: Object.create(new Proxy(f.options.subjectAuthority, handler)),
    },
    {
      ...f.options,
      subjectAuthority: {
        ...f.options.subjectAuthority,
        resolveSubject: new Proxy(f.options.subjectAuthority.resolveSubject, handler),
      },
    },
  ])
    assert.throws(() => createTotpRuntime(options as typeof f.options), hasCode('EK_MFA_POLICY'));
  assert.equal(traps, 0);
});

test('Unverified subject proxy input is rejected without invoking traps or the identity authority', async () => {
  const f = fixture();
  let traps = 0,
    resolutions = 0;
  const runtime = createTotpRuntime({
    ...f.options,
    subjectAuthority: {
      ...f.options.subjectAuthority,
      async resolveSubject(...args) {
        resolutions++;
        return f.options.subjectAuthority.resolveSubject(...args);
      },
    },
  });
  const subject = new Proxy(f.subject, {
    ownKeys(target) {
      traps++;
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, name) {
      traps++;
      return Reflect.getOwnPropertyDescriptor(target, name);
    },
    getPrototypeOf(target) {
      traps++;
      return Reflect.getPrototypeOf(target);
    },
  });
  await assert.rejects(
    runtime.run(undefined, (call) => runtime.resolve(subject, call)),
    hasCode('EK_MFA_POLICY'),
  );
  assert.equal(traps, 0);
  assert.equal(resolutions, 0);
});

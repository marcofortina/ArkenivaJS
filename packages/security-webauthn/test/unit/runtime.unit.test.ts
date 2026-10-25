// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext, OperationOptions, TenantId } from '@arkenivajs/core';
import { runtimeFixture } from '../support/runtime-fixture.js';
import type { WebAuthnServiceOptions, WebAuthnPolicyAction } from '../../dist/contracts.js';
import type { WebAuthnCall } from '../../dist/runtime.js';

import { createWebAuthnRuntime, data, text, instant } from '../../dist/runtime.js';
const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;

test('WebAuthn requires complete runtime providers and never accepts a structural subject as authentication', async () => {
  const f = runtimeFixture(),
    runtime = createWebAuthnRuntime(f.options);
  await runtime.run(undefined, async (call) => {
    assert.equal(await runtime.resolve(f.subject, call), f.subject);
    await assert.rejects(
      runtime.resolve(Object.freeze({ ...f.subject }), call),
      hasCode('EK_AUTH_FORBIDDEN'),
    );
  });
  for (const field of [
    'stateStore',
    'rateLimitStore',
    'evidenceStore',
    'subjectAuthority',
  ] as const) {
    for (const value of [undefined, null, {}])
      assert.throws(
        () => createWebAuthnRuntime({ ...f.options, [field]: value } as WebAuthnServiceOptions),
        hasCode('EK_MFA_POLICY'),
      );
    for (const name of Object.keys(f.options[field])) {
      if (name === 'usage') continue;
      const provider = { ...f.options[field], [name]: null };
      assert.throws(
        () => createWebAuthnRuntime({ ...f.options, [field]: provider } as WebAuthnServiceOptions),
        hasCode('EK_MFA_POLICY'),
      );
    }
  }
});

test('WebAuthn rejects invalid configuration and getters without executing them', () => {
  const f = runtimeFixture();
  let reads = 0;
  for (const value of [
    undefined,
    null,
    [],
    { ...f.options, unknown: true },
    { ...f.options, environment: null },
    { ...f.options, environment: 'other' },
    { ...f.options, userVerification: 'preferred' },
    { ...f.options, attestation: 'indirect' },
    { ...f.options, passwordlessEnabled: 1 },
    ...[0, -1, 0.5, NaN, Infinity, 300001].map((challengeTtlMs) => ({
      ...f.options,
      challengeTtlMs,
    })),
  ])
    assert.throws(
      () => createWebAuthnRuntime(value as WebAuthnServiceOptions),
      hasCode('EK_MFA_POLICY'),
    );
  const getter = {
    ...f.options,
    get rpId() {
      reads++;
      throw new Error('Untrusted getter');
    },
  };
  assert.throws(
    () => createWebAuthnRuntime(getter as unknown as WebAuthnServiceOptions),
    hasCode('EK_MFA_POLICY'),
  );
  const authority = {
    ...f.options.subjectAuthority,
    get authorize() {
      reads++;
      throw new Error('Untrusted getter');
    },
  };
  assert.throws(
    () =>
      createWebAuthnRuntime({
        ...f.options,
        subjectAuthority: authority,
      } as unknown as WebAuthnServiceOptions),
    hasCode('EK_MFA_POLICY'),
  );
  assert.equal(reads, 0);
  for (const length of [1, 65]) {
    const origins = new Array<string>(length).fill('https://example.test');
    Object.defineProperty(origins, '0', {
      get() {
        reads++;
        throw new Error('Untrusted origin getter');
      },
      enumerable: true,
    });
    assert.throws(
      () => createWebAuthnRuntime({ ...f.options, expectedOrigins: origins }),
      hasCode('EK_MFA_POLICY'),
    );
  }
  assert.equal(reads, 0);
  const proxy = new Proxy(
    {},
    {
      ownKeys() {
        throw new Error('Synthetic confidential diagnostic');
      },
    },
  );
  assert.throws(
    () => createWebAuthnRuntime(proxy as WebAuthnServiceOptions),
    (error) => {
      assert.ok(hasCode('EK_MFA_POLICY')(error));
      assert.equal(inspect(error).includes('confidential'), false);
      return true;
    },
  );
});

test('Production defaults reject every test-only provider and every non-test clock override', () => {
  const f = runtimeFixture();
  const production = {
    ...f.options,
    stateStore: { ...f.options.stateStore, ...{ usage: 'production' } },
    rateLimitStore: { ...f.options.rateLimitStore, ...{ usage: 'production' } },
    evidenceStore: { ...f.options.evidenceStore, ...{ usage: 'production' } },
    subjectAuthority: { ...f.options.subjectAuthority, ...{ usage: 'production' } },
  };
  delete production.environment;
  delete production.clock;
  assert.equal(createWebAuthnRuntime(production).challengeTtlMs, 300000);
  for (const field of [
    'stateStore',
    'rateLimitStore',
    'evidenceStore',
    'subjectAuthority',
  ] as const)
    for (const usage of ['test-only', 'unknown', false])
      assert.throws(
        () => createWebAuthnRuntime({ ...production, [field]: { ...production[field], usage } }),
        hasCode('EK_MFA_POLICY'),
      );
  for (const environment of [undefined, 'production', 'development'] as const)
    assert.throws(
      () =>
        createWebAuthnRuntime({
          ...production,
          ...(environment === undefined ? {} : { environment }),
          clock: f.options.clock!,
        }),
      hasCode('EK_MFA_POLICY'),
    );
  assert.equal(
    createWebAuthnRuntime({
      ...f.options,
      challengeTtlMs: 1,
      attestation: 'direct',
      passwordlessEnabled: true,
    }).attestation,
    'direct',
  );
});

test('Invalid, throwing and asynchronous clocks fail closed without leaking diagnostics', async () => {
  const f = runtimeFixture();
  for (const value of [-1, 0.5, NaN, Infinity, 253402300800000]) {
    assert.throws(
      () => createWebAuthnRuntime({ ...f.options, clock: { nowEpochMs: () => value } }),
      hasCode('EK_MFA_POLICY'),
    );
  }
  assert.throws(
    () =>
      createWebAuthnRuntime({
        ...f.options,
        clock: {
          nowEpochMs() {
            throw new Error('Sensitive clock diagnostic');
          },
        },
      }),
    hasCode('EK_MFA_POLICY'),
  );
  assert.throws(
    () =>
      createWebAuthnRuntime({
        ...f.options,
        clock: {
          nowEpochMs: async () => {
            throw new Error('Synthetic async clock');
          },
        } as never,
      }),
    hasCode('EK_MFA_POLICY'),
  );
  const runtime = createWebAuthnRuntime(f.options);
  f.setTime(NaN);
  await assert.rejects(
    runtime.run(undefined, async (call) => call.now()),
    hasCode('EK_MFA_POLICY'),
  );
});

test('Provider methods are captured once, retain their receiver and may be inherited', async () => {
  const f = runtimeFixture();
  class Clock {
    at = f.now();
    nowEpochMs() {
      return this.at;
    }
  }
  const clock = new Clock();
  const runtime = createWebAuthnRuntime({ ...f.options, clock });
  clock.nowEpochMs = () => NaN;
  f.options.subjectAuthority.resolveSubject = async () => {
    throw new Error('Replacement authority');
  };
  await runtime.run(undefined, async (call) => {
    assert.equal(call.now(), clock.at);
    assert.equal(await runtime.resolve(f.subject, call), f.subject);
  });
});

test('Subject, issuer, tenant and primary-session substitution cannot pass a successful authority call', async () => {
  const f = runtimeFixture();
  for (const changes of [
    { issuer: 'foreign' },
    { subject: 'foreign' },
    { primarySessionId: 'foreign' },
    { authenticatedAt: new Date(f.now() - 1).toISOString() },
  ]) {
    const authority = {
      ...f.options.subjectAuthority,
      async resolveSubject() {
        return Object.freeze({ ...f.subject, ...changes });
      },
    };
    const runtime = createWebAuthnRuntime({ ...f.options, subjectAuthority: authority });
    await assert.rejects(
      runtime.run(undefined, (call) => runtime.resolve(f.subject, call)),
      hasCode('EK_MFA_POLICY'),
    );
  }
  const runtime = createWebAuthnRuntime(f.options);
  for (const value of [
    undefined,
    { ...f.subject, tenant: undefined },
    Object.freeze({ ...f.subject, authenticatedAt: new Date(f.now() + 1).toISOString() }),
  ]) {
    if (value) f.authenticated.add(value);
    await assert.rejects(
      runtime.run(undefined, (call) => runtime.resolve(value as MfaSubjectContext, call)),
      hasCode('EK_MFA_POLICY'),
    );
  }
});

test('Each session-bound WebAuthn action is independently authorized and forged grants stay untrusted', async () => {
  const f = runtimeFixture(),
    runtime = createWebAuthnRuntime(f.options);
  const actions: WebAuthnPolicyAction[] = [
    'begin-registration',
    'finish-registration',
    'begin-authentication',
    'finish-authentication',
    'list-credentials',
    'revoke-credential',
  ];
  for (const action of actions) {
    f.denied.add(action);
    await assert.rejects(
      runtime.run(undefined, (call) =>
        runtime.authorize(
          f.subject,
          action,
          action === 'revoke-credential' ? f.grant : undefined,
          call,
        ),
      ),
      hasCode('EK_AUTH_FORBIDDEN'),
    );
    f.denied.clear();
    await runtime.run(undefined, (call) =>
      runtime.authorize(
        f.subject,
        action,
        action === 'revoke-credential' ? f.grant : undefined,
        call,
      ),
    );
  }
  await assert.rejects(
    runtime.run(undefined, (call) =>
      runtime.authorize(f.subject, 'revoke-credential', Object.freeze({ ...f.grant }), call),
    ),
    hasCode('EK_AUTH_FORBIDDEN'),
  );
  f.strong.delete(f.subject);
  await assert.rejects(
    runtime.run(undefined, (call) =>
      runtime.authorize(f.subject, 'begin-registration', undefined, call),
    ),
    hasCode('EK_MFA_ASSURANCE_REQUIRED'),
  );
  assert.equal(f.observed.authorizations.length, 14);
});

test('Recent session and revocation grants are rechecked after asynchronous authorization', async () => {
  const f = runtimeFixture(),
    runtime = createWebAuthnRuntime(f.options);
  for (const grant of [
    undefined,
    { ...f.grant, action: 'disable' },
    { ...f.grant, subject: 'foreign' },
    { ...f.grant, trustedSessionId: 'foreign' },
    { ...f.grant, verifiedAt: new Date(f.now() + 1).toISOString() },
    { ...f.grant, verifiedAt: new Date(f.now() - 60001).toISOString() },
  ])
    await assert.rejects(
      runtime.run(undefined, (call) =>
        runtime.authorize(f.subject, 'revoke-credential', grant as never, call),
      ),
      hasCode('EK_MFA_POLICY'),
    );
  await assert.rejects(
    runtime.run(undefined, (call) =>
      runtime.authorize(f.subject, 'begin-authentication', f.grant, call),
    ),
    hasCode('EK_MFA_POLICY'),
  );
  f.setTime(f.now() + 300001);
  await assert.rejects(
    runtime.run(undefined, (call) =>
      runtime.authorize(f.subject, 'begin-registration', undefined, call),
    ),
    hasCode('EK_MFA_POLICY'),
  );
  const late = runtimeFixture();
  const delayed = createWebAuthnRuntime({
    ...late.options,
    subjectAuthority: {
      ...late.options.subjectAuthority,
      async authorize() {
        late.setTime(late.now() + 60001);
      },
    },
  });
  await assert.rejects(
    delayed.run(undefined, (call) =>
      delayed.authorize(late.subject, 'revoke-credential', late.grant, call),
    ),
    hasCode('EK_MFA_POLICY'),
  );
});

test('Timeout, cancellation and retained calls cannot allow later provider work or leak abort reasons', async () => {
  const f = runtimeFixture(),
    runtime = createWebAuthnRuntime(f.options);
  let calls = 0;
  for (const timeoutMs of [0, -1, 0.5, NaN, Infinity, 120001])
    await assert.rejects(
      runtime.run({ timeoutMs }, async () => {
        calls++;
      }),
      hasCode('EK_MFA_POLICY'),
    );
  for (const operation of [null, { unknown: 1 }, { signal: {} }])
    await assert.rejects(
      runtime.run(operation as OperationOptions, async () => {
        calls++;
      }),
      hasCode('EK_MFA_POLICY'),
    );
  await assert.rejects(
    runtime.run({ signal: AbortSignal.abort(new Error('Sensitive abort reason')) }, async () => {
      calls++;
    }),
    (error) => {
      assert.ok(hasCode('EK_ABORTED')(error));
      assert.equal(inspect(error).includes('Sensitive'), false);
      return true;
    },
  );
  assert.equal(calls, 0);
  await assert.rejects(
    runtime.run({ timeoutMs: 10 }, () => new Promise<void>(() => {})),
    hasCode('EK_TIMEOUT'),
  );
  let retained!: WebAuthnCall;
  await runtime.run(undefined, async (call) => {
    retained = call;
  });
  await assert.rejects(
    retained.call(async () => {
      calls++;
    }),
    hasCode('EK_ABORTED'),
  );
  assert.equal(calls, 0);
});

test('Provider outages, malformed decisions and unexpected authorization results never become permission', async () => {
  const f = runtimeFixture();
  for (const decision of [
    null,
    { allowed: 'yes' },
    { allowed: true, retryAfterMs: 0 },
    { allowed: true, unexpected: 1 },
  ]) {
    const runtime = createWebAuthnRuntime({
      ...f.options,
      rateLimitStore: {
        async checkAndRecord() {
          return decision as never;
        },
      },
    });
    await assert.rejects(
      runtime.run(undefined, (call) => runtime.limit('begin-authentication', f.subject, call)),
      hasCode('EK_MFA_STORAGE'),
    );
  }
  const denied = createWebAuthnRuntime({
    ...f.options,
    rateLimitStore: {
      async checkAndRecord() {
        return { allowed: false, retryAfterMs: 1 };
      },
    },
  });
  await assert.rejects(
    denied.run(undefined, (call) => denied.limit('begin-passwordless', undefined, call)),
    hasCode('EK_MFA_RATE_LIMIT'),
  );
  for (const kind of ['storage', 'policy'] as const) {
    const runtime = createWebAuthnRuntime(f.options);
    await assert.rejects(
      runtime.run(undefined, (call) =>
        call.call(async () => {
          throw new Error('Sensitive provider diagnostic');
        }, kind),
      ),
      (error) => {
        assert.ok(hasCode(kind === 'storage' ? 'EK_MFA_STORAGE' : 'EK_MFA_POLICY')(error));
        assert.equal(inspect(error).includes('Sensitive'), false);
        return true;
      },
    );
  }
  const wrong = createWebAuthnRuntime({
    ...f.options,
    subjectAuthority: { ...f.options.subjectAuthority, authorize: async () => true as never },
  });
  await assert.rejects(
    wrong.run(undefined, (call) => wrong.authorize(f.subject, 'list-credentials', undefined, call)),
    hasCode('EK_MFA_POLICY'),
  );
  await assert.rejects(
    wrong.run(undefined, async () => {
      throw new Error('Sensitive operation diagnostic');
    }),
    hasCode('EK_MFA_STORAGE'),
  );
});

test('Rate-limit buckets separate RP, issuer, owner and tenant without exposing those values', async () => {
  const f = runtimeFixture(),
    runtime = createWebAuthnRuntime(f.options);
  await runtime.run(undefined, async (call) => {
    for (const subject of [
      f.subject,
      { ...f.subject, subject: 'another' },
      { ...f.subject, issuer: 'another' },
      { ...f.subject, tenant: { tenantId: 'another' } as never },
      undefined,
    ])
      await runtime.limit('begin-authentication', subject, call);
  });
  const other = createWebAuthnRuntime({
    ...f.options,
    rpId: 'other.test',
    expectedOrigins: ['https://other.test'],
  });
  await other.run(undefined, (call) => other.limit('begin-authentication', f.subject, call));
  assert.equal(new Set(f.observed.limits.map((entry) => entry.scopeKey)).size, 6);
  for (const entry of f.observed.limits) {
    assert.match(entry.scopeKey, /^[a-f0-9]{64}$/);
    assert.equal(entry.windowMs, 60000);
    assert.equal(entry.nowMs, f.now());
  }
  assert.equal(f.observed.limits[4]!.maxAttempts, 20);
  assert.equal(f.observed.limits[0]!.maxAttempts, 5);
});

test('Passwordless identity resolution is explicitly enabled, pre-session and cannot substitute a credential owner', async () => {
  const f = runtimeFixture();
  const input = {
    rpId: f.options.rpId,
    credentialId: 'synthetic-credential',
    issuer: f.subject.issuer,
    subject: f.subject.subject,
  };
  const disabled = createWebAuthnRuntime(f.options);
  await assert.rejects(
    disabled.run(undefined, (call) => disabled.passwordlessOwner(input, call)),
    hasCode('EK_MFA_POLICY'),
  );
  const enabled = createWebAuthnRuntime({ ...f.options, passwordlessEnabled: true });
  await enabled.run(undefined, async (call) => {
    assert.deepEqual(await enabled.passwordlessOwner(input, call), {
      issuer: input.issuer,
      subject: input.subject,
    });
    assert.deepEqual(
      await enabled.passwordlessOwner({ ...input, tenantId: 'tenant-a', userHandle: null }, call),
      { issuer: input.issuer, subject: input.subject, tenantId: 'tenant-a' },
    );
  });
  assert.equal(f.observed.resolutions, 0);
  assert.equal(f.observed.anonymous, 2);
  for (const changes of [{ subject: 'foreign' }, { issuer: 'foreign' }, { tenantId: 'foreign' }]) {
    const runtime = createWebAuthnRuntime({
      ...f.options,
      passwordlessEnabled: true,
      subjectAuthority: {
        ...f.options.subjectAuthority,
        async resolvePasswordlessSubject() {
          return { issuer: input.issuer, subject: input.subject, ...changes };
        },
      },
    });
    await assert.rejects(
      runtime.run(undefined, (call) => runtime.passwordlessOwner(input, call)),
      hasCode('EK_MFA_POLICY'),
    );
  }
});

test('Data validators reject malformed values and preserve exact UTC timestamps', () => {
  for (const value of ['', '\u0000', 'x'.repeat(1025), 1])
    assert.throws(() => text(value), hasCode('EK_MFA_POLICY'));
  for (const value of ['invalid', '2026-10-25', '2026-10-25T00:00:00Z'])
    assert.throws(() => instant(value), hasCode('EK_MFA_POLICY'));
  assert.equal(instant('2026-10-25T00:00:00.000Z'), Date.UTC(2026, 9, 25));
  assert.equal(Object.getPrototypeOf(data({ safe: 1 }, ['safe'])), null);
  assert.throws(() => data({ [Symbol('untrusted')]: 1 }, []), hasCode('EK_MFA_POLICY'));
});

test('Verified tenant ownership is checked independently from the shape of a frozen tenant object', async () => {
  const f = runtimeFixture();
  const identity = Object.freeze({
    issuer: f.subject.issuer,
    subject: f.subject.subject,
    audience: Object.freeze(['application']),
    scopes: Object.freeze([]),
    claims: Object.freeze({}),
  });
  const tenant = (tenantId: string) =>
    Object.freeze({
      tenantId: tenantId as TenantId,
      identity,
      verifiedAt: f.subject.authenticatedAt,
      source: 'oidc',
    });
  const subject = Object.freeze({ ...f.subject, tenant: tenant('tenant-a') }) as MfaSubjectContext;
  f.authenticated.add(subject);
  const good = createWebAuthnRuntime(f.options);
  await good.run(undefined, async (call) => {
    assert.equal(await good.resolve(subject, call), subject);
  });
  const substituted = createWebAuthnRuntime({
    ...f.options,
    subjectAuthority: {
      ...f.options.subjectAuthority,
      async resolveSubject() {
        return Object.freeze({ ...subject, tenant: tenant('tenant-b') }) as MfaSubjectContext;
      },
    },
  });
  await assert.rejects(
    substituted.run(undefined, (call) => substituted.resolve(subject, call)),
    hasCode('EK_MFA_POLICY'),
  );
  for (const bad of [
    { ...subject },
    Object.freeze({ ...subject, tenant: { ...subject.tenant! } }),
    Object.freeze({
      ...subject,
      tenant: Object.freeze({ ...subject.tenant!, source: 'unverified' }),
    }),
    Object.freeze({
      ...subject,
      tenant: Object.freeze({
        ...subject.tenant!,
        identity: Object.freeze({ ...identity, issuer: 'foreign' }),
      }),
    }),
  ]) {
    f.authenticated.add(bad);
    await assert.rejects(
      good.run(undefined, (call) => good.resolve(bad as MfaSubjectContext, call)),
      hasCode('EK_MFA_POLICY'),
    );
  }
  const forged = Object.freeze({ ...subject });
  await assert.rejects(
    good.run(undefined, (call) => good.resolve(forged, call)),
    hasCode('EK_AUTH_FORBIDDEN'),
  );
});

test('Monotonic deadline guards stop work before a delayed timer can run', async (t) => {
  const f = runtimeFixture(),
    runtime = createWebAuthnRuntime(f.options);
  let elapsed = 0,
    calls = 0;
  t.mock.method(performance, 'now', () => elapsed);
  await assert.rejects(
    runtime.run({ timeoutMs: 10 }, async (call) => {
      elapsed = 11;
      await call.call(async () => {
        calls++;
      });
    }),
    hasCode('EK_TIMEOUT'),
  );
  assert.equal(calls, 0);
});

test('Cancellation during a provider call rejects safely and late completion cannot resume the operation', async () => {
  const f = runtimeFixture(),
    runtime = createWebAuthnRuntime(f.options),
    controller = new AbortController();
  let entered!: () => void,
    complete!: () => void,
    continued = false;
  const ready = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const pending = new Promise<void>((resolve) => {
    complete = resolve;
  });
  const operation = runtime.run({ signal: controller.signal }, async (call) => {
    await call.call(async () => {
      entered();
      await pending;
    });
    continued = true;
  });
  const denied = assert.rejects(operation, hasCode('EK_ABORTED'));
  await ready;
  controller.abort(new Error('Sensitive late-provider diagnostic'));
  await denied;
  complete();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(continued, false);
  const late = runtimeFixture();
  const stale = createWebAuthnRuntime({
    ...late.options,
    subjectAuthority: {
      ...late.options.subjectAuthority,
      async authorize() {
        late.setTime(late.now() + 300001);
      },
    },
  });
  await assert.rejects(
    stale.run(undefined, (call) =>
      stale.authorize(late.subject, 'finish-registration', undefined, call),
    ),
    hasCode('EK_MFA_POLICY'),
  );
});

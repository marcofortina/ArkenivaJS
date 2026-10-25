// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import type { MfaChallengeRecord, MfaSubjectContext, OperationOptions } from '@arkenivajs/core';
import { createWebAuthnRuntime } from '../../dist/runtime.js';
import { issueCeremony, claimCeremony, requireChallenge } from '../../dist/ceremonies.js';
import { readUnverifiedResponse } from '../../dist/browser-response.js';
import { runtimeFixture } from '../support/runtime-fixture.js';
import { authenticator } from '../support/authenticator.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;

/** Test-only atomic map: proves the service protocol, never durability or database conformance. */
function fixture() {
  const f = runtimeFixture(),
    records = new Map<string, MfaChallengeRecord>();
  const calls: OperationOptions[] = [];
  const stateStore = {
    ...f.options.stateStore,
    async createChallenge(record: MfaChallengeRecord, options?: OperationOptions) {
      if (records.has(record.id)) throw new Error('Synthetic duplicate ceremony');
      records.set(record.id, record);
      calls.push(options!);
    },
    async claimChallenge(
      input: Parameters<typeof f.options.stateStore.claimChallenge>[0],
      options?: OperationOptions,
    ) {
      calls.push(options!);
      const value = records.get(input.id);
      if (
        !value ||
        ['purpose', 'rpId', 'issuer', 'subject', 'tenantId', 'primarySessionId'].some(
          (key) => value[key as keyof MfaChallengeRecord] !== input[key as keyof typeof input],
        )
      )
        return null;
      records.delete(input.id);
      return Date.parse(value.expiresAt) <= Date.parse(input.now) ? null : value;
    },
    async discardChallenge(id: string) {
      records.delete(id);
    },
  };
  const options = { ...f.options, stateStore };
  return { ...f, options, records, calls, runtime: createWebAuthnRuntime(options) };
}

test('Ceremony issue stores only a policy-bound digest and returns immutable browser options', async () => {
  const f = fixture();
  await f.runtime.run(undefined, async (call) => {
    const options = await f.runtime.driver.authenticationOptions([authenticator().id]);
    const ceremony = await issueCeremony(
      f.runtime,
      'webauthn-authenticate',
      f.subject,
      options,
      call,
    );
    const record = f.records.get(ceremony.ceremonyId)!;
    assert.equal(Buffer.from(ceremony.ceremonyId, 'base64url').length, 32);
    assert.match(record.challengeDigest, /^[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(record).includes(options.challenge), false);
    assert.equal(record.rpId, f.options.rpId);
    assert.equal(record.issuer, f.subject.issuer);
    assert.equal(record.primarySessionId, f.subject.primarySessionId);
    assert.equal(ceremony.expiresAt, new Date(f.now() + 300000).toISOString());
    assert.equal(ceremony.optionsJSON.timeout, 300000);
    assert.ok(Object.isFrozen(ceremony));
    assert.ok(Object.isFrozen(ceremony.optionsJSON));
    assert.ok(Object.isFrozen(ceremony.optionsJSON.allowCredentials));
    requireChallenge(f.runtime, record, options.challenge);
    const next = await issueCeremony(f.runtime, 'webauthn-authenticate', f.subject, options, call);
    assert.notEqual(next.ceremonyId, ceremony.ceremonyId);
    assert.equal(f.calls[0], call.options);
    assert.equal(f.calls[1], call.options);
  });
});

test('Two independent runtimes can consume one shared ceremony at most once', async () => {
  const f = fixture(),
    other = createWebAuthnRuntime(f.options);
  const ceremony = await f.runtime.run(undefined, async (call) =>
    issueCeremony(
      f.runtime,
      'webauthn-authenticate',
      f.subject,
      await f.runtime.driver.authenticationOptions(),
      call,
    ),
  );
  const results = await Promise.allSettled(
    [f.runtime, other].map((runtime) =>
      runtime.run(undefined, (call) =>
        claimCeremony(runtime, 'webauthn-authenticate', f.subject, ceremony.ceremonyId, call),
      ),
    ),
  );
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  const denied = results.find((result) => result.status === 'rejected');
  assert.ok(denied?.status === 'rejected' && hasCode('EK_MFA_CHALLENGE_EXPIRED')(denied.reason));
  assert.equal(f.records.size, 0);
});

test('Wrong owner, issuer, tenant, session, purpose and RP cannot claim another ceremony', async () => {
  const f = fixture();
  const ceremony = await f.runtime.run(undefined, async (call) =>
    issueCeremony(
      f.runtime,
      'webauthn-register',
      f.subject,
      await f.runtime.driver.registrationOptions(randomBytes(32)),
      call,
    ),
  );
  for (const changes of [
    { subject: 'foreign' },
    { issuer: 'foreign' },
    { primarySessionId: 'foreign' },
    { tenant: { tenantId: 'foreign' } },
  ])
    await assert.rejects(
      f.runtime.run(undefined, (call) =>
        claimCeremony(
          f.runtime,
          'webauthn-register',
          { ...f.subject, ...changes } as MfaSubjectContext,
          ceremony.ceremonyId,
          call,
        ),
      ),
      hasCode('EK_MFA_CHALLENGE_EXPIRED'),
    );
  await assert.rejects(
    f.runtime.run(undefined, (call) =>
      claimCeremony(f.runtime, 'webauthn-authenticate', f.subject, ceremony.ceremonyId, call),
    ),
    hasCode('EK_MFA_CHALLENGE_EXPIRED'),
  );
  const other = createWebAuthnRuntime({
    ...f.options,
    rpId: 'other.test',
    expectedOrigins: ['https://other.test'],
  });
  await assert.rejects(
    other.run(undefined, (call) =>
      claimCeremony(other, 'webauthn-register', f.subject, ceremony.ceremonyId, call),
    ),
    hasCode('EK_MFA_CHALLENGE_EXPIRED'),
  );
  assert.equal(f.records.size, 1);
  await f.runtime.run(undefined, (call) =>
    claimCeremony(f.runtime, 'webauthn-register', f.subject, ceremony.ceremonyId, call),
  );
  assert.equal(f.records.size, 0);
});

test('An invalid cryptographic response still consumes the one-use ceremony', async () => {
  const f = fixture(),
    device = authenticator();
  const options = await f.runtime.driver.authenticationOptions([device.id]);
  const ceremony = await f.runtime.run(undefined, (call) =>
    issueCeremony(f.runtime, 'webauthn-authenticate', f.subject, options, call),
  );
  await assert.rejects(
    f.runtime.run(undefined, async (call) => {
      const record = await claimCeremony(
        f.runtime,
        'webauthn-authenticate',
        f.subject,
        ceremony.ceremonyId,
        call,
      );
      const parsed = readUnverifiedResponse(
        device.authentication(options.challenge, { origin: 'https://foreign.test' }),
        false,
      );
      requireChallenge(f.runtime, record, parsed.challenge);
      await f.runtime.driver.verifyAuthentication(parsed.serialized, parsed.challenge, {
        id: device.id,
        publicKey: device.publicKey,
        counter: 0,
      });
    }),
    hasCode('EK_MFA_INVALID'),
  );
  await assert.rejects(
    f.runtime.run(undefined, (call) =>
      claimCeremony(f.runtime, 'webauthn-authenticate', f.subject, ceremony.ceremonyId, call),
    ),
    hasCode('EK_MFA_CHALLENGE_EXPIRED'),
  );
});

test('A valid claimed browser proof still verifies through the real upstream adapter', async () => {
  const f = fixture(),
    device = authenticator();
  const options = await f.runtime.driver.authenticationOptions([device.id]);
  const ceremony = await f.runtime.run(undefined, (call) =>
    issueCeremony(f.runtime, 'webauthn-authenticate', f.subject, options, call),
  );
  const verified = await f.runtime.run(undefined, async (call) => {
    const record = await claimCeremony(
      f.runtime,
      'webauthn-authenticate',
      f.subject,
      ceremony.ceremonyId,
      call,
    );
    const parsed = readUnverifiedResponse(
      device.authentication(options.challenge, { origin: 'https://example.test' }),
      false,
    );
    requireChallenge(f.runtime, record, parsed.challenge);
    return f.runtime.driver.verifyAuthentication(parsed.serialized, parsed.challenge, {
      id: device.id,
      publicKey: device.publicKey,
      counter: 0,
    });
  });
  assert.equal(verified.newCounter, 1);
  assert.equal('evidence' in verified, false);
});

test('Challenge digests bind origin set, RP, attestation, verification and TTL policy across instances', async () => {
  const f = fixture();
  const first = createWebAuthnRuntime({
    ...f.options,
    expectedOrigins: ['https://example.test', 'https://login.example.test'],
  });
  const options = await first.driver.authenticationOptions();
  const ceremony = await first.run(undefined, (call) =>
    issueCeremony(first, 'webauthn-authenticate', f.subject, options, call),
  );
  const record = f.records.get(ceremony.ceremonyId)!;
  const reordered = createWebAuthnRuntime({
    ...f.options,
    expectedOrigins: ['https://login.example.test', 'https://example.test'],
  });
  requireChallenge(reordered, record, options.challenge);
  for (const changes of [
    { expectedOrigins: ['https://example.test'] },
    { challengeTtlMs: 1000 },
    { attestation: 'direct' as const },
    { rpId: 'other.test', expectedOrigins: ['https://other.test'] },
  ]) {
    const changed = createWebAuthnRuntime({ ...f.options, ...changes });
    assert.throws(
      () => requireChallenge(changed, record, options.challenge),
      hasCode('EK_MFA_INVALID'),
    );
  }
  assert.throws(
    () => requireChallenge(first, record, randomBytes(32).toString('base64url')),
    hasCode('EK_MFA_INVALID'),
  );
  assert.throws(
    () => requireChallenge(first, { ...record, challengeDigest: 'invalid' }, options.challenge),
    hasCode('EK_MFA_INVALID'),
  );
});

test('Returned durable metadata is independently checked before cryptographic verification', async () => {
  const f = fixture(),
    options = await f.runtime.driver.authenticationOptions();
  const ceremony = await f.runtime.run(undefined, (call) =>
    issueCeremony(f.runtime, 'webauthn-authenticate', f.subject, options, call),
  );
  const record = f.records.get(ceremony.ceremonyId)!;
  for (const changes of [
    { id: 'wrong' },
    { purpose: 'totp-enroll' },
    { rpId: 'foreign' },
    { issuer: 'foreign' },
    { subject: 'foreign' },
    { tenantId: 'foreign' },
    { primarySessionId: 'foreign' },
    { challengeDigest: null },
    { challengeDigest: 'invalid' },
    { unexpected: true },
    { createdAt: 'invalid' },
    { expiresAt: record.createdAt },
    { createdAt: new Date(f.now() + 1).toISOString() },
    { expiresAt: new Date(f.now() + 300001).toISOString() },
  ]) {
    const bad = createWebAuthnRuntime({
      ...f.options,
      stateStore: {
        ...f.options.stateStore,
        async claimChallenge() {
          return { ...record, ...changes } as MfaChallengeRecord;
        },
      },
    });
    await assert.rejects(
      bad.run(undefined, (call) =>
        claimCeremony(bad, 'webauthn-authenticate', f.subject, ceremony.ceremonyId, call),
      ),
      hasCode('EK_MFA_STORAGE'),
    );
  }
});

test('Expiry, clock overflow, invalid references and failed storage never return a ceremony', async () => {
  const f = fixture(),
    options = await f.runtime.driver.authenticationOptions();
  for (const id of ['', 'x', 'A'.repeat(42) + 'B', null])
    await assert.rejects(
      f.runtime.run(undefined, (call) =>
        claimCeremony(f.runtime, 'webauthn-authenticate', f.subject, id as string, call),
      ),
      hasCode('EK_MFA_INVALID'),
    );
  assert.equal(f.calls.length, 0);
  for (const result of [true, 'incorrect']) {
    const bad = createWebAuthnRuntime({
      ...f.options,
      stateStore: {
        ...f.options.stateStore,
        async createChallenge() {
          return result as never;
        },
      },
    });
    await assert.rejects(
      bad.run(undefined, (call) =>
        issueCeremony(bad, 'webauthn-authenticate', f.subject, options, call),
      ),
      hasCode('EK_MFA_STORAGE'),
    );
  }
  const failed = createWebAuthnRuntime({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async createChallenge() {
        throw new Error('Sensitive storage diagnostic');
      },
    },
  });
  await assert.rejects(
    failed.run(undefined, (call) =>
      issueCeremony(failed, 'webauthn-authenticate', f.subject, options, call),
    ),
    hasCode('EK_MFA_STORAGE'),
  );
  const ceremony = await f.runtime.run(undefined, (call) =>
    issueCeremony(f.runtime, 'webauthn-authenticate', f.subject, options, call),
  );
  const record = f.records.get(ceremony.ceremonyId)!;
  f.setTime(f.now() + 300000);
  const expired = createWebAuthnRuntime({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async claimChallenge() {
        return record;
      },
    },
  });
  await assert.rejects(
    expired.run(undefined, (call) =>
      claimCeremony(expired, 'webauthn-authenticate', f.subject, ceremony.ceremonyId, call),
    ),
    hasCode('EK_MFA_CHALLENGE_EXPIRED'),
  );
  f.setTime(253402300799999);
  await assert.rejects(
    f.runtime.run(undefined, (call) =>
      issueCeremony(f.runtime, 'webauthn-authenticate', f.subject, options, call),
    ),
    hasCode('EK_MFA_POLICY'),
  );
});

test('Passwordless ceremony binding remains anonymous and cannot consume a session-bound ceremony', async () => {
  const f = fixture();
  await f.runtime.run(undefined, async (call) => {
    const options = await f.runtime.driver.authenticationOptions();
    const ceremony = await issueCeremony(
      f.runtime,
      'webauthn-passwordless',
      undefined,
      options,
      call,
    );
    const record = f.records.get(ceremony.ceremonyId)!;
    assert.equal(record.subject, undefined);
    assert.equal(record.tenantId, undefined);
    assert.equal(record.primarySessionId, undefined);
    assert.equal(record.issuer, 'urn:arkenivajs:webauthn:passwordless:example.test');
    await assert.rejects(
      claimCeremony(f.runtime, 'webauthn-authenticate', f.subject, ceremony.ceremonyId, call),
      hasCode('EK_MFA_CHALLENGE_EXPIRED'),
    );
    requireChallenge(
      f.runtime,
      await claimCeremony(f.runtime, 'webauthn-passwordless', undefined, ceremony.ceremonyId, call),
      options.challenge,
    );
    await assert.rejects(
      issueCeremony(f.runtime, 'webauthn-passwordless', f.subject, options, call),
      hasCode('EK_MFA_POLICY'),
    );
    await assert.rejects(
      issueCeremony(f.runtime, 'webauthn-register', undefined, options, call),
      hasCode('EK_MFA_POLICY'),
    );
  });
  assert.equal(f.observed.resolutions, 0);
});

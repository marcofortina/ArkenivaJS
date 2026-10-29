// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { MfaSubjectContext, TenantId } from '@arkenivajs/core';
import type { WebAuthnCeremony } from '../../dist/index.js';
import { createWebAuthnService } from '@arkenivajs/security-webauthn';
import { serviceFixture } from '../support/service-fixture.js';
import { authenticator } from '../support/authenticator.js';

const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
function challenge(ceremony: WebAuthnCeremony): string {
  const value = ceremony.optionsJSON.challenge;
  assert.ok(typeof value === 'string');
  return value;
}
function handle(ceremony: WebAuthnCeremony): string {
  const user = ceremony.optionsJSON.user as { id: string };
  assert.ok(typeof user.id === 'string');
  return user.id;
}
async function enroll(
  f: ReturnType<typeof serviceFixture>,
  service = createWebAuthnService(f.options),
  owner = f.subject,
  device = authenticator(),
  counter = 0,
) {
  const ceremony = await service.beginRegistration(owner);
  const summary = await service.finishRegistration(
    owner,
    ceremony.ceremonyId,
    device.registration(challenge(ceremony), { origin: 'https://example.test', counter }),
  );
  return { service, device, summary, userHandle: handle(ceremony) };
}

test('Public finish operations reject executable browser responses without trap execution or factor/evidence persistence', async () => {
  for (const mode of ['registration', 'authentication', 'passwordless'] as const) {
    const f = serviceFixture(),
      service = createWebAuthnService({ ...f.options, passwordlessEnabled: true }),
      device = authenticator();
    if (mode !== 'registration') await enroll(f, service, f.subject, device);
    const ceremony =
      mode === 'registration'
        ? await service.beginRegistration(f.subject)
        : mode === 'authentication'
          ? await service.beginAuthentication(f.subject)
          : await service.beginPasswordless();
    const response =
      mode === 'registration'
        ? device.registration(challenge(ceremony), { origin: 'https://example.test', counter: 0 })
        : device.authentication(challenge(ceremony), { origin: 'https://example.test' });
    let calls = 0;
    const proxy = new Proxy(response, {
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
    });
    const finish = (value: unknown) =>
      mode === 'registration'
        ? service.finishRegistration(f.subject, ceremony.ceremonyId, value)
        : mode === 'authentication'
          ? service.finishAuthentication(f.subject, ceremony.ceremonyId, value)
          : service.finishPasswordless(ceremony.ceremonyId, value);
    await assert.rejects(finish(proxy), hasCode('EK_MFA_INVALID'));
    assert.equal(calls, 0);
    assert.equal(f.credentials.size, mode === 'registration' ? 0 : 1);
    if (mode !== 'registration') assert.equal(f.credentials.get(device.id)!.counter, 0);
    assert.equal(f.evidence.size, 0);
    assert.equal(f.observed.anonymous, 0);
    assert.equal(f.challenges.has(ceremony.ceremonyId), false);
    await assert.rejects(finish(response), hasCode('EK_MFA_CHALLENGE_EXPIRED'));
  }
});

for (const algorithm of ['RS256', 'EdDSA'] as const)
  test(`Public ${algorithm} factor ceremonies preserve atomic claims, counters and one-use MFA evidence`, async () => {
    const f = serviceFixture(),
      service = createWebAuthnService({ ...f.options, passwordlessEnabled: true }),
      device = authenticator(algorithm);
    await enroll(f, service, f.subject, device);
    const invalid = await service.beginAuthentication(f.subject),
      original = device.authentication(challenge(invalid), { origin: 'https://example.test' }),
      corrupt = structuredClone(original),
      bytes = Buffer.from(corrupt.response.signature!, 'base64url');
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    corrupt.response.signature = bytes.toString('base64url');
    await assert.rejects(
      service.finishAuthentication(f.subject, invalid.ceremonyId, corrupt),
      hasCode('EK_MFA_INVALID'),
    );
    assert.equal(f.credentials.get(device.id)!.counter, 0);
    assert.equal(f.evidence.size, 0);
    await assert.rejects(
      service.finishAuthentication(f.subject, invalid.ceremonyId, original),
      hasCode('EK_MFA_CHALLENGE_EXPIRED'),
    );
    const ceremony = await service.beginAuthentication(f.subject),
      response = device.authentication(challenge(ceremony), { origin: 'https://example.test' }),
      attempts = await Promise.allSettled(
        Array.from({ length: 4 }, () =>
          service.finishAuthentication(f.subject, ceremony.ceremonyId, response),
        ),
      );
    const accepted = attempts.filter((result) => result.status === 'fulfilled');
    assert.equal(accepted.length, 1);
    assert.equal(f.credentials.get(device.id)!.counter, 1);
    assert.equal(f.evidence.size, 1);
    const result = accepted[0]!.value,
      binding = {
        evidenceId: result.evidenceId,
        issuer: f.subject.issuer,
        subject: f.subject.subject,
        primarySessionId: f.subject.primarySessionId,
        now: new Date(f.now()).toISOString(),
      };
    assert.equal(result.assurance, 'phishing-resistant');
    assert.ok(await f.options.evidenceStore.consume(binding));
    assert.equal(await f.options.evidenceStore.consume(binding), null);
    const anonymous = await service.beginPasswordless(),
      passwordless = await service.finishPasswordless(
        anonymous.ceremonyId,
        device.authentication(challenge(anonymous), { origin: 'https://example.test', counter: 2 }),
      );
    assert.equal(passwordless.subject, f.subject.subject);
    assert.equal(passwordless.issuer, f.subject.issuer);
    assert.equal(f.credentials.get(device.id)!.counter, 2);
    await assert.rejects(
      service.finishPasswordless(
        anonymous.ceremonyId,
        device.authentication(challenge(anonymous), { origin: 'https://example.test', counter: 2 }),
      ),
      hasCode('EK_MFA_CHALLENGE_EXPIRED'),
    );
  });

test('Complete registration and session-bound authentication persist one-use phishing-resistant evidence', async () => {
  const f = serviceFixture(),
    { service, device, summary, userHandle } = await enroll(f);
  assert.deepEqual(Object.keys(summary).sort(), ['backedUp', 'credentialId', 'registeredAt']);
  assert.equal(summary.credentialId, device.id);
  assert.equal(f.credentials.get(device.id)!.userHandle, userHandle);
  assert.equal(f.credentials.get(device.id)!.stateVersion, 'backend-1');
  assert.deepEqual(await service.listCredentials(f.subject), [summary]);
  const ceremony = await service.beginAuthentication(f.subject);
  const response = device.authentication(challenge(ceremony), {
    origin: 'https://example.test',
    counter: 1,
  });
  const result = await service.finishAuthentication(f.subject, ceremony.ceremonyId, response);
  assert.equal(result.method, 'webauthn');
  assert.equal(result.assurance, 'phishing-resistant');
  assert.equal('sessionToken' in result, false);
  assert.equal(f.credentials.get(device.id)!.counter, 1);
  const binding = {
    evidenceId: result.evidenceId,
    issuer: f.subject.issuer,
    subject: f.subject.subject,
    primarySessionId: f.subject.primarySessionId,
    now: new Date(f.now()).toISOString(),
  };
  assert.equal((await f.options.evidenceStore.consume(binding))!.evidenceId, result.evidenceId);
  assert.equal(await f.options.evidenceStore.consume(binding), null);
  await assert.rejects(
    service.finishAuthentication(f.subject, ceremony.ceremonyId, response),
    hasCode('EK_MFA_CHALLENGE_EXPIRED'),
  );
});

test('Concurrent enrollment reuses one RP/account handle and never reassigns a credential', async () => {
  const f = serviceFixture(),
    first = createWebAuthnService(f.options),
    second = createWebAuthnService(f.options);
  const starts = await Promise.all([
    first.beginRegistration(f.subject),
    second.beginRegistration(f.subject),
  ]);
  assert.equal(handle(starts[0]!), handle(starts[1]!));
  assert.equal(Buffer.from(handle(starts[0]!), 'base64url').length, 32);
  const devices = [authenticator(), authenticator()];
  await Promise.all(
    [first, second].map((service, index) =>
      service.finishRegistration(
        f.subject,
        starts[index]!.ceremonyId,
        devices[index]!.registration(challenge(starts[index]!), {
          origin: 'https://example.test',
          counter: 0,
        }),
      ),
    ),
  );
  assert.equal(f.credentials.size, 2);
  assert.equal(f.handles.size, 1);
  const duplicate = await first.beginRegistration(f.subject);
  await assert.rejects(
    first.finishRegistration(
      f.subject,
      duplicate.ceremonyId,
      devices[0]!.registration(challenge(duplicate), {
        origin: 'https://example.test',
        counter: 0,
      }),
    ),
    hasCode('EK_MFA_CREDENTIAL_CONFLICT'),
  );
  assert.equal(f.credentials.size, 2);
});

test('Every session-bound operation rejects a manually constructed subject or forged management grant', async () => {
  const f = serviceFixture(),
    { service, device } = await enroll(f),
    forged = Object.freeze({ ...f.subject });
  for (const work of [
    () => service.beginRegistration(forged),
    () => service.finishRegistration(forged, 'invalid', {}),
    () => service.beginAuthentication(forged),
    () => service.finishAuthentication(forged, 'invalid', {}),
    () => service.listCredentials(forged),
    () => service.revokeCredential(forged, device.id, f.grant),
  ])
    await assert.rejects(work(), hasCode('EK_AUTH_FORBIDDEN'));
  await assert.rejects(
    service.revokeCredential(f.subject, device.id, Object.freeze({ ...f.grant })),
    hasCode('EK_AUTH_FORBIDDEN'),
  );
  assert.equal(f.credentials.get(device.id)!.revokedAt, undefined);
  assert.equal(f.evidence.size, 0);
});

test('Revocation consumes its trusted management grant exactly once and still rechecks the live session', async () => {
  const f = serviceFixture();
  const authorize = f.options.subjectAuthority.authorize;
  let consumed = 0;
  f.options.subjectAuthority.authorize = async (input, operation) => {
    await authorize(input, operation);
    if (input.action === 'revoke-credential') {
      assert.ok(f.grants.delete(input.authorization!));
      consumed++;
    }
  };
  const { service, device } = await enroll(f);
  const before = f.observed.resolutions;
  await service.revokeCredential(f.subject, device.id, f.grant);
  assert.equal(consumed, 1);
  assert.equal(f.observed.resolutions - before, 2);
  assert.equal(f.credentials.get(device.id)!.revokedAt, new Date(f.now()).toISOString());
  await assert.rejects(
    service.revokeCredential(f.subject, device.id, f.grant),
    hasCode('EK_AUTH_FORBIDDEN'),
  );
  assert.equal(consumed, 1);
});

test('Revocation rejects grants or primary authentication that expire during storage access', async () => {
  for (const elapsed of [60001, 300001]) {
    const f = serviceFixture(),
      { device } = await enroll(f);
    const service = createWebAuthnService({
      ...f.options,
      stateStore: {
        ...f.options.stateStore,
        async getCredential(...args) {
          const record = await f.options.stateStore.getCredential(...args);
          f.setTime(f.now() + elapsed);
          return record;
        },
      },
    });
    await assert.rejects(
      service.revokeCredential(f.subject, device.id, f.grant),
      hasCode('EK_MFA_POLICY'),
    );
    assert.equal(f.credentials.get(device.id)!.revokedAt, undefined);
  }
});

test('An independently authenticated tenant cannot use another tenant account credential', async () => {
  const f = serviceFixture(),
    { service, device } = await enroll(f);
  const identity = Object.freeze({
    issuer: f.subject.issuer,
    subject: f.subject.subject,
    audience: [],
    scopes: [],
    claims: {},
  });
  const foreign: MfaSubjectContext = Object.freeze({
    ...f.subject,
    primarySessionId: 'other-tenant-session',
    tenant: Object.freeze({
      tenantId: 'other-tenant' as TenantId,
      identity,
      source: 'oidc',
      verifiedAt: f.subject.authenticatedAt,
    }),
  });
  f.authenticated.add(foreign);
  f.strong.add(foreign);
  const other = await enroll(f, service, foreign);
  assert.notEqual(other.userHandle, f.credentials.get(device.id)!.userHandle);
  const ceremony = await service.beginAuthentication(foreign);
  await assert.rejects(
    service.finishAuthentication(
      foreign,
      ceremony.ceremonyId,
      device.authentication(challenge(ceremony), { origin: 'https://example.test' }),
    ),
    hasCode('EK_MFA_INVALID'),
  );
  assert.equal(f.evidence.size, 0);
});

test('Passwordless is opt-in and resolves identity only after a verified owner-bound assertion', async () => {
  const f = serviceFixture(),
    { device } = await enroll(f),
    disabled = createWebAuthnService(f.options);
  await assert.rejects(disabled.beginPasswordless(), hasCode('EK_MFA_POLICY'));
  await assert.rejects(disabled.finishPasswordless('invalid', {}), hasCode('EK_MFA_POLICY'));
  const service = createWebAuthnService({ ...f.options, passwordlessEnabled: true });
  const invalid = await service.beginPasswordless();
  await assert.rejects(
    service.finishPasswordless(
      invalid.ceremonyId,
      device.authentication(challenge(invalid), { origin: 'https://foreign.test', counter: 0 }),
    ),
    hasCode('EK_MFA_INVALID'),
  );
  assert.equal(f.observed.anonymous, 0);
  const beforeResolutions = f.observed.resolutions,
    ceremony = await service.beginPasswordless();
  const response = device.authentication(challenge(ceremony), {
    origin: 'https://example.test',
    counter: 0,
  });
  const result = await service.finishPasswordless(ceremony.ceremonyId, response);
  assert.equal(f.observed.resolutions, beforeResolutions);
  assert.equal(f.observed.anonymous, 1);
  assert.equal(result.subject, f.subject.subject);
  assert.equal(result.issuer, f.subject.issuer);
  assert.equal(result.evidence.assurance, 'phishing-resistant');
  const record = f.evidence.get(result.evidence.evidenceId)!;
  assert.equal(record.primarySessionId, ceremony.ceremonyId);
  const binding = {
    evidenceId: record.evidenceId,
    issuer: record.issuer,
    subject: record.subject,
    primarySessionId: ceremony.ceremonyId,
    now: new Date(f.now()).toISOString(),
  };
  assert.equal((await f.options.evidenceStore.consume(binding))!.evidenceId, record.evidenceId);
  assert.equal(await f.options.evidenceStore.consume(binding), null);
  await assert.rejects(
    service.finishPasswordless(ceremony.ceremonyId, response),
    hasCode('EK_MFA_CHALLENGE_EXPIRED'),
  );
});

test('Revocation invalidates account ceremonies and prevents later signed assertions', async () => {
  const f = serviceFixture(),
    { service, device } = await enroll(f);
  const pending = await service.beginAuthentication(f.subject);
  await service.revokeCredential(f.subject, device.id, f.grant);
  assert.ok(f.credentials.get(device.id)!.revokedAt);
  assert.equal(f.challenges.has(pending.ceremonyId), false);
  assert.deepEqual(await service.listCredentials(f.subject), []);
  await assert.rejects(
    service.finishAuthentication(
      f.subject,
      pending.ceremonyId,
      device.authentication(challenge(pending), { origin: 'https://example.test' }),
    ),
    hasCode('EK_MFA_CHALLENGE_EXPIRED'),
  );
  const enabled = createWebAuthnService({ ...f.options, passwordlessEnabled: true }),
    anonymous = await enabled.beginPasswordless();
  await assert.rejects(
    enabled.finishPasswordless(
      anonymous.ceremonyId,
      device.authentication(challenge(anonymous), { origin: 'https://example.test' }),
    ),
    hasCode('EK_MFA_INVALID'),
  );
  assert.equal(f.evidence.size, 0);
});

test('Backend outage and invalid evidence acknowledgement never return a verification result', async () => {
  const f = serviceFixture(),
    { device } = await enroll(f);
  for (const recordOnce of [
    async () => {
      throw new Error('Sensitive evidence-store diagnostic');
    },
    async () => true as never,
  ]) {
    const service = createWebAuthnService({
      ...f.options,
      evidenceStore: { ...f.options.evidenceStore, recordOnce },
    });
    const ceremony = await service.beginAuthentication(f.subject);
    await assert.rejects(
      service.finishAuthentication(
        f.subject,
        ceremony.ceremonyId,
        device.authentication(challenge(ceremony), { origin: 'https://example.test', counter: 0 }),
      ),
      (error) => {
        assert.ok(hasCode('EK_MFA_STORAGE')(error));
        assert.equal(inspect(error).includes('Sensitive'), false);
        return true;
      },
    );
  }
  assert.equal(f.evidence.size, 0);
});

test('One shared challenge has exactly one successful finish across independent service instances', async () => {
  const f = serviceFixture(),
    { service, device } = await enroll(f),
    other = createWebAuthnService(f.options);
  const ceremony = await service.beginAuthentication(f.subject);
  const response = device.authentication(challenge(ceremony), {
    origin: 'https://example.test',
    counter: 0,
  });
  const result = await Promise.allSettled(
    [service, other].map((instance) =>
      instance.finishAuthentication(f.subject, ceremony.ceremonyId, response),
    ),
  );
  assert.equal(result.filter((item) => item.status === 'fulfilled').length, 1);
  assert.equal(f.evidence.size, 1);
  assert.equal(f.credentials.get(device.id)!.counter, 0);
});

test('Unknown and mismatched user handles cannot create passwordless evidence', async () => {
  const f = serviceFixture(),
    { device } = await enroll(f);
  const service = createWebAuthnService({ ...f.options, passwordlessEnabled: true });
  const ceremony = await service.beginPasswordless(),
    response = device.authentication(challenge(ceremony), {
      origin: 'https://example.test',
      counter: 0,
    });
  await assert.rejects(
    service.finishPasswordless(ceremony.ceremonyId, {
      ...response,
      response: { ...response.response, userHandle: randomBytes(32).toString('base64url') },
    }),
    hasCode('EK_MFA_INVALID'),
  );
  assert.equal(f.observed.anonymous, 0);
  assert.equal(f.evidence.size, 0);
});

test('Distinct zero-counter ceremonies still contend on the same credential state version', async () => {
  const f = serviceFixture(),
    { device } = await enroll(f);
  let arrivals = 0,
    release!: () => void;
  const barrier = new Promise<void>((resolve) => {
    release = resolve;
  });
  const options = {
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async advanceCounter(...args: Parameters<typeof f.options.stateStore.advanceCounter>) {
        if (++arrivals === 2) release();
        await barrier;
        return f.options.stateStore.advanceCounter(...args);
      },
    },
  };
  const services = [createWebAuthnService(options), createWebAuthnService(options)];
  const starts = await Promise.all(
    services.map((service) => service.beginAuthentication(f.subject)),
  );
  const results = await Promise.allSettled(
    services.map((service, index) =>
      service.finishAuthentication(
        f.subject,
        starts[index]!.ceremonyId,
        device.authentication(challenge(starts[index]!), {
          origin: 'https://example.test',
          counter: 0,
        }),
      ),
    ),
  );
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  const denied = results.find((result) => result.status === 'rejected');
  assert.ok(denied?.status === 'rejected' && hasCode('EK_MFA_CREDENTIAL_CONFLICT')(denied.reason));
  assert.equal(f.evidence.size, 1);
  assert.equal(f.credentials.get(device.id)!.stateVersion, 'backend-2');
});

test('Backup state transitions are committed while eligibility stays immutable', async () => {
  const f = serviceFixture(),
    service = createWebAuthnService(f.options),
    device = authenticator();
  const registration = await service.beginRegistration(f.subject);
  await service.finishRegistration(
    f.subject,
    registration.ceremonyId,
    device.registration(challenge(registration), {
      origin: 'https://example.test',
      counter: 0,
      flags: 0x4d,
    }),
  );
  for (const [flags, backedUp] of [
    [0x1d, true],
    [0x0d, false],
  ] as const) {
    const ceremony = await service.beginAuthentication(f.subject);
    await service.finishAuthentication(
      f.subject,
      ceremony.ceremonyId,
      device.authentication(challenge(ceremony), {
        origin: 'https://example.test',
        counter: 0,
        flags,
      }),
    );
    assert.equal(f.credentials.get(device.id)!.backedUp, backedUp);
  }
  assert.equal(f.credentials.get(device.id)!.stateVersion, 'backend-3');
});

test('Signed nonzero counter equality and regression fail without evidence or state advancement', async () => {
  const f = serviceFixture(),
    { service, device } = await enroll(f, undefined, undefined, undefined, 5);
  for (const counter of [5, 4, 0]) {
    const ceremony = await service.beginAuthentication(f.subject);
    await assert.rejects(
      service.finishAuthentication(
        f.subject,
        ceremony.ceremonyId,
        device.authentication(challenge(ceremony), { origin: 'https://example.test', counter }),
      ),
      hasCode('EK_MFA_COUNTER_REGRESSION'),
    );
  }
  assert.equal(f.evidence.size, 0);
  assert.equal(f.credentials.get(device.id)!.counter, 5);
  const valid = await service.beginAuthentication(f.subject);
  await service.finishAuthentication(
    f.subject,
    valid.ceremonyId,
    device.authentication(challenge(valid), { origin: 'https://example.test', counter: 6 }),
  );
  assert.equal(f.credentials.get(device.id)!.counter, 6);
});

test('Direct registration uses upstream verification and a backend-owned initial revision', async () => {
  const f = serviceFixture(),
    service = createWebAuthnService({ ...f.options, attestation: 'direct' }),
    device = authenticator();
  const ceremony = await service.beginRegistration(f.subject);
  assert.equal(ceremony.optionsJSON.attestation, 'direct');
  await service.finishRegistration(
    f.subject,
    ceremony.ceremonyId,
    device.registration(challenge(ceremony), {
      origin: 'https://example.test',
      format: 'packed',
      counter: 0,
    }),
  );
  assert.equal(f.credentials.get(device.id)!.stateVersion, 'backend-1');
  const broken = serviceFixture(),
    nativeInsert = broken.options.stateStore.insertCredentialIfAbsent;
  const refusesVersion = createWebAuthnService({
    ...broken.options,
    stateStore: {
      ...broken.options.stateStore,
      async insertCredentialIfAbsent(record, operation) {
        const accepted = await nativeInsert(record, operation);
        broken.credentials.set(record.credentialId, record);
        return accepted;
      },
    },
  });
  const pending = await refusesVersion.beginRegistration(broken.subject);
  await assert.rejects(
    refusesVersion.finishRegistration(
      broken.subject,
      pending.ceremonyId,
      authenticator().registration(challenge(pending), {
        origin: 'https://example.test',
        counter: 0,
      }),
    ),
    hasCode('EK_MFA_STORAGE'),
  );
});

test('Primary-session revocation during signature verification prevents the final credential update', async () => {
  const f = serviceFixture(),
    { device } = await enroll(f);
  let reads = 0;
  const service = createWebAuthnService({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async getCredential(...args) {
        if (++reads === 2) f.authenticated.delete(f.subject);
        return f.options.stateStore.getCredential(...args);
      },
    },
  });
  const ceremony = await service.beginAuthentication(f.subject);
  await assert.rejects(
    service.finishAuthentication(
      f.subject,
      ceremony.ceremonyId,
      device.authentication(challenge(ceremony), { origin: 'https://example.test', counter: 0 }),
    ),
    hasCode('EK_AUTH_FORBIDDEN'),
  );
  assert.equal(f.credentials.get(device.id)!.stateVersion, 'backend-1');
  assert.equal(f.evidence.size, 0);
});

test('Post-CAS revocation and expiry during evidence persistence prevent returning a result', async () => {
  for (const expire of [false, true]) {
    const f = serviceFixture(),
      { device } = await enroll(f);
    const service = createWebAuthnService({
      ...f.options,
      evidenceStore: {
        ...f.options.evidenceStore,
        async recordOnce(record, operation) {
          await f.options.evidenceStore.recordOnce(record, operation);
          if (expire) f.setTime(f.now() + 300001);
          else {
            const current = f.credentials.get(device.id)!;
            await f.options.stateStore.revokeCredential(
              f.subject,
              current.rpId,
              current.credentialId,
              current.stateVersion,
            );
          }
        },
      },
    });
    const ceremony = await service.beginAuthentication(f.subject);
    await assert.rejects(
      service.finishAuthentication(
        f.subject,
        ceremony.ceremonyId,
        device.authentication(challenge(ceremony), { origin: 'https://example.test', counter: 0 }),
      ),
      hasCode(expire ? 'EK_MFA_CHALLENGE_EXPIRED' : 'EK_MFA_INVALID'),
    );
  }
});

test('Operation admission remains bounded while timed-out providers have not settled', async (t) => {
  const f = serviceFixture();
  await enroll(f);
  let elapsed = 0;
  t.mock.method(performance, 'now', () => elapsed);
  let blocking = true,
    entered = 0,
    ready!: () => void;
  const started = new Promise<void>((resolve) => {
    ready = resolve;
  });
  const releases: Array<() => void> = [];
  const service = createWebAuthnService({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async listCredentials(...args) {
        if (blocking) {
          await new Promise<void>((resolve) => {
            releases.push(resolve);
            if (++entered === 32) ready();
          });
        }
        return f.options.stateStore.listCredentials(...args);
      },
    },
  });
  const pending = Promise.allSettled(
    Array.from({ length: 32 }, () => service.beginAuthentication(f.subject, { timeoutMs: 25 })),
  );
  await started;
  elapsed = 26;
  await assert.rejects(service.beginAuthentication(f.subject), hasCode('EK_MFA_RATE_LIMIT'));
  assert.ok(
    (await pending).every(
      (result) => result.status === 'rejected' && hasCode('EK_TIMEOUT')(result.reason),
    ),
  );
  await assert.rejects(service.beginAuthentication(f.subject), hasCode('EK_MFA_RATE_LIMIT'));
  blocking = false;
  for (const release of releases) release();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.ok((await service.beginAuthentication(f.subject)).ceremonyId);
});

test('Credential collections are bounded, snapshotted once and never silently truncated', async () => {
  const f = serviceFixture();
  await enroll(f);
  const record = [...f.credentials.values()][0]!;
  const getter: unknown[] = [];
  let reads = 0;
  Object.defineProperty(getter, '0', {
    get() {
      reads++;
      return record;
    },
    enumerable: true,
  });
  for (const result of [
    null,
    {},
    new Array(1),
    getter,
    [record, record],
    new Array(101).fill(record),
  ]) {
    const service = createWebAuthnService({
      ...f.options,
      stateStore: {
        ...f.options.stateStore,
        async listCredentials() {
          return result as never;
        },
      },
    });
    await assert.rejects(service.listCredentials(f.subject), hasCode('EK_MFA_STORAGE'));
  }
  assert.equal(reads, 0);
  let lengths = 0;
  const proxy = new Proxy([record], {
    get(target, key, receiver) {
      if (key === 'length') {
        lengths++;
        return lengths === 1 ? 1 : 10000;
      }
      return Reflect.get(target, key, receiver);
    },
  });
  const bounded = createWebAuthnService({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async listCredentials() {
        return proxy;
      },
    },
  });
  assert.equal((await bounded.listCredentials(f.subject)).length, 1);
  assert.equal(lengths, 1);
  const hundred = Array.from({ length: 100 }, () => ({
    ...record,
    credentialId: randomBytes(32).toString('base64url'),
  }));
  const full = createWebAuthnService({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async listCredentials() {
        return hundred;
      },
    },
  });
  assert.equal((await full.listCredentials(f.subject)).length, 100);
  await assert.rejects(full.beginRegistration(f.subject), hasCode('EK_MFA_POLICY'));
  const revoked = createWebAuthnService({
    ...f.options,
    stateStore: {
      ...f.options.stateStore,
      async listCredentials() {
        return [{ ...record, revokedAt: record.registeredAt }];
      },
    },
  });
  assert.deepEqual(await revoked.listCredentials(f.subject), []);
  await assert.rejects(revoked.beginAuthentication(f.subject), hasCode('EK_MFA_INVALID'));
});

test('Malformed account handles and insertion acknowledgements cannot complete enrollment', async () => {
  for (const value of ['', randomBytes(16).toString('base64url'), 'A'.repeat(42) + 'B']) {
    const f = serviceFixture(),
      service = createWebAuthnService({
        ...f.options,
        stateStore: {
          ...f.options.stateStore,
          async getOrCreateUserHandle() {
            return value;
          },
        },
      });
    await assert.rejects(service.beginRegistration(f.subject), hasCode('EK_MFA_STORAGE'));
    assert.equal(f.challenges.size, 0);
  }
  for (const accepted of [undefined, null, 'true']) {
    const f = serviceFixture(),
      service = createWebAuthnService({
        ...f.options,
        stateStore: {
          ...f.options.stateStore,
          async insertCredentialIfAbsent() {
            return accepted as never;
          },
        },
      });
    const ceremony = await service.beginRegistration(f.subject);
    await assert.rejects(
      service.finishRegistration(
        f.subject,
        ceremony.ceremonyId,
        authenticator().registration(challenge(ceremony), {
          origin: 'https://example.test',
          counter: 0,
        }),
      ),
      hasCode('EK_MFA_STORAGE'),
    );
    assert.equal(f.credentials.size, 0);
  }
});

test('Invalid deadlines and cancellation reject every configurable operation before provider access', async () => {
  const f = serviceFixture(),
    service = createWebAuthnService(f.options);
  const operations = [
    (options: { timeoutMs?: number; signal?: AbortSignal }) =>
      service.beginRegistration(f.subject, options),
    (options: { timeoutMs?: number; signal?: AbortSignal }) =>
      service.finishRegistration(f.subject, 'invalid', {}, options),
    (options: { timeoutMs?: number; signal?: AbortSignal }) =>
      service.beginAuthentication(f.subject, options),
    (options: { timeoutMs?: number; signal?: AbortSignal }) =>
      service.finishAuthentication(f.subject, 'invalid', {}, options),
    (options: { timeoutMs?: number; signal?: AbortSignal }) => service.beginPasswordless(options),
    (options: { timeoutMs?: number; signal?: AbortSignal }) =>
      service.finishPasswordless('invalid', {}, options),
    (options: { timeoutMs?: number; signal?: AbortSignal }) =>
      service.revokeCredential(f.subject, 'invalid', f.grant, options),
  ];
  for (const operation of operations) {
    await assert.rejects(operation({ timeoutMs: 0 }), hasCode('EK_MFA_POLICY'));
    await assert.rejects(operation({ signal: AbortSignal.abort() }), hasCode('EK_ABORTED'));
  }
  assert.equal(f.observed.resolutions, 0);
  assert.equal(f.observed.limits.length, 0);
  assert.deepEqual(await service.listCredentials(f.subject), []);
});

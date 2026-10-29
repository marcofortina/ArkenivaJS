// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { createWebAuthnService } from '@arkenivajs/security-webauthn';
import type { WebAuthnCeremony } from '@arkenivajs/security-webauthn';
import { authenticator } from './webauthn-authenticator.js';
import { webAuthnServiceFixture } from './webauthn-service-fixture.js';

const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
function challenge(ceremony: WebAuthnCeremony) {
  assert.equal(typeof ceremony.optionsJSON.challenge, 'string');
  return ceremony.optionsJSON.challenge as string;
}
for (const algorithm of ['RS256', 'EdDSA'] as const)
  test(
    `Actual PostgreSQL and signed application authority persist ${algorithm} credentials and accept a shared ceremony once`,
    { timeout: 30000 },
    async () => {
      const f = await webAuthnServiceFixture('https://example.test');
      try {
        const owner = await f.subject({ acr: 'urn:fixture:reauthenticated' }),
          device = authenticator(algorithm),
          peer = createWebAuthnService(f.settings);
        f.approveEnrollment(owner);
        await assert.rejects(
          f.service.beginRegistration(Object.freeze({ ...owner })),
          code('EK_AUTH_FORBIDDEN'),
        );
        const registration = await f.service.beginRegistration(owner);
        await peer.finishRegistration(
          owner,
          registration.ceremonyId,
          device.registration(challenge(registration), {
            origin: 'https://example.test',
            counter: 0,
          }),
        );
        const stored = await f.state.getCredential(device.id, 'example.test');
        assert.ok(stored);
        assert.deepEqual(stored.publicKey, device.publicKey);
        assert.equal(stored.tenantId, 'tenant-a');
        assert.equal(stored.counter, 0);
        const invalid = await f.service.beginAuthentication(owner),
          corrupt = device.authentication(challenge(invalid), { origin: 'https://example.test' }),
          signature = Buffer.from(corrupt.response.signature!, 'base64url');
        signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
        corrupt.response.signature = signature.toString('base64url');
        await assert.rejects(
          peer.finishAuthentication(owner, invalid.ceremonyId, corrupt),
          code('EK_MFA_INVALID'),
        );
        assert.equal((await f.state.getCredential(device.id, 'example.test'))!.counter, 0);
        const ceremony = await f.service.beginAuthentication(owner),
          response = device.authentication(challenge(ceremony), { origin: 'https://example.test' }),
          attempts = await Promise.allSettled([
            f.service.finishAuthentication(owner, ceremony.ceremonyId, response),
            peer.finishAuthentication(owner, ceremony.ceremonyId, response),
          ]),
          accepted = attempts.filter((result) => result.status === 'fulfilled');
        assert.equal(accepted.length, 1);
        assert.equal((await f.state.getCredential(device.id, 'example.test'))!.counter, 1);
        const result = accepted[0]!.value,
          binding = {
            evidenceId: result.evidenceId,
            issuer: owner.issuer,
            subject: owner.subject,
            tenantId: owner.tenant!.tenantId,
            primarySessionId: owner.primarySessionId,
            now: new Date(f.clock()).toISOString(),
          };
        assert.equal(result.assurance, 'phishing-resistant');
        assert.ok(await f.evidence.consume(binding));
        assert.equal(await f.evidence.consume(binding), null);
        await assert.rejects(
          peer.finishAuthentication(owner, ceremony.ceremonyId, response),
          code('EK_MFA_CHALLENGE_EXPIRED'),
        );
        const foreign = await f.subject({ tenant_id: 'tenant-b', sid: 'foreign-session' });
        assert.deepEqual(await peer.listCredentials(foreign), []);
        await assert.rejects(peer.beginAuthentication(foreign), code('EK_MFA_INVALID'));
        const anonymous = await peer.beginPasswordless(),
          verified = await f.service.finishPasswordless(
            anonymous.ceremonyId,
            device.authentication(challenge(anonymous), {
              origin: 'https://example.test',
              counter: 2,
            }),
          );
        assert.equal(verified.subject, owner.subject);
        assert.equal(verified.tenantId, 'tenant-a');
        assert.equal((await f.state.getCredential(device.id, 'example.test'))!.counter, 2);
      } finally {
        await f.close();
      }
    },
  );

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { jwtVerify, calculateJwkThumbprint } from 'jose';
import { capture } from '../../dist/settings.js';
import { createFederationEntityConfiguration } from '../../dist/entity-configuration.js';
import { transactionFixture } from '../fixtures/transactions.js';
import { registration, signed } from '../fixtures/registration.js';

const signing = generateKeyPairSync('rsa', { modulusLength: 2048 }),
  decrypt = generateKeyPairSync('rsa', { modulusLength: 2048 });
async function fixture() {
  const f = await transactionFixture(),
    input = await registration(f.profile.entityId),
    settings = { ...f.settings, profiles: [{ ...f.profile, oidcRegistration: input }] };
  f.material.set('signing-ref', {
    bytes: Buffer.from(signing.privateKey.export({ format: 'pem', type: 'pkcs8' })),
    keyVersion: 'fixture',
  });
  f.material.set(input.decryptionKeyRef, {
    bytes: Buffer.from(decrypt.privateKey.export({ format: 'pem', type: 'pkcs8' })),
    keyVersion: 'fixture',
  });
  return { ...f, settings, configuration: capture(settings, 'test') };
}
test('Real JOSE entity configurations publish only captured registration and separate public key roles', async () => {
  const f = await fixture();
  try {
    const token = await f.runtime.run((call) =>
        createFederationEntityConfiguration(call, f.configuration, f.profile.profileId),
      ),
      verified = await jwtVerify(token, signing.publicKey, {
        algorithms: ['RS256'],
        issuer: f.profile.entityId,
        subject: f.profile.entityId,
        typ: 'entity-statement+jwt',
      }),
      payload = verified.payload,
      metadata = payload.metadata as Record<string, Record<string, unknown>>,
      rp = metadata.openid_relying_party!,
      organization = metadata.federation_entity!,
      jwks = rp.jwks as { keys: Record<string, unknown>[] };
    assert.equal(rp.client_id, f.profile.entityId);
    assert.deepEqual(rp.redirect_uris, [f.profile.redirectUri]);
    assert.deepEqual(rp.client_registration_types, ['automatic']);
    assert.equal(rp.token_endpoint_auth_method, 'private_key_jwt');
    assert.equal(rp.id_token_signed_response_alg, 'RS512');
    assert.equal(rp.userinfo_encrypted_response_alg, 'RSA-OAEP-256');
    assert.equal(rp.id_token_encrypted_response_alg, undefined);
    assert.equal(organization.organization_name, 'Fixture Organization');
    assert.equal(organization.federation_resolve_endpoint, 'https://service.example.test/resolve');
    assert.deepEqual(payload.authority_hints, ['https://anchor.example.test']);
    assert.ok(
      verified.payload.exp! <= verified.payload.iat! + f.profile.metadata.refreshIntervalSeconds,
    );
    assert.equal(jwks.keys.length, 2);
    assert.deepEqual(
      jwks.keys.map((key) => key.use),
      ['sig', 'enc'],
    );
    assert.notEqual(jwks.keys[0]!.kid, jwks.keys[1]!.kid);
    assert.equal(verified.protectedHeader.kid, await calculateJwkThumbprint(jwks.keys[0]!));
    for (const key of jwks.keys)
      for (const property of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'keyVersion'])
        assert.equal(key[property], undefined);
    const contents = JSON.stringify(payload);
    for (const reference of [
      'signing-ref',
      'oidc-decryption-ref',
      'state-encryption-current',
      'state-mac-current',
    ])
      assert.ok(!contents.includes(reference));
    assert.equal('trusted' in payload, false);
    assert.equal('tenantId' in payload, false);
  } finally {
    await f.close();
  }
});
test('Entity configuration expiry is bounded by external key material and received marks', async (t) => {
  const f = await fixture();
  try {
    const expiry = Math.floor(Date.now() / 1000) + 25,
      input = {
        ...f.settings.profiles[0]!.oidcRegistration!,
        trustMarks: [await signed(f.profile.entityId, { exp: expiry })],
      },
      markSettings = capture(
        { ...f.settings, profiles: [{ ...f.profile, oidcRegistration: input }] },
        'test',
      ),
      settings = capture(
        {
          ...f.settings,
          profiles: [{ ...f.profile, oidcRegistration: input }],
          secretProvider: {
            async get(reference) {
              const value = f.material.get(reference)!;
              return { ...value, expiresAt: new Date((expiry - 5) * 1000).toISOString() };
            },
          },
        },
        'test',
      ),
      token = await f.runtime.run((call) =>
        createFederationEntityConfiguration(call, settings, f.profile.profileId),
      );
    assert.equal((await jwtVerify(token, signing.publicKey)).payload.exp, expiry - 5);
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    t.mock.timers.tick(26000);
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          createFederationEntityConfiguration(call, markSettings, f.profile.profileId),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    t.mock.timers.reset();
    await f.close();
  }
});
test('A second reference resolving to the signing key cannot masquerade as a separate encryption key', async () => {
  const f = await fixture();
  try {
    const settings = capture(
      {
        ...f.settings,
        secretProvider: {
          async get() {
            return f.material.get('signing-ref')!;
          },
        },
      },
      'test',
    );
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          createFederationEntityConfiguration(call, settings, f.profile.profileId),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});
test('The encoded JWS budget includes headers, base64 expansion and the real signature', async () => {
  const f = await fixture();
  try {
    const token = await f.runtime.run((call) =>
        createFederationEntityConfiguration(call, f.configuration, f.profile.profileId),
      ),
      payloadBytes = Buffer.from(token.split('.')[1]!, 'base64url').byteLength,
      maximum = Math.ceil((payloadBytes + Buffer.byteLength(token)) / 2),
      settings = capture(
        { ...f.settings, policy: { ...f.settings.policy, maxOutputBytes: maximum } },
        'test',
      );
    assert.ok(payloadBytes < maximum && maximum < Buffer.byteLength(token));
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          createFederationEntityConfiguration(call, settings, f.profile.profileId),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});
test('Missing registration, provider errors, foreign profiles and encoded-output overflow yield no configuration', async () => {
  const f = await fixture();
  try {
    const absent = capture({ ...f.settings, profiles: [f.profile] }, 'test'),
      bounded = capture(
        { ...f.settings, policy: { ...f.settings.policy, maxOutputBytes: 100 } },
        'test',
      ),
      failed = capture(
        {
          ...f.settings,
          secretProvider: {
            async get(): Promise<never> {
              throw new Error('Private metadata material');
            },
          },
        },
        'test',
      );
    for (const settings of [absent, bounded, failed])
      await assert.rejects(
        () =>
          f.runtime.run((call) =>
            createFederationEntityConfiguration(call, settings, f.profile.profileId),
          ),
        { code: 'EK_EID_FEDERATION' },
      );
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          createFederationEntityConfiguration(call, f.configuration, 'foreign-profile'),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});

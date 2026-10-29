// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { CompactEncrypt, SignJWT, compactDecrypt, calculateJwkThumbprint, exportJWK } from 'jose';
import {
  Configuration,
  customFetch,
  enableDecryptingResponses,
  enableNonRepudiationChecks,
  fetchUserInfo,
} from 'openid-client';
import { capture } from '../../dist/settings.js';
import { loadFederationDecryptionKey } from '../../dist/decryption.js';
import { registration } from '../fixtures/registration.js';
import { transactionFixture } from '../fixtures/transactions.js';

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }),
  other = generateKeyPairSync('rsa', { modulusLength: 2048 }),
  weak = generateKeyPairSync('rsa', { modulusLength: 1024 }),
  ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const encoded = (pair = rsa) =>
  Buffer.from(pair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
async function fixture() {
  const f = await transactionFixture();
  const input = await registration(f.profile.entityId);
  f.material.set(input.decryptionKeyRef, { bytes: encoded(), keyVersion: 'fixture' });
  const settings = {
    ...f.settings,
    profiles: [
      {
        ...f.profile,
        oidcRegistration: {
          ...input,
          idTokenEncryption: {
            algorithm: 'RSA-OAEP' as const,
            encryption: 'A128CBC-HS256' as const,
          },
        },
      },
    ],
  };
  return { ...f, settings, configuration: capture(settings, 'test') };
}
test('External decryption keys remain non-extractable and decrypt all prescribed native JWE combinations', async () => {
  const f = await fixture();
  try {
    const before = Buffer.from(f.material.get('oidc-decryption-ref')!.bytes),
      material = await f.runtime.run((call) =>
        loadFederationDecryptionKey(call, f.configuration, f.profile.profileId),
      );
    assert.equal(material.publicJwk.kid, await calculateJwkThumbprint(material.publicJwk));
    assert.equal(material.publicJwk.use, 'enc');
    assert.equal(material.publicJwk.d, undefined);
    assert.equal('keyVersion' in material.publicJwk, false);
    assert.ok(Object.isFrozen(material.keys));
    for (const item of material.keys) {
      assert.equal(item.key.extractable, false);
      assert.deepEqual(item.key.usages, ['decrypt']);
      await assert.rejects(() => webcrypto.subtle.exportKey('pkcs8', item.key));
      for (const encryption of ['A128CBC-HS256', 'A256CBC-HS512']) {
        const plaintext = new TextEncoder().encode('Native encrypted fixture'),
          token = await new CompactEncrypt(plaintext)
            .setProtectedHeader({ alg: item.alg, enc: encryption, kid: item.kid })
            .encrypt(rsa.publicKey),
          verified = await compactDecrypt(token, item.key, {
            keyManagementAlgorithms: [item.alg],
            contentEncryptionAlgorithms: [encryption],
          });
        assert.deepEqual(verified.plaintext, plaintext);
        verified.plaintext.fill(0);
        plaintext.fill(0);
      }
    }
    assert.deepEqual(f.material.get('oidc-decryption-ref')!.bytes, before);
    before.fill(0);
  } finally {
    await f.close();
  }
});
test('The selected OpenID SDK verifies signed encrypted UserInfo with the imported native key', async () => {
  const f = await fixture();
  try {
    const material = await f.runtime.run((call) =>
        loadFederationDecryptionKey(call, f.configuration, f.profile.profileId),
      ),
      issuer = f.input.issuer,
      clientId = f.profile.clientId!,
      config = new Configuration(
        { issuer, userinfo_endpoint: issuer + '/userinfo', jwks_uri: issuer + '/jwks' },
        clientId,
        {
          userinfo_signed_response_alg: 'RS256',
          userinfo_encrypted_response_alg: 'RSA-OAEP-256',
          userinfo_encrypted_response_enc: 'A256CBC-HS512',
        },
      ),
      jwk = await exportJWK(other.publicKey),
      signed = await new SignJWT({ sub: 'native-subject', name: 'Verified Fixture' })
        .setProtectedHeader({ alg: 'RS256', kid: 'native-op' })
        .setIssuer(issuer)
        .setAudience(clientId)
        .setIssuedAt()
        .setExpirationTime('1m')
        .sign(other.privateKey),
      encrypted = await new CompactEncrypt(new TextEncoder().encode(signed))
        .setProtectedHeader({
          alg: 'RSA-OAEP-256',
          enc: 'A256CBC-HS512',
          kid: material.publicJwk.kid,
          cty: 'JWT',
        })
        .encrypt(rsa.publicKey),
      requests: string[] = [];
    let response = encrypted;
    config[customFetch] = async (input) => {
      const target = String(input);
      requests.push(target);
      if (target === issuer + '/userinfo')
        return new Response(response, { headers: { 'content-type': 'application/jwt' } });
      assert.equal(target, issuer + '/jwks');
      return Response.json({ keys: [{ ...jwk, kid: 'native-op', alg: 'RS256', use: 'sig' }] });
    };
    enableDecryptingResponses(config, ['A256CBC-HS512'], ...material.keys);
    enableNonRepudiationChecks(config);
    const result = await fetchUserInfo(config, 'fixture-access-token', 'native-subject');
    assert.equal(result.sub, 'native-subject');
    assert.equal(result.name, 'Verified Fixture');
    assert.deepEqual(requests, [issuer + '/userinfo', issuer + '/jwks']);
    await assert.rejects(() => fetchUserInfo(config, 'fixture-access-token', 'foreign-subject'));
    const forged = await new SignJWT({ sub: 'native-subject' })
      .setProtectedHeader({ alg: 'RS256', kid: 'native-op' })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setIssuedAt()
      .setExpirationTime('1m')
      .sign(rsa.privateKey);
    response = await new CompactEncrypt(new TextEncoder().encode(forged))
      .setProtectedHeader({
        alg: 'RSA-OAEP-256',
        enc: 'A256CBC-HS512',
        kid: material.publicJwk.kid,
      })
      .encrypt(rsa.publicKey);
    await assert.rejects(() => fetchUserInfo(config, 'fixture-access-token', 'native-subject'));
    const parts = encrypted.split('.'),
      tag = Buffer.from(parts[4]!, 'base64url');
    tag[0] = tag[0]! ^ 1;
    parts[4] = tag.toString('base64url');
    response = parts.join('.');
    await assert.rejects(() => fetchUserInfo(config, 'fixture-access-token', 'native-subject'));
  } finally {
    await f.close();
  }
});
test('Missing registration, weak, public-only, malformed and non-RSA material cannot become decryptors', async () => {
  const f = await fixture();
  try {
    for (const bytes of [
      encoded(weak),
      encoded(ec),
      Buffer.from(rsa.publicKey.export({ format: 'pem', type: 'spki' })),
      Buffer.from('invalid-material'),
      new Uint8Array(new SharedArrayBuffer(32)),
    ]) {
      const settings = capture(
        {
          ...f.settings,
          secretProvider: {
            async get() {
              return { bytes, keyVersion: 'fixture' };
            },
          },
        },
        'test',
      );
      await assert.rejects(
        () =>
          f.runtime.run((call) => loadFederationDecryptionKey(call, settings, f.profile.profileId)),
        { code: 'EK_EID_FEDERATION' },
      );
    }
    const absent = capture({ ...f.settings, profiles: [f.profile] }, 'test');
    await assert.rejects(
      () => f.runtime.run((call) => loadFederationDecryptionKey(call, absent, f.profile.profileId)),
      { code: 'EK_EID_FEDERATION' },
    );
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          loadFederationDecryptionKey(call, f.configuration, 'foreign-profile'),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});
test('Expired, unavailable and executable provider material fail closed without leaking diagnostics', async (t) => {
  const f = await fixture();
  let effects = 0;
  try {
    for (const get of [
      async () => ({
        bytes: encoded(),
        keyVersion: 'fixture',
        expiresAt: new Date(Date.now() - 1).toISOString(),
      }),
      async () => ({
        get bytes() {
          effects++;
          return encoded();
        },
        keyVersion: 'fixture',
      }),
      async () => {
        throw new Error('Private decrypt fixture diagnostic');
      },
    ]) {
      const settings = capture({ ...f.settings, secretProvider: { get } }, 'test');
      await assert.rejects(
        () =>
          f.runtime.run((call) => loadFederationDecryptionKey(call, settings, f.profile.profileId)),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.equal((error as Error & { code: string }).code, 'EK_EID_FEDERATION');
          assert.doesNotMatch(error.message, /Private decrypt/);
          return true;
        },
      );
    }
    assert.equal(effects, 0);
    const expiry = Date.now() + 30000,
      settings = capture(
        {
          ...f.settings,
          secretProvider: {
            async get() {
              return {
                bytes: encoded(),
                keyVersion: 'fixture',
                expiresAt: new Date(expiry).toISOString(),
              };
            },
          },
        },
        'test',
      ),
      material = await f.runtime.run((call) =>
        loadFederationDecryptionKey(call, settings, f.profile.profileId),
      );
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    t.mock.timers.tick(31000);
    assert.throws(material.check, { code: 'EK_EID_FEDERATION' });
  } finally {
    t.mock.timers.reset();
    await f.close();
  }
});
test('Late decryption-provider work retains physical admission after the public timeout', async () => {
  const f = await fixture();
  let release!: () => void, entered!: () => void;
  const pending = new Promise<void>((resolve) => {
      release = resolve;
    }),
    began = new Promise<void>((resolve) => {
      entered = resolve;
    });
  try {
    const settings = capture(
        {
          ...f.settings,
          secretProvider: {
            async get() {
              entered();
              await pending;
              return { bytes: encoded(), keyVersion: 'fixture' };
            },
          },
        },
        'test',
      ),
      work = f.runtime.run(
        (call) => loadFederationDecryptionKey(call, settings, f.profile.profileId),
        { timeoutMs: 100 },
      ),
      rejected = assert.rejects(work, { code: 'EK_TIMEOUT' });
    await began;
    await rejected;
    assert.equal(f.runtime.stats().active, 1);
  } finally {
    release();
    await f.close();
  }
});

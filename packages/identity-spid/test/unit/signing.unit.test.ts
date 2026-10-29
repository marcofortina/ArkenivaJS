// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { SignJWT, jwtVerify, calculateJwkThumbprint } from 'jose';
import { Configuration, PrivateKeyJwt, buildAuthorizationUrlWithJAR } from 'openid-client';
import { capture } from '../../dist/settings.js';
import { loadFederationSigningKey } from '../../dist/signing.js';
import type { FederationSignatureAlgorithm } from '../../dist/signing.js';
import { transactionFixture } from '../fixtures/transactions.js';

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }),
  weak = generateKeyPairSync('rsa', { modulusLength: 1024 }),
  ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
  ec384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }),
  ec512 = generateKeyPairSync('ec', { namedCurve: 'secp521r1' }),
  ed = generateKeyPairSync('ed25519');
function encoded(key: KeyObject, format: 'pem' | 'der') {
  return format === 'der'
    ? key.export({ format, type: 'pkcs8' })
    : Buffer.from(key.export({ format, type: 'pkcs8' }));
}
test('Imported external RSA/EC keys produce real JOSE signatures and RFC7638 public identifiers', async () => {
  const f = await transactionFixture();
  try {
    for (const [algorithm, pair, format] of [
      ['RS256', rsa, 'pem'],
      ['RS512', rsa, 'der'],
      ['PS256', rsa, 'pem'],
      ['PS384', rsa, 'pem'],
      ['PS512', rsa, 'der'],
      ['ES256', ec, 'pem'],
      ['ES384', ec384, 'der'],
      ['ES512', ec512, 'pem'],
    ] as const) {
      const source = encoded(pair.privateKey, format),
        before = Buffer.from(source);
      f.material.set('signing-ref', { bytes: source, keyVersion: 'fixture' });
      const signer = await f.runtime.run((call) =>
        loadFederationSigningKey(call, capture(f.settings, 'test'), f.profile.profileId, algorithm),
      );
      assert.equal(signer.key.extractable, false);
      assert.equal(signer.key.type, 'private');
      assert.deepEqual(signer.key.usages, ['sign']);
      assert.equal(signer.kid, await calculateJwkThumbprint(signer.publicJwk));
      assert.equal(signer.publicJwk.d, undefined);
      assert.equal('keyVersion' in signer.publicJwk, false);
      assert.deepEqual(source, before, 'Import must not mutate provider-owned material');
      const token = await new SignJWT({ sub: 'verified-fixture' })
        .setProtectedHeader({ alg: algorithm, kid: signer.kid })
        .setIssuer(f.profile.entityId)
        .setIssuedAt()
        .setExpirationTime('1m')
        .sign(signer.key);
      const verified = await jwtVerify(token, pair.publicKey, {
        algorithms: [algorithm],
        issuer: f.profile.entityId,
      });
      assert.equal(verified.protectedHeader.kid, signer.kid);
      await assert.rejects(
        () => webcrypto.subtle.exportKey('pkcs8', signer.key),
        (error: unknown) => {
          assert.ok(error instanceof Error);
          // Node 22 retains the older DOMException name for the same forbidden export.
          assert.ok(['InvalidAccessError', 'InvalidAccessException'].includes(error.name));
          return true;
        },
      );
      source.fill(0);
      before.fill(0);
    }
  } finally {
    await f.close();
  }
});
test('The selected OpenID SDK signs an actual JAR with the non-extractable key and thumbprint kid', async () => {
  const f = await transactionFixture();
  try {
    f.material.set('signing-ref', {
      bytes: encoded(rsa.privateKey, 'der'),
      keyVersion: 'fixture',
    });
    const signer = await f.runtime.run((call) =>
        loadFederationSigningKey(call, capture(f.settings, 'test'), f.profile.profileId, 'RS512'),
      ),
      server = {
        issuer: f.input.issuer,
        authorization_endpoint: f.input.issuer + '/authorize',
        token_endpoint: f.input.issuer + '/token',
      },
      config = new Configuration(
        server,
        f.profile.clientId!,
        { token_endpoint_auth_signing_alg: signer.algorithm },
        PrivateKeyJwt({ key: signer.key, kid: signer.kid }),
      ),
      result = await buildAuthorizationUrlWithJAR(
        config,
        {
          response_type: 'code',
          scope: 'openid',
          redirect_uri: f.profile.redirectUri,
          nonce: 'a'.repeat(64),
          state: 'b'.repeat(64),
        },
        { key: signer.key, kid: signer.kid },
      );
    assert.equal(result.origin, new URL(server.authorization_endpoint).origin);
    const request = result.searchParams.get('request');
    assert.ok(request);
    const verified = await jwtVerify(request, rsa.publicKey, {
      algorithms: ['RS512'],
      issuer: f.profile.clientId!,
      audience: server.issuer,
    });
    assert.equal(verified.protectedHeader.kid, signer.kid);
    assert.equal(verified.payload.scope, 'openid');
    assert.equal(verified.payload.redirect_uri, f.profile.redirectUri);
    assert.equal(verified.payload.state, 'b'.repeat(64));
  } finally {
    await f.close();
  }
});
test('Public-only, malformed, shared, weak and algorithm-incompatible material cannot become signing keys', async () => {
  const f = await transactionFixture();
  try {
    for (const [bytes, algorithm] of [
      [Buffer.from(rsa.publicKey.export({ format: 'pem', type: 'spki' })), 'RS256'],
      [Buffer.from('invalid-private-material'), 'RS256'],
      [new Uint8Array(), 'RS256'],
      [new Uint8Array(16385), 'RS256'],
      [encoded(weak.privateKey, 'pem'), 'RS256'],
      [encoded(ec.privateKey, 'pem'), 'RS512'],
      [encoded(rsa.privateKey, 'pem'), 'ES256'],
      [encoded(ed.privateKey, 'pem'), 'RS256'],
      [new Uint8Array(new SharedArrayBuffer(32)), 'RS256'],
    ] as const) {
      const settings = capture(
        {
          ...f.settings,
          secretProvider: {
            async get() {
              return { bytes, keyVersion: 'opaque-version' };
            },
          },
        },
        'test',
      );
      await assert.rejects(
        () =>
          f.runtime.run((call) =>
            loadFederationSigningKey(call, settings, f.profile.profileId, algorithm),
          ),
        { code: 'EK_EID_FEDERATION' },
      );
    }
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          loadFederationSigningKey(
            call,
            capture(f.settings, 'test'),
            f.profile.profileId,
            'HS256' as FederationSignatureAlgorithm,
          ),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
  } finally {
    await f.close();
  }
});
test('Runtime provider metadata and expiry cannot be bypassed with executable or manually constructed objects', async (t) => {
  const f = await transactionFixture();
  let effects = 0;
  try {
    const source = encoded(rsa.privateKey, 'pem');
    const providers = [
      {
        async get() {
          return { bytes: source, keyVersion: '' };
        },
      },
      {
        async get() {
          return { bytes: source, keyVersion: 'label', expiresAt: 'invalid' };
        },
      },
      {
        async get() {
          return {
            bytes: source,
            keyVersion: 'label',
            expiresAt: new Date(Date.now() - 1).toISOString(),
          };
        },
      },
      {
        async get() {
          return {
            get bytes() {
              effects++;
              return source;
            },
            keyVersion: 'label',
          };
        },
      },
    ];
    for (const secretProvider of providers)
      await assert.rejects(
        () =>
          f.runtime.run((call) =>
            loadFederationSigningKey(
              call,
              capture({ ...f.settings, secretProvider }, 'test'),
              f.profile.profileId,
              'RS256',
            ),
          ),
        { code: 'EK_EID_FEDERATION' },
      );
    assert.equal(effects, 0);
    const expires = Date.now() + 30000,
      settings = capture(
        {
          ...f.settings,
          secretProvider: {
            async get() {
              return {
                bytes: source,
                keyVersion: 'label',
                expiresAt: new Date(expires).toISOString(),
              };
            },
          },
        },
        'test',
      ),
      signer = await f.runtime.run((call) =>
        loadFederationSigningKey(call, settings, f.profile.profileId, 'RS256'),
      );
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
    t.mock.timers.tick(31000);
    assert.throws(signer.check, { code: 'EK_EID_FEDERATION' });
    source.fill(0);
  } finally {
    t.mock.timers.reset();
    await f.close();
  }
});
test('Secret-provider failure and late work cannot produce a signer or release physical admission early', async () => {
  const f = await transactionFixture();
  let release!: () => void, entered!: () => void;
  const pending = new Promise<void>((resolve) => {
      release = resolve;
    }),
    began = new Promise<void>((resolve) => {
      entered = resolve;
    });
  const source = encoded(rsa.privateKey, 'pem');
  try {
    const failed = capture(
      {
        ...f.settings,
        secretProvider: {
          async get(): Promise<never> {
            throw new Error('Private fixture diagnostic');
          },
        },
      },
      'test',
    );
    await assert.rejects(
      () =>
        f.runtime.run((call) =>
          loadFederationSigningKey(call, failed, f.profile.profileId, 'RS256'),
        ),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal((error as Error & { code: string }).code, 'EK_EID_FEDERATION');
        assert.doesNotMatch(error.message, /Private fixture/);
        return true;
      },
    );
    const late = capture(
        {
          ...f.settings,
          secretProvider: {
            async get() {
              entered();
              await pending;
              return { bytes: source, keyVersion: 'label' };
            },
          },
        },
        'test',
      ),
      work = f.runtime.run(
        (call) => loadFederationSigningKey(call, late, f.profile.profileId, 'RS256'),
        { timeoutMs: 100 },
      );
    const rejected = assert.rejects(work, { code: 'EK_TIMEOUT' });
    await began;
    await rejected;
    assert.equal(f.runtime.stats().active, 1);
  } finally {
    release();
    await f.close();
    source.fill(0);
  }
});

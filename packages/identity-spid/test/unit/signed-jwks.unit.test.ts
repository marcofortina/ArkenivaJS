// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportSPKI, exportJWK, SignJWT } from 'jose';
import { anchorKeys, verifyFederationToken } from '../../dist/statements.js';

const pair = await generateKeyPair('ES256'),
  issuer = 'https://idp.example.test',
  jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'federated-public' }] },
  expires = Math.floor(Date.now() / 1000) + 300,
  keys = anchorKeys(
    [
      {
        issuer,
        kid: 'federated-public',
        publicKeyPem: await exportSPKI(pair.publicKey),
        validFrom: new Date(Date.now() - 60000).toISOString(),
        expiresAt: new Date(expires * 1000).toISOString(),
      },
    ],
    issuer,
  );
const signed = (claims: Record<string, unknown> = {}, type = 'jwk-set+jwt') =>
  new SignJWT({ iss: issuer, sub: issuer, keys: jwks.keys, ...claims })
    .setProtectedHeader({ alg: 'ES256', typ: type, kid: 'federated-public' })
    .sign(pair.privateKey);
const expected = {
  issuer,
  subject: issuer,
  keys,
  maxBytes: 8192,
  type: 'jwk-set+jwt' as const,
  requiredClaims: ['sub', 'keys'],
};
test('Signed JWK sets permit optional timestamps while current delegated key validity bounds evidence', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const claims of [{}, { iat: now - 1 }, { exp: now + 30 }, { iat: now - 1, exp: now + 30 }]) {
    const verified = await verifyFederationToken(await signed(claims), expected);
    assert.ok(verified.expiresAt <= expires);
    const returned = verified.claims.keys as readonly Record<string, unknown>[];
    assert.ok(returned.every((key) => Object.getPrototypeOf(key) === null));
    assert.deepEqual(
      returned.map((key) => ({ ...key })),
      jwks.keys,
    );
    if (claims.exp !== undefined) assert.equal(verified.expiresAt, claims.exp);
  }
});
test('Present signed-set timestamps, issuer, subject, critical claims and token type remain strict', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const claims of [
    { iat: now + 100 },
    { iat: -1 },
    { iat: 1.5 },
    { exp: now - 1 },
    { exp: 'future' },
    { iss: 'https://foreign.example.test' },
    { sub: 'https://foreign.example.test' },
    { crit: ['unsupported'] },
  ])
    await assert.rejects(
      () => signed(claims).then((token) => verifyFederationToken(token, expected)),
      { code: 'EK_EID_FEDERATION' },
    );
  await assert.rejects(
    () => signed({}, 'JWT').then((token) => verifyFederationToken(token, expected)),
    { code: 'EK_EID_FEDERATION' },
  );
});
test('Entity, mark and status signatures cannot borrow the optional JWK-set issued-at rule', async () => {
  for (const type of [
    'entity-statement+jwt',
    'trust-mark+jwt',
    'trust-mark-status-response+jwt',
  ] as const)
    await assert.rejects(
      () =>
        signed({ exp: Math.floor(Date.now() / 1000) + 60 }, type).then((token) =>
          verifyFederationToken(token, { ...expected, type }),
        ),
      { code: 'EK_EID_FEDERATION' },
    );
});

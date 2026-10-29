// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, exportSPKI, SignJWT } from 'jose';
import { anchorKeys, verifyStatement } from '../../dist/statements.js';

const issuer = 'https://anchor.example.test',
  subject = 'https://idp.example.test';
const pair = await generateKeyPair('RS256', { modulusLength: 2048 });
const other = await generateKeyPair('RS256', { modulusLength: 2048 });
const jwks = { keys: [{ ...(await exportJWK(other.publicKey)), kid: 'provider-public' }] };
const roots = [
  {
    kid: 'root-public',
    issuer,
    publicKeyPem: await exportSPKI(pair.publicKey),
    validFrom: new Date(Date.now() - 60000).toISOString(),
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
  },
];
const expected = { issuer, subject, maxBytes: 65536, keys: anchorKeys(roots, issuer) };
const timestamp = () => Math.floor(Date.now() / 1000);
async function token(
  claims: Readonly<Record<string, unknown>> = {},
  header: Record<string, string> = {},
) {
  return new SignJWT({
    iss: issuer,
    sub: subject,
    iat: timestamp(),
    exp: timestamp() + 60,
    jwks,
    ...claims,
  })
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'entity-statement+jwt',
      kid: 'root-public',
      ...header,
    })
    .sign(pair.privateKey);
}
test('JOSE verifies a bounded root-signed entity statement and public descendant keys', async () => {
  const verified = await verifyStatement(
    await token({
      metadata_policy: { openid_provider: { response_types_supported: { subset_of: ['code'] } } },
      unused: [],
    }),
    expected,
  );
  assert.equal(verified.issuer, issuer);
  assert.equal(verified.subject, subject);
  assert.equal(verified.keys.length, 1);
  assert.equal(verified.keys[0]!.kid, 'provider-public');
  assert.equal(verified.keys[0]!.publicKey.type, 'public');
  assert.ok(Object.isFrozen(verified.claims));
  assert.ok(Object.isFrozen(verified.keys));
  assert.ok(verified.expiresAt > verified.issuedAt);
  assert.equal('trusted' in verified, false, 'Signature evidence is not a complete trust decision');
});
test('Wrong signatures, issuer, subject, key IDs and protocol headers fail with safe errors', async () => {
  const signed = await token();
  const wrong = new SignJWT({
    iss: issuer,
    sub: subject,
    iat: timestamp(),
    exp: timestamp() + 60,
    jwks,
  }).setProtectedHeader({ alg: 'RS256', typ: 'entity-statement+jwt', kid: 'root-public' });
  const wrongSignature = await wrong.sign(other.privateKey);
  await assert.rejects(() => verifyStatement(wrongSignature, expected), {
    code: 'EK_EID_FEDERATION',
  });
  for (const encoded of [
    await token({ iss: 'https://foreign.example.test' }),
    await token({ sub: 'https://foreign.example.test' }),
    await token({}, { kid: 'unknown' }),
    await token({}, { typ: 'JWT' }),
    await token({}, { jku: 'https://unapproved.example.test/keys' }),
  ]) {
    await assert.rejects(
      () => verifyStatement(encoded, expected),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal((error as Error & { code: string }).code, 'EK_EID_FEDERATION');
        assert.doesNotMatch(error.message, /foreign|unapproved|root-public/);
        return true;
      },
    );
  }
  await assert.rejects(
    () => verifyStatement(signed, { ...expected, keys: [...expected.keys, ...expected.keys] }),
    { code: 'EK_EID_FEDERATION' },
  );
  await assert.rejects(
    () =>
      verifyStatement(signed, {
        ...expected,
        keys: [{ ...expected.keys[0]!, algorithm: 'RS512' }],
      }),
    { code: 'EK_EID_FEDERATION' },
  );
});
test('Expired, future-issued, missing and non-integer temporal claims fail closed', async () => {
  for (const claims of [
    { exp: timestamp() - 1 },
    { iat: timestamp() + 60 },
    { iat: 1.5 },
    { exp: timestamp() + 60.5 },
    { exp: undefined },
    { iat: undefined },
    { exp: timestamp(), iat: timestamp() },
  ]) {
    const encoded = await token(claims);
    await assert.rejects(() => verifyStatement(encoded, expected), { code: 'EK_EID_FEDERATION' });
  }
});
test('Statement bounds and public JWKS policy reject excess, malformed and private material', async () => {
  const signed = await token();
  await assert.rejects(() => verifyStatement(signed, { ...expected, maxBytes: 32 }), {
    code: 'EK_EID_FEDERATION',
  });
  await assert.rejects(() => verifyStatement('not-a-compact-jwt', expected), {
    code: 'EK_EID_FEDERATION',
  });
  for (const keys of [
    [],
    [jwks.keys[0], jwks.keys[0]],
    [{ ...jwks.keys[0], kid: undefined }],
    [{ ...jwks.keys[0], use: 'enc' }],
    [{ ...jwks.keys[0], d: 'invalid-private-component' }],
    [{ kty: 'oct', kid: 'symmetric' }],
  ]) {
    const encoded = await token({ jwks: { keys } });
    await assert.rejects(() => verifyStatement(encoded, expected), { code: 'EK_EID_FEDERATION' });
  }
});

test('Pinned trust-root validity bounds signatures and descendant key lifetime', async () => {
  const encoded = await token();
  const until = Date.now() + 30000;
  const verified = await verifyStatement(encoded, {
    ...expected,
    keys: [{ ...expected.keys[0]!, expiresAt: until }],
  });
  assert.equal(verified.expiresAt, until / 1000);
  assert.equal(verified.keys[0]!.expiresAt, until);
  for (const timing of [
    { expiresAt: Date.now() - 1 },
    { validFrom: Date.now() + 60000 },
    { expiresAt: NaN },
  ])
    await assert.rejects(
      () => verifyStatement(encoded, { ...expected, keys: [{ ...expected.keys[0]!, ...timing }] }),
      { code: 'EK_EID_FEDERATION' },
    );
  assert.throws(() => anchorKeys(roots, 'https://unconfigured.example.test'), {
    code: 'EK_EID_FEDERATION',
  });
  assert.throws(
    () => anchorKeys([{ ...roots[0]!, expiresAt: new Date(Date.now() - 1).toISOString() }], issuer),
    { code: 'EK_EID_FEDERATION' },
  );
});

test('Statement cancellation remains distinct from a failed signature and does not yield evidence', async () => {
  const encoded = await token();
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    () => verifyStatement(encoded, expected, { signal: controller.signal, timeoutMs: 1000 }),
    { code: 'EK_ABORTED' },
  );
});

test('Deep signed metadata and prototype-like keys are rejected despite a valid signature', async () => {
  let nested: unknown = {};
  for (let depth = 0; depth < 20; depth++) nested = { nested };
  for (const metadata of [nested, JSON.parse('{"__proto__":{"polluted":true}}')]) {
    const encoded = await token({ metadata });
    await assert.rejects(() => verifyStatement(encoded, expected), { code: 'EK_EID_FEDERATION' });
  }
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
});

test('JOSE verifies mandatory RSA-SHA512 and supported P-256 statements with their actual key types', async () => {
  for (const algorithm of ['RS512', 'ES256']) {
    const signing = await generateKeyPair(algorithm);
    const keys = anchorKeys(
      [{ ...roots[0]!, publicKeyPem: await exportSPKI(signing.publicKey) }],
      issuer,
    );
    const encoded = await new SignJWT({
      iss: issuer,
      sub: subject,
      iat: timestamp(),
      exp: timestamp() + 60,
      jwks,
    })
      .setProtectedHeader({ alg: algorithm, typ: 'entity-statement+jwt', kid: 'root-public' })
      .sign(signing.privateKey);
    assert.equal((await verifyStatement(encoded, { ...expected, keys })).subject, subject);
  }
});

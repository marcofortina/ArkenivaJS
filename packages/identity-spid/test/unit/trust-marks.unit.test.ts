// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportSPKI, SignJWT } from 'jose';
import { anchorKeys } from '../../dist/statements.js';
import { TrustMarkVerifier } from '../../dist/trust-marks.js';

const issuer = 'https://anchor.example.test',
  subject = 'https://provider.example.test',
  type = issuer + '/openid_provider';
const pair = await generateKeyPair('RS256', { modulusLength: 2048 }),
  other = await generateKeyPair('RS256', { modulusLength: 2048 });
const roots = [
  {
    issuer,
    kid: 'public-root',
    publicKeyPem: await exportSPKI(pair.publicKey),
    validFrom: new Date(Date.now() - 60000).toISOString(),
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
  },
];
const expected = { issuer, subject, type, keys: anchorKeys(roots, issuer), maxBytes: 65536 };
const timestamp = () => Math.floor(Date.now() / 1000);
const sign = (claims: Record<string, unknown>, typ: string, key = pair.privateKey) =>
  new SignJWT({ iss: issuer, iat: timestamp(), ...claims })
    .setProtectedHeader({ alg: 'RS256', typ, kid: 'public-root' })
    .sign(key);
const markToken = (claims: Record<string, unknown> = {}) =>
  sign(
    { sub: subject, exp: timestamp() + 300, trust_mark_type: type, ...claims },
    'trust-mark+jwt',
  );
const statusToken = (
  token: string,
  claims: Record<string, unknown> = {},
  typ = 'trust-mark-status-response+jwt',
) => sign({ trust_mark: token, status: 'active', ...claims }, typ);

test('Actual signed public marks and fresh issuer status bind the exact mark without exposing raw metadata', async () => {
  const verifier = new TrustMarkVerifier();
  const token = await markToken({ organization_name: 'never-disclose-organization' });
  const mark = await verifier.verify(token, expected);
  assert.ok(Object.isFrozen(mark));
  assert.equal(mark.type, type);
  assert.equal(verifier.request(mark), token);
  await verifier.verifyStatus(await statusToken(token), mark, 30);
  assert.doesNotMatch(JSON.stringify(mark), /never-disclose-organization|eyJ|trust_mark/);
});
test('Italian id and final trust_mark_type are unambiguous signed type bindings', async () => {
  const verifier = new TrustMarkVerifier();
  const legacy = await markToken({ trust_mark_type: undefined, id: type });
  assert.equal((await verifier.verify(legacy, expected)).type, type);
  for (const claims of [
    { id: type },
    { trust_mark_type: undefined },
    { trust_mark_type: 'https://other.example.test/type' },
    { trust_mark_type: undefined, id: 'https://other.example.test/type' },
  ]) {
    const token = await markToken(claims);
    await assert.rejects(() => verifier.verify(token, expected), { code: 'EK_EID_FEDERATION' });
  }
});
test('Wrong mark signatures, issuer, subject and missing/expired validity cannot yield owned evidence', async () => {
  const verifier = new TrustMarkVerifier();
  const invalid = await sign(
    { sub: subject, exp: timestamp() + 300, trust_mark_type: type },
    'trust-mark+jwt',
    other.privateKey,
  );
  await assert.rejects(() => verifier.verify(invalid, expected), { code: 'EK_EID_FEDERATION' });
  for (const claims of [
    { iss: 'https://other.example.test' },
    { sub: 'https://other.example.test' },
    { exp: undefined },
    { exp: timestamp() - 1 },
  ]) {
    const token = await markToken(claims);
    await assert.rejects(() => verifier.verify(token, expected), { code: 'EK_EID_FEDERATION' });
  }
});
test('Copied and cross-verifier mark objects cannot request or validate status evidence', async () => {
  const verifier = new TrustMarkVerifier(),
    otherVerifier = new TrustMarkVerifier();
  const token = await markToken(),
    mark = await verifier.verify(token, expected),
    status = await statusToken(token);
  assert.throws(() => verifier.request({ ...mark }), { code: 'EK_EID_FEDERATION' });
  assert.throws(() => otherVerifier.request(mark), { code: 'EK_EID_FEDERATION' });
  await assert.rejects(() => verifier.verifyStatus(status, { ...mark }, 30), {
    code: 'EK_EID_FEDERATION',
  });
  await assert.rejects(() => otherVerifier.verifyStatus(status, mark, 30), {
    code: 'EK_EID_FEDERATION',
  });
});
test('Revoked, expired, invalid and unknown status values fail closed', async () => {
  const verifier = new TrustMarkVerifier(),
    token = await markToken(),
    mark = await verifier.verify(token, expected);
  for (const value of ['revoked', 'expired', 'invalid', 'unknown', true, undefined]) {
    const status = await statusToken(token, { status: value });
    await assert.rejects(() => verifier.verifyStatus(status, mark, 30), {
      code: 'EK_EID_FEDERATION',
    });
  }
});
test('Status must be a recent correctly typed issuer signature for the exact mark', async () => {
  const verifier = new TrustMarkVerifier(),
    token = await markToken(),
    mark = await verifier.verify(token, expected);
  const another = await markToken({ instance: 'different-mark' });
  for (const claims of [
    { trust_mark: another },
    { iss: 'https://other.example.test' },
    { iat: timestamp() - 60 },
    { iat: timestamp() + 60 },
    { iat: undefined },
    { exp: timestamp() - 1 },
  ]) {
    const status = await statusToken(token, claims);
    await assert.rejects(() => verifier.verifyStatus(status, mark, 30), {
      code: 'EK_EID_FEDERATION',
    });
  }
  const wrongType = await statusToken(token, {}, 'trust-mark+jwt');
  await assert.rejects(() => verifier.verifyStatus(wrongType, mark, 30), {
    code: 'EK_EID_FEDERATION',
  });
  const wrongSignature = await sign(
    { trust_mark: token, status: 'active' },
    'trust-mark-status-response+jwt',
    other.privateKey,
  );
  await assert.rejects(() => verifier.verifyStatus(wrongSignature, mark, 30), {
    code: 'EK_EID_FEDERATION',
  });
});

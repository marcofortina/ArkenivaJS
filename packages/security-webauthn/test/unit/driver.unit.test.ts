// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import { createWebAuthnDriver, type WebAuthnDriverSettings } from '../../dist/webauthn-driver.js';
import { authenticator } from '../support/authenticator.js';

const settings = () => ({
  rpId: 'example.test',
  rpName: 'Synthetic service',
  expectedOrigins: ['https://login.example.test'],
});
const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
const invalid = hasCode('EK_MFA_INVALID');
const proof = () => randomBytes(32).toString('base64url');

test('Option generation uses fresh 256-bit challenges and mandatory verification without browser dependencies', async () => {
  const driver = createWebAuthnDriver(settings());
  const handle = randomBytes(32),
    device = authenticator();
  const registration = await driver.registrationOptions(handle, [device.id]);
  const first = await driver.authenticationOptions([device.id]);
  const second = await driver.authenticationOptions();
  assert.equal(Buffer.from(registration.challenge, 'base64url').length, 32);
  assert.equal(Buffer.from(first.challenge, 'base64url').length, 32);
  assert.equal(new Set([registration.challenge, first.challenge, second.challenge]).size, 3);
  assert.equal(registration.user.id, handle.toString('base64url'));
  assert.equal(registration.rp.id, 'example.test');
  assert.equal(registration.attestation, 'none');
  assert.equal(registration.authenticatorSelection?.userVerification, 'required');
  assert.deepEqual(
    registration.pubKeyCredParams.map((p) => p.alg),
    [-8, -7, -257],
  );
  assert.deepEqual(
    registration.excludeCredentials?.map((c) => c.id),
    [device.id],
  );
  assert.deepEqual(
    first.allowCredentials?.map((c) => c.id),
    [device.id],
  );
  assert.equal(first.userVerification, 'required');
  assert.equal(second.allowCredentials?.length ?? 0, 0);
  assert.equal(first.timeout, 300000);
});

test('Policy is captured before requests; production rejects insecure and ambiguous RP/origin configurations', async () => {
  const policy = settings(),
    driver = createWebAuthnDriver(policy);
  policy.expectedOrigins[0] = 'https://hostile.example.test';
  policy.rpId = 'hostile.example.test';
  assert.equal((await driver.authenticationOptions()).rpId, 'example.test');
  const device = authenticator(),
    challenge = proof();
  await driver.verifyRegistration(JSON.stringify(device.registration(challenge)), challenge);
  const bad: unknown[] = [
    null,
    {},
    { ...settings(), environment: null },
    { ...settings(), environment: 'automatic' },
    { ...settings(), rpId: '' },
    { ...settings(), rpId: 'EXAMPLE.TEST' },
    { ...settings(), rpId: '127.0.0.1' },
    { ...settings(), rpId: 'example..test' },
    { ...settings(), rpId: '-example.test' },
    { ...settings(), rpId: 'example.test.' },
    { ...settings(), rpId: 'a'.repeat(64) + '.test' },
    { ...settings(), rpName: '' },
    { ...settings(), rpName: 'unsafe\nname' },
    { ...settings(), expectedOrigins: [] },
    { ...settings(), expectedOrigins: ['invalid'] },
    { ...settings(), expectedOrigins: ['http://login.example.test'] },
    { ...settings(), expectedOrigins: ['https://other.test'] },
    { ...settings(), expectedOrigins: ['https://login.example.test/'] },
    { ...settings(), expectedOrigins: ['https://user:password@login.example.test'] },
    {
      ...settings(),
      expectedOrigins: ['https://login.example.test', 'https://login.example.test'],
    },
    { rpId: 'localhost', rpName: 'Local', expectedOrigins: ['http://localhost:3000'] },
  ];
  for (const value of bad)
    assert.throws(
      () => createWebAuthnDriver(value as WebAuthnDriverSettings),
      hasCode('EK_MFA_POLICY'),
    );
  for (const environment of ['development', 'test'] as const)
    assert.equal(
      (
        await createWebAuthnDriver({
          rpId: 'localhost',
          rpName: 'Local',
          expectedOrigins: ['http://localhost:3000'],
          environment,
        }).authenticationOptions()
      ).rpId,
      'localhost',
    );
});

test('Synthetic none-attestation registration returns only verified credential material', async () => {
  const driver = createWebAuthnDriver(settings()),
    device = authenticator(),
    challenge = proof();
  const result = await driver.verifyRegistration(
    JSON.stringify(device.registration(challenge)),
    challenge,
  );
  assert.equal(result.credential.id, device.id);
  assert.deepEqual(result.credential.publicKey, device.publicKey);
  assert.equal(result.credential.counter, 1);
  assert.equal(result.backupEligible, false);
  assert.equal(result.backedUp, false);
  assert.deepEqual(Object.keys(result).sort(), ['backedUp', 'backupEligible', 'credential']);
  // The primitive has no durable acceptance state and must not be used as replay protection.
  await driver.verifyRegistration(JSON.stringify(device.registration(challenge)), challenge);
});

test('Registration rejects wrong RP/origin/challenge/type, absent UP/UV, embedding and outer-ID substitution', async () => {
  const driver = createWebAuthnDriver(settings()),
    device = authenticator(),
    challenge = proof();
  for (const overrides of [
    { rpId: 'other.test' },
    { origin: 'https://other.test' },
    { type: 'webauthn.get' },
    { flags: 0x41 },
    { flags: 0x44 },
    { flags: 0x55 },
    { crossOrigin: true },
    { crossOrigin: false, topOrigin: 'https://other.test' },
    { format: 'packed' },
  ])
    await assert.rejects(
      driver.verifyRegistration(
        JSON.stringify(device.registration(challenge, overrides)),
        challenge,
      ),
      invalid,
    );
  await assert.rejects(
    driver.verifyRegistration(JSON.stringify(device.registration(proof())), challenge),
    invalid,
  );
  const swapped = device.registration(challenge);
  swapped.id = proof();
  swapped.rawId = swapped.id;
  await assert.rejects(driver.verifyRegistration(JSON.stringify(swapped), challenge), invalid);
});

test('Actual P-256 signatures verify using the upstream primitive and return no MFA evidence', async () => {
  const driver = createWebAuthnDriver(settings()),
    device = authenticator(),
    challenge = proof();
  const result = await driver.verifyAuthentication(
    JSON.stringify(device.authentication(challenge)),
    challenge,
    { id: device.id, publicKey: device.publicKey, counter: 0 },
  );
  assert.deepEqual(result, { newCounter: 1, backupEligible: false, backedUp: false });
  const backedUp = await driver.verifyAuthentication(
    JSON.stringify(device.authentication(challenge, { flags: 0x1d, counter: 3 })),
    challenge,
    { id: device.id, publicKey: device.publicKey, counter: 2 },
  );
  assert.deepEqual(backedUp, { newCounter: 3, backupEligible: true, backedUp: true });
});

test('Valid signatures cannot bypass assertion RP/origin/challenge/type, UP/UV, backup and ownership checks', async () => {
  const driver = createWebAuthnDriver(settings()),
    device = authenticator(),
    challenge = proof();
  const stored = { id: device.id, publicKey: device.publicKey, counter: 0 };
  for (const overrides of [
    { rpId: 'other.test' },
    { origin: 'https://other.test' },
    { type: 'webauthn.create' },
    { flags: 0x01 },
    { flags: 0x04 },
    { flags: 0x15 },
    { crossOrigin: true },
    { crossOrigin: true, topOrigin: 'https://other.test' },
  ])
    await assert.rejects(
      driver.verifyAuthentication(
        JSON.stringify(device.authentication(challenge, overrides)),
        challenge,
        stored,
      ),
      invalid,
    );
  await assert.rejects(
    driver.verifyAuthentication(JSON.stringify(device.authentication(proof())), challenge, stored),
    invalid,
  );
  for (const bad of [
    { ...stored, id: proof() },
    { ...stored, publicKey: authenticator().publicKey },
    { ...stored, publicKey: new Uint8Array() },
    { ...stored, counter: -1 },
    { ...stored, counter: 1 },
    { ...stored, counter: 0xffffffff + 1 },
  ])
    await assert.rejects(
      driver.verifyAuthentication(JSON.stringify(device.authentication(challenge)), challenge, bad),
      invalid,
    );
  const forged = device.authentication(challenge);
  forged.response.signature = proof();
  await assert.rejects(
    driver.verifyAuthentication(JSON.stringify(forged), challenge, stored),
    invalid,
  );
});

test('Malformed and oversized browser responses fail safely without exposing upstream diagnostics', async () => {
  const driver = createWebAuthnDriver(settings()),
    device = authenticator(),
    challenge = proof();
  const stored = { id: device.id, publicKey: device.publicKey, counter: 0 };
  const valid = device.authentication(challenge);
  const variants: unknown[] = [
    null,
    [],
    {},
    { ...valid, rawId: proof() },
    { ...valid, type: 'password' },
    { ...valid, id: valid.id + '=', rawId: valid.id + '=' },
    { ...valid, clientExtensionResults: [] },
    { ...valid, response: {} },
    { ...valid, response: { ...valid.response, clientDataJSON: 'invalid' } },
    {
      ...valid,
      response: { ...valid.response, clientDataJSON: Buffer.from([0xff]).toString('base64url') },
    },
    { ...valid, response: { ...valid.response, signature: 'a'.repeat(23000) } },
    { ...valid, response: { ...valid.response, userHandle: 'a'.repeat(100) } },
    { ...valid, response: { ...valid.response, authenticatorData: 'a' } },
  ];
  for (const text of [
    '',
    '{',
    'x'.repeat(1048577),
    'é'.repeat(600000),
    ...variants.map((value) => JSON.stringify(value)),
  ]) {
    await assert.rejects(driver.verifyAuthentication(text, challenge, stored), (error) => {
      assert.equal(invalid(error), true);
      assert.equal(JSON.stringify(error).includes(challenge), false);
      assert.equal(JSON.stringify(error).includes(device.id), false);
      assert.equal(JSON.stringify(error).includes('expected'), false);
      return true;
    });
  }
  const registration = device.registration(challenge);
  for (const patch of [
    { attestationObject: 'a' },
    { transports: ['x'.repeat(33)] },
    { transports: 'internal' },
  ])
    await assert.rejects(
      driver.verifyRegistration(
        JSON.stringify({ ...registration, response: { ...registration.response, ...patch } }),
        challenge,
      ),
      invalid,
    );
  for (const expected of ['', proof() + '=', randomBytes(31).toString('base64url')])
    await assert.rejects(
      driver.verifyAuthentication(JSON.stringify(valid), expected, stored),
      invalid,
    );
});

test('Option inputs stay bounded and cannot silently replace empty credential allowlists with discovery', async () => {
  const driver = createWebAuthnDriver(settings());
  for (const handle of [new Uint8Array(), new Uint8Array(65), null])
    await assert.rejects(driver.registrationOptions(handle as Uint8Array), invalid);
  for (const ids of [[], [proof() + '='], Array.from({ length: 101 }, proof), null])
    await assert.rejects(driver.authenticationOptions(ids as string[]), invalid);
  await assert.rejects(
    driver.registrationOptions(randomBytes(32), Array.from({ length: 101 }, proof)),
    invalid,
  );
});

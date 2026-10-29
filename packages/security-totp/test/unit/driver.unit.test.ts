// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generate } from 'otplib';
import { parse } from '@otplib/uri';
import { KitError } from '@arkenivajs/core';
import { inspect } from 'node:util';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { newTotpSecret, totpProvisioningUri, verifyTotpStep } from '../../dist/totp-driver.js';

// Public RFC 6238 SHA1 test material, never an application credential.
const rfcSeed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const hasCode = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;

test('The upstream adapter matches all SHA1 RFC 6238 vectors with six-digit truncation', async () => {
  for (const [seconds, proof] of [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
    [20000000000, '353130'],
  ] as const) {
    assert.equal(await verifyTotpStep(rfcSeed, proof, seconds * 1000, 0), Math.floor(seconds / 30));
  }
  assert.equal(await verifyTotpStep(rfcSeed, '000000', 1234567890000, 0), null);
});

test('Verification returns the exact adjacent step and rejects larger drift at interval boundaries', async () => {
  for (const nowMs of [1234567860000, 1234567860001, 1234567875000, 1234567889999, 1234567890000]) {
    for (const delta of [-2, -1, 0, 1, 2]) {
      const code = await generate({
        secret: rfcSeed,
        epoch: Math.floor(nowMs / 1000) + delta * 30,
      });
      const expected = Math.abs(delta) <= 1 ? Math.floor(nowMs / 30000) + delta : null;
      assert.equal(await verifyTotpStep(rfcSeed, code, nowMs, 1), expected);
      assert.equal(
        await verifyTotpStep(rfcSeed, code, nowMs, 0),
        delta === 0 ? Math.floor(nowMs / 30000) : null,
      );
    }
  }
});

test('Proof syntax is strict; invalid configuration or stored material cannot become success', async () => {
  for (const code of [
    '',
    '12345',
    '1234567',
    ' 123456',
    '123456 ',
    '123456\n',
    '１２３４５６',
    '1e0000',
    123456,
    null,
  ])
    await assert.rejects(
      verifyTotpStep(rfcSeed, code as string, 1234567890000, 0),
      hasCode('EK_MFA_INVALID'),
    );
  for (const clock of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER, '1234567890000'])
    await assert.rejects(
      verifyTotpStep(rfcSeed, '005924', clock as number, 0),
      hasCode('EK_MFA_POLICY'),
    );
  await assert.rejects(
    verifyTotpStep(rfcSeed, '005924', 1234567890000, 2 as 1),
    hasCode('EK_MFA_POLICY'),
  );
  for (const secret of ['', rfcSeed + '\n', rfcSeed.toLowerCase(), 'A'.repeat(33)])
    await assert.rejects(verifyTotpStep(secret, '005924', 1234567890000, 0), (error) => {
      assert.equal(hasCode('EK_MFA_STORAGE')(error), true);
      const serialized = JSON.stringify(error);
      if (secret) assert.equal(serialized.includes(secret), false);
      assert.equal(serialized.includes('005924'), false);
      return true;
    });
});

test('CSPRNG seeds provision with standard defaults and encoded issuer/account labels', () => {
  const first = newTotpSecret(),
    second = newTotpSecret();
  assert.match(first, /^[A-Z2-7]{32}$/);
  assert.notEqual(first, second);
  const issuer = 'Synthetic Company & Lab',
    account = 'synthetic+account@example.test';
  const uri = totpProvisioningUri(issuer, account, first),
    parsed = parse(uri);
  assert.equal(parsed.type, 'totp');
  assert.equal(parsed.label, issuer + ':' + account);
  assert.equal(parsed.params.issuer, issuer);
  assert.equal(parsed.params.secret, first);
  assert.equal(parsed.params.algorithm ?? 'sha1', 'sha1');
  assert.equal(parsed.params.digits ?? 6, 6);
  assert.equal(parsed.params.period ?? 30, 30);
  assert.equal(uri.includes('synthetic%2Baccount%40example.test'), true);
  for (const label of ['', ' trailing ', 'line\nfeed', 'a'.repeat(129)])
    assert.throws(() => totpProvisioningUri(label, account, first), hasCode('EK_MFA_POLICY'));
  assert.throws(
    () => totpProvisioningUri(issuer, account, first + '\n'),
    hasCode('EK_MFA_STORAGE'),
  );
});

test('A native entropy-source failure cannot produce a seed or expose provider diagnostics', (context) => {
  const marker = 'synthetic-entropy-source-failure';
  context.mock.method(globalThis.crypto, 'getRandomValues', () => {
    throw new Error(marker);
  });
  assert.throws(
    () => newTotpSecret(),
    (error) => {
      assert.equal(inspect(error).includes(marker), false);
      return hasCode('EK_MFA_STORAGE')(error);
    },
  );
});

test('Native provisioning encoding failures remain safe and cannot return a partial secret-bearing URI', () => {
  const seed = newTotpSecret();
  for (const [issuer, account] of [
    ['\ud800', 'synthetic-account'],
    ['Synthetic Company', '\udfff'],
  ])
    assert.throws(
      () => totpProvisioningUri(issuer!, account!, seed),
      (error) => {
        assert.equal(inspect(error).includes(seed), false);
        assert.equal(inspect(error).includes('URIError'), false);
        return hasCode('EK_MFA_STORAGE')(error);
      },
    );
});

test('An upstream HMAC execution failure cannot become a valid OTP or expose backend diagnostics', async (context) => {
  // Resolve the exact pinned default backend through otplib, without selecting another algorithm.
  const require = createRequire(import.meta.url),
    backend = createRequire(require.resolve('otplib')),
    { NobleCryptoPlugin } = (await import(
      pathToFileURL(backend.resolve('@otplib/plugin-crypto-noble').replace(/\.cjs$/u, '.js')).href
    )) as {
      NobleCryptoPlugin: { prototype: { hmac(...args: unknown[]): unknown } };
    },
    marker = 'synthetic-hmac-backend-failure';
  let calls = 0;
  context.mock.method(NobleCryptoPlugin.prototype, 'hmac', () => {
    calls++;
    throw new Error(marker);
  });
  await assert.rejects(verifyTotpStep(rfcSeed, '005924', 1234567890000, 0), (error) => {
    assert.equal(inspect(error).includes(marker), false);
    return hasCode('EK_MFA_STORAGE')(error);
  });
  assert.ok(calls > 0, 'The pinned upstream verifier must attempt its own HMAC operation');
});

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { deflateRawSync } from 'node:zlib';
import { native } from '../../dist/backend.js';
import { capture } from '../../dist/settings.js';
import { createSamlService } from '../../dist/index.js';
import type { NativeConfiguration, NativeRequest } from '../../dist/backend-contracts.js';
import { fixture } from '../fixture.js';

test(
  'Native SAML redirect decoding rejects ambiguous fields and noncanonical compressed envelopes',
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    try {
      const settings = capture(f.settings);
      const configuration: NativeConfiguration = {
        entityId: settings.entityId,
        acsUrl: settings.acsUrl,
        audience: settings.audience,
        issuer: settings.trusted.issuer,
        certificates: settings.trusted.certificates,
        loginUrl: settings.trusted.loginUrl,
        clockSkewSeconds: settings.clockSkewSeconds,
        binding: 'redirect',
      };
      const requestId = '_' + randomBytes(20).toString('hex');
      const input: NativeRequest = {
        action: 'verify-logout',
        configuration,
        requestId,
        instant: new Date().toISOString(),
        relayState: requestId,
      };
      const response = await f.logoutResponse(requestId);
      const run = (response: string) =>
        native({ ...input, response }, new AbortController().signal);
      const valid = await run('?' + response);
      assert.equal(valid.kind, 'logout');
      for (const response of ['', 'unknown=value', 'RelayState=a&RelayState=b'])
        await assert.rejects(run(response), { code: 'EK_SAML_ASSERTION' });
      for (const mutate of [
        (query: URLSearchParams) => query.delete('Signature'),
        (query: URLSearchParams) => query.set('RelayState', '_foreign'),
        (query: URLSearchParams) => query.set('SigAlg', 'urn:unsupported'),
      ]) {
        const query = new URLSearchParams(response);
        mutate(query);
        await assert.rejects(run(query.toString()), { code: 'EK_SAML_SIGNATURE' });
      }
      for (const encoded of [
        'AB==',
        Buffer.alloc(262145).toString('base64'),
        deflateRawSync(Buffer.from([0xff])).toString('base64'),
      ]) {
        const query = new URLSearchParams(response);
        query.set('SAMLResponse', encoded);
        await assert.rejects(run(query.toString()), { code: 'EK_SAML_ASSERTION' });
      }
      const query = new URLSearchParams(response);
      query.set('Signature', randomBytes(256).toString('base64'));
      await assert.rejects(run(query.toString()), { code: 'EK_SAML_SIGNATURE' });
      await assert.rejects(native({ ...input, action: 'logout' }, new AbortController().signal), {
        code: 'EK_SAML_ASSERTION',
      });

      const canceled = new AbortController();
      canceled.abort();
      await assert.rejects(native(input, canceled.signal), { code: 'EK_ABORTED' });
    } finally {
      await f.close();
    }
  },
);

test('Previously valid pinned IdP metadata and certificates cannot authorize work after expiration', async (context) => {
  const f = await fixture();
  let reads = 0;
  try {
    const expiry = Date.now() + 60000;
    const expiring = createSamlService({
      ...f.settings,
      trustedIdpMetadata: f.settings.trustedIdpMetadata.replace(
        'entityID=',
        'validUntil="' + new Date(expiry).toISOString() + '" entityID=',
      ),
      secretProvider: {
        async get() {
          reads++;
          throw new Error('Expired trust cannot request signing keys');
        },
      },
    });
    const clock = context.mock.method(Date, 'now', () => expiry);
    await assert.rejects(expiring.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
    clock.mock.restore();
    const { signingKeyRef, signingCertificateRef, ...unsigned } = f.settings;
    void signingKeyRef;
    void signingCertificateRef;
    const service = createSamlService(unsigned);
    const certificate = new X509Certificate(await readFile(f.directory + '/idp.pem'));
    const expired = context.mock.method(Date, 'now', () => Date.parse(certificate.validTo));
    await assert.rejects(service.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
    expired.mock.restore();
    assert.equal(reads, 0);
  } finally {
    context.mock.restoreAll();
    await f.close();
  }
});

test(
  'Logout rejects malformed and oversized identity attributes without consuming the authentic session',
  { timeout: 15000 },
  async () => {
    const f = await fixture();
    try {
      const login = await f.service.beginLogin({ returnPath: '/' });
      const identity = await f.service.consumeResponse(
        { inResponseTo: login.requestId, relayState: login.requestId },
        f.response(login.requestId),
      );
      for (const attributes of [
        null,
        { [Symbol('unexpected')]: ['value'] },
        Object.fromEntries(Array.from({ length: 129 }, (_, index) => ['a' + index, ['value']])),
        { large: Array.from({ length: 5 }, () => 'x'.repeat(8192)) },
      ])
        await assert.rejects(f.service.beginLogout({ ...identity, attributes } as never), {
          code: 'EK_SAML_ASSERTION',
        });
      const logout = await f.service.beginLogout(identity);
      await f.service.consumeLogoutResponse(await f.logoutResponse(logout.requestId));
    } finally {
      await f.close();
    }
  },
);

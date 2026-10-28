// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createSamlService } from '../../dist/index.js';
import { fixture } from '../fixture.js';

test(
  'Pinned IdP rollover accepts both active keys and rejects a removed key without consuming the transaction',
  { timeout: 20000 },
  async () => {
    const first = await fixture(),
      next = await fixture();
    try {
      const key = (await readFile(join(next.directory, 'idp.pem'), 'utf8')).replace(
        /-----[^-]+-----|\s/g,
        '',
      );
      const metadata = first.settings.trustedIdpMetadata.replace(
        '</md:KeyDescriptor>',
        '</md:KeyDescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
          key +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>',
      );
      const overlapping = createSamlService({ ...first.settings, trustedIdpMetadata: metadata });
      for (const signer of [first, next]) {
        const request = await overlapping.beginLogin({ returnPath: '/app' });
        assert.equal(
          (
            await overlapping.consumeResponse(
              { inResponseTo: request.requestId, relayState: request.requestId },
              signer.response(request.requestId),
            )
          ).subject,
          'synthetic-account',
        );
      }
      const retired = createSamlService({
          ...first.settings,
          trustedIdpMetadata: next.settings.trustedIdpMetadata,
        }),
        request = await retired.beginLogin({ returnPath: '/app' }),
        context = { inResponseTo: request.requestId, relayState: request.requestId };
      await assert.rejects(retired.consumeResponse(context, first.response(request.requestId)), {
        code: 'EK_SAML_SIGNATURE',
      });
      await retired.consumeResponse(context, next.response(request.requestId));
    } finally {
      await Promise.all([first.close(), next.close()]);
    }
  },
);

test(
  'SP key rotation uses fresh provider versions and rejects mismatched certificates',
  { timeout: 15000 },
  async () => {
    const first = await fixture(),
      next = await fixture();
    let current = first.settings.secretProvider;
    try {
      const service = createSamlService({
        ...first.settings,
        secretProvider: { get: (...args) => current.get(...args) },
      });
      const before = await service.createMetadata();
      current = next.settings.secretProvider;
      const after = await service.createMetadata();
      assert.notEqual(before, after);
      const nextCertificate = (await readFile(join(next.directory, 'sp.pem'), 'utf8')).replace(
        /-----[^-]+-----|\s/g,
        '',
      );
      assert.ok(after.replace(/\s/g, '').includes(nextCertificate));
      const mismatched = createSamlService({
        ...first.settings,
        secretProvider: {
          get(reference, options) {
            return (
              reference === first.settings.signingKeyRef ? first : next
            ).settings.secretProvider.get(reference, options);
          },
        },
      });
      await assert.rejects(mismatched.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
    } finally {
      await Promise.all([first.close(), next.close()]);
    }
  },
);

test(
  'Poisoned offline metadata and missing signing credentials fail closed',
  { timeout: 15000 },
  async () => {
    const f = await fixture();
    try {
      for (const metadata of [
        f.settings.trustedIdpMetadata.replace(
          'entityID=',
          'validUntil="2000-01-01T00:00:00.000Z" entityID=',
        ),
        f.settings.trustedIdpMetadata.replace(
          'Location="https://idp.fixture.invalid/login"',
          'Location="http://foreign.invalid/login"',
        ),
        f.settings.trustedIdpMetadata.replace(
          'protocolSupportEnumeration=',
          'WantAuthnRequestsSigned="unknown" protocolSupportEnumeration=',
        ),
        f.settings.trustedIdpMetadata.replace('use="signing"', 'use="encryption"'),
        f.settings.trustedIdpMetadata.replace('IDPSSODescriptor', 'SPSSODescriptor'),
      ])
        assert.throws(() => createSamlService({ ...f.settings, trustedIdpMetadata: metadata }), {
          code: 'EK_SAML_CONFIGURATION',
        });
      const metadata = f.settings.trustedIdpMetadata.replace(
        'protocolSupportEnumeration=',
        'WantAuthnRequestsSigned="true" protocolSupportEnumeration=',
      );
      const unsigned = { ...f.settings, trustedIdpMetadata: metadata };
      Reflect.deleteProperty(unsigned, 'signingKeyRef');
      Reflect.deleteProperty(unsigned, 'signingCertificateRef');
      assert.throws(() => createSamlService(unsigned), { code: 'EK_SAML_CONFIGURATION' });
      const service = createSamlService({
        ...f.settings,
        secretProvider: {
          async get(reference, options) {
            const value = await f.settings.secretProvider.get(reference, options);
            return { ...value, expiresAt: '2000-01-01T00:00:00.000Z' };
          },
        },
      });
      await assert.rejects(service.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
    } finally {
      await f.close();
    }
  },
);

for (const binding of ['redirect', 'post'] as const)
  test(
    `Negative ${binding} logout signatures cannot poison a valid pending logout`,
    { timeout: 15000 },
    async () => {
      const f = await fixture(binding),
        foreign = await fixture(binding);
      try {
        const request = await f.service.beginLogin({ returnPath: '/app' }),
          identity = await f.service.consumeResponse(
            { inResponseTo: request.requestId, relayState: request.requestId },
            f.response(request.requestId),
          );
        const logout = await f.service.beginLogout(identity);
        await assert.rejects(
          f.service.consumeLogoutResponse(await foreign.logoutResponse(logout.requestId)),
          { code: 'EK_SAML_SIGNATURE' },
        );
        await f.service.consumeLogoutResponse(await f.logoutResponse(logout.requestId));
        const unauthenticated = { ...f.settings };
        Reflect.deleteProperty(unauthenticated, 'authority');
        const missingAuthority = createSamlService(unauthenticated);
        await assert.rejects(missingAuthority.beginLogout(identity), {
          code: 'EK_SAML_CONFIGURATION',
        });
        await assert.rejects(f.service.beginLogout({ ...identity, subject: 'forged-subject' }), {
          code: 'EK_SAML_ASSERTION',
        });
      } finally {
        await Promise.all([f.close(), foreign.close()]);
      }
    },
  );

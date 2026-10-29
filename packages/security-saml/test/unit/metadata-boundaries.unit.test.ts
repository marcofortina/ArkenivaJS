// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createSamlService } from '../../dist/index.js';
import { fixture } from '../fixture.js';

test('Real weak RSA and EC metadata certificates cannot become SAML signing pins', async () => {
  const f = await fixture();
  try {
    for (const [name, pair] of [
      ['weak', generateKeyPairSync('rsa', { modulusLength: 1024 })],
      ['ec', generateKeyPairSync('ec', { namedCurve: 'prime256v1' })],
    ] as const) {
      const key = join(f.directory, name + '-pin.key'),
        cert = join(f.directory, name + '-pin.pem');
      await writeFile(key, pair.privateKey.export({ format: 'pem', type: 'pkcs8' }), {
        mode: 0o600,
      });
      await writeFile(cert, '', { mode: 0o600 });
      await promisify(execFile)(
        'openssl',
        [
          'req',
          '-x509',
          '-key',
          key,
          '-out',
          cert,
          '-days',
          '1',
          '-subj',
          '/CN=Synthetic signing pin',
        ],
        { timeout: 10000 },
      );
      const encoded = new X509Certificate(await readFile(cert)).raw.toString('base64'),
        metadata = f.settings.trustedIdpMetadata.replace(
          /(<ds:X509Certificate>)[^<]+(<\/ds:X509Certificate>)/u,
          '$1' + encoded + '$2',
        );
      assert.throws(() => createSamlService({ ...f.settings, trustedIdpMetadata: metadata }), {
        code: 'EK_SAML_CONFIGURATION',
      });
    }
  } finally {
    await f.close();
  }
});

test('Pinned metadata rejects malformed certificate encodings, invalid ASN.1, ambiguous endpoints and unsupported roles before provider I/O', async () => {
  const f = await fixture();
  let reads = 0;
  try {
    const source = f.settings.trustedIdpMetadata,
      certificate = /<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/u.exec(source)![1]!,
      descriptor = /<md:KeyDescriptor[^>]*>.*?<\/md:KeyDescriptor>/u.exec(source)![0]!,
      login = /<md:SingleSignOnService[^>]*HTTP-Redirect[^>]*\/>/u.exec(source)![0]!;
    for (const metadata of [
      source.replace(certificate, 'AQ=='),
      source.replace(certificate, 'AB=='),
      source.replace(certificate, 'A'.repeat(16388)),
      source.replace(certificate, ''),
      source.replace(descriptor, descriptor.repeat(9)),
      source.replace(/<ds:X509Certificate>[^<]+<\/ds:X509Certificate>/u, ''),
      source.replace('entityID=', 'validUntil="invalid" entityID='),
      source.replace('protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"', ''),
      source.replace(
        'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"',
        'xmlns:md="urn:example:foreign"',
      ),
      source.replace(login, login + login),
      source.replace(login, ''),
    ])
      assert.throws(
        () =>
          createSamlService({
            ...f.settings,
            trustedIdpMetadata: metadata,
            secretProvider: {
              async get() {
                reads++;
                throw new Error('Invalid metadata must not read secrets');
              },
            },
          }),
        { code: 'EK_SAML_CONFIGURATION' },
      );
    assert.equal(reads, 0);
    const noLogout = source.replace(/<md:SingleLogoutService[^>]*\/>/gu, ''),
      service = createSamlService({ ...f.settings, trustedIdpMetadata: noLogout });
    assert.equal((await service.beginLogin({ returnPath: '/' })).binding, 'redirect');
  } finally {
    await f.close();
  }
});

test('Actual pinned X.509 validity boundaries and malformed context URIs fail configuration', async (context) => {
  const f = await fixture();
  try {
    const certificate = new X509Certificate(await readFile(join(f.directory, 'idp.pem')));
    for (const now of [Date.parse(certificate.validFrom) - 1, Date.parse(certificate.validTo)]) {
      const clock = context.mock.method(Date, 'now', () => now);
      assert.throws(() => createSamlService(f.settings), { code: 'EK_SAML_CONFIGURATION' });
      clock.mock.restore();
    }
    for (const value of [
      '::::',
      'https://user:password@example.test/context',
      'https://:password@example.test/context',
    ])
      assert.throws(
        () =>
          createSamlService({
            ...f.settings,
            requestedAuthnContext: {
              classReferences: [value],
              acceptedClassReferences: [value],
              comparison: 'exact',
            },
          }),
        { code: 'EK_SAML_CONFIGURATION' },
      );
  } finally {
    context.mock.restoreAll();
    await f.close();
  }
});

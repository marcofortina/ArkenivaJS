// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import { x509Plugin, X509_CAPABILITY } from '@arkenivajs/security-x509';
import type { X509Service } from '@arkenivajs/security-x509';
import { createCertificateFixture } from './trust-fixture.js';

/** Execute every public certificate utility and actual CRL denial without printing identities. */
export async function runCertificateExample(authorization: { readonly testOnly: true }) {
  const fixture = await createCertificateFixture(authorization);
  let app: Awaited<ReturnType<typeof createApplication>> | undefined;
  try {
    app = await createApplication({
      service: { name: 'certificates-example', version: '1.0.0', environment: 'test' },
      plugins: [
        x509Plugin({
          trustRoots: { demonstration: [fixture.rootDer] },
          trustProvider: fixture.provider,
          policy: {
            maxConcurrent: 2,
            timeoutMs: 3000,
            maxInputBytes: 16384,
            maxOutputBytes: 16384,
          },
        }),
      ],
    });
    await app.start();
    const certificates = app.resolve<X509Service>(X509_CAPABILITY),
      parsed = certificates.parse(fixture.leafPem);
    assert.deepEqual(parsed, certificates.parse(fixture.leafDer));
    assert.ok(certificates.daysUntilExpiry(parsed) >= 0);
    const fingerprints = certificates.getFingerprints(parsed);
    assert.equal(fingerprints.sha256.length, 64);
    assert.equal(fingerprints.sha512?.length, 128);
    const policy = {
      trustRoots: [fixture.rootDer],
      expectedHostname: 'localhost',
      requireRevocationCheck: true,
    };
    assert.equal((await certificates.inspectChain([fixture.leafDer], policy)).status, 'trusted');
    assert.equal(
      (
        await certificates.inspectChain([fixture.leafDer], {
          ...policy,
          expectedHostname: 'foreign.invalid',
        })
      ).status,
      'untrusted',
    );
    await fixture.revoke();
    assert.equal(
      (await certificates.inspectChain([fixture.leafDer], policy)).status,
      'indeterminate',
    );
    await app.stop();
    assert.throws(
      () => certificates.parse(fixture.leafPem),
      (error) => error instanceof KitError && error.code === 'EK_RESOURCE_CLOSED',
    );
    return {
      parsed: true,
      fingerprints: true,
      trustedBeforeRevocation: true,
      wrongHostnameDenied: true,
      revokedCertificateDenied: true,
      closed: true,
      trustChecks: fixture.checks(),
    };
  } finally {
    try {
      await app?.stop();
    } finally {
      await fixture.close();
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.env.ARKENIVA_X509_DISPOSABLE !== '1')
      throw new KitError({
        code: 'EK_CONFIG_INVALID',
        message: 'Explicit disposable certificate example authorization is required',
      });
    console.log(JSON.stringify(await runCertificateExample({ testOnly: true })));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The certificate example could not finish' },
      ),
    );
    process.exitCode = 1;
  }
}

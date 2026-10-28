// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mtlsPlugin } from '@arkenivajs/security-mtls';
import { fixture as pkiFixture } from '../../../security-mtls/dist-test/fixture.js';
import { fixture, send } from '../fixture.js';

test('Approved outbound mTLS uses native client credentials and rejects actual CRL revocation before HTTP forwarding', async () => {
  const pki = await pkiFixture();
  const profiles = Object.fromEntries(
    Object.entries(pki.profiles).map(([name, profile]) => [
      name,
      { ...profile, alpnProtocols: ['http/1.1'] },
    ]),
  );
  for (const [name, material] of pki.materials)
    pki.materials.set(name, { ...material, ALPNProtocols: ['http/1.1'] });
  const material = pki.materials.get('server')!;
  const f = await fixture({ upstreamTlsProfile: profiles.client! }, undefined, {
    upstreamTls: {
      key: Buffer.from(material.key),
      cert: Buffer.from(material.cert),
      ca: pki.root,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
    },
    plugins: [mtlsPlugin({ ...pki.settings, profiles })],
  });
  try {
    const authorization = await f.token();
    const accepted = await send(f.origin, '/orders', 'GET', { authorization });
    assert.equal(accepted.status, 200, accepted.body);
    assert.equal(f.received.length, 1);
    assert.ok(pki.verifications() > 0);
    await pki.revoke('server');
    f.upstream.closeAllConnections();
    const revoked = await send(f.origin, '/orders', 'GET', { authorization });
    assert.equal(revoked.status, 502, revoked.body);
    assert.equal(f.received.length, 1);
    assert.equal(JSON.parse(revoked.body).error.code, 'EK_PROXY_UPSTREAM');
  } finally {
    await f.close();
    await pki.close();
  }
});

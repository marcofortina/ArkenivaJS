// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { samlLoginFixture } from '../fixtures/saml-login.js';
import { closeRegistryFixture } from '../fixtures/saml-metadata.js';
import { FederationSamlLogin } from '../../dist/saml-login.js';
import { FederationSamlRegistry } from '../../dist/saml-registry.js';

after(closeRegistryFixture);

test('Public SAML metadata retains original verified signature bytes and rejects foreign or expired document receipts', async (context) => {
  const f = await samlLoginFixture();
  try {
    const documents = { sp: f.document.xml('sp'), idp: f.document.xml('idp') },
      transport = {
        ...f.transport,
        async samlMetadata(endpoint: string) {
          return documents[endpoint.endsWith('/sp') ? 'sp' : 'idp'];
        },
      },
      login = new FederationSamlLogin(
        f.settings,
        f.document.profile.profileId,
        transport,
        f.crypto,
      ),
      registry = new FederationSamlRegistry(f.document.profile, transport),
      receipt = await f.runtime.run((call) =>
        registry.verify(call, f.document.profile.entityId, 'sp'),
      );
    assert.equal(registry.document(receipt), documents.sp);
    assert.equal(registry.document(receipt).includes('<ds:Signature'), true);
    assert.equal(receipt.verifiedXml.includes('<ds:Signature'), false);
    assert.throws(() => registry.document({ ...receipt }), { code: 'EK_EID_FEDERATION' });
    assert.throws(
      () => new FederationSamlRegistry(f.document.profile, transport).document(receipt),
      { code: 'EK_EID_FEDERATION' },
    );
    assert.equal(await f.runtime.run((call) => login.metadata(call)), documents.sp);
    for (const document of [documents.sp, documents.idp])
      await f.runtime.run((call) => login.verifyTrust(call, document));
    for (const document of [
      documents.idp.replace('WantAuthnRequestsSigned="true"', 'WantAuthnRequestsSigned="false"'),
      '<invalid/>',
      'x'.repeat(65537),
    ])
      await assert.rejects(() => f.runtime.run((call) => login.verifyTrust(call, document)), {
        code: 'EK_EID_FEDERATION',
      });
    // A different, genuinely root-signed snapshot does not match the current authoritative record.
    const old = f.document.xml('idp', { expiry: new Date(Date.now() + 50000).toISOString() });
    await assert.rejects(() => f.runtime.run((call) => login.verifyTrust(call, old)), {
      code: 'EK_EID_FEDERATION',
    });
    f.state.revokedIdp = true;
    await assert.rejects(() => f.runtime.run((call) => login.verifyTrust(call, documents.idp)), {
      code: 'EK_EID_FEDERATION',
    });
    f.state.revokedIdp = false;
    const limited = new FederationSamlLogin(
      { ...f.settings, policy: { ...f.settings.policy, maxOutputBytes: 1 } },
      f.document.profile.profileId,
      transport,
      f.crypto,
    );
    await assert.rejects(() => f.runtime.run((call) => limited.metadata(call)), {
      code: 'EK_EID_FEDERATION',
    });
    context.mock.method(Date, 'now', () => Date.parse(receipt.expiresAt));
    assert.throws(() => registry.document(receipt), { code: 'EK_EID_FEDERATION' });
  } finally {
    context.mock.restoreAll();
    await f.close();
  }
});

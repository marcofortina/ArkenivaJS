// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { samlLoginFixture } from '../fixtures/saml-login.js';
import { samlResponse } from '../fixtures/saml-response.js';
import { closeRegistryFixture } from '../fixtures/saml-metadata.js';
import { FederationSamlLogin } from '../../dist/saml-login.js';

after(closeRegistryFixture);

test(
  'Actual signed SPID assertions enforce issuer formats, both condition boundaries and absence of Advice',
  { timeout: 20000 },
  async (context) => {
    const f = await samlLoginFixture();
    try {
      for (const [name, change] of [
        ['missing assertion issuer format', { assertionIssuerFormat: null }],
        ['foreign assertion issuer format', { assertionIssuerFormat: 'urn:example:foreign' }],
        ['empty assertion issuer format', { assertionIssuerFormat: '' }],
        ['foreign response issuer format', { responseIssuerFormat: 'urn:example:foreign' }],
        ['missing Conditions NotBefore', { conditionsNotBefore: false }],
        ['unsupported Advice', { advice: true }],
        ['level2 SessionIndex', { sessionIndex: 'unexpected-session' }],
      ] as const)
        await context.test(name, async () => {
          const login = await f.runtime.run((call) => f.login.begin(call, f.input));
          await assert.rejects(
            () => f.runtime.run((call) => f.login.consume(call, samlResponse(f, login, change))),
            { code: 'EK_EID_FEDERATION' },
          );
          await assert.rejects(
            () => f.runtime.run((call) => f.login.consume(call, samlResponse(f, login))),
            { code: 'EK_EID_FEDERATION' },
          );
        });
      const login = await f.runtime.run((call) => f.login.begin(call, f.input)),
        result = await f.runtime.run((call) =>
          f.login.consume(call, samlResponse(f, login, { responseIssuerFormat: null })),
        );
      assert.equal(result.assurance, 'spid-l2');
    } finally {
      await f.close();
    }
  },
);

test('SessionIndex follows the actual native verified SPID level, including an approved higher level', async () => {
  const f = await samlLoginFixture();
  try {
    const profile = {
        ...f.document.profile,
        allowedAssurance: ['spid-l1', 'spid-l2', 'spid-l3'] as const,
      },
      login = new FederationSamlLogin(
        { ...f.settings, profiles: [profile] },
        profile.profileId,
        f.transport,
        f.crypto,
      );
    for (const n of [1, 2, 3]) {
      const request = await f.runtime.run((call) =>
          login.begin(call, { ...f.input, assurance: 'spid-l1' }),
        ),
        context = 'https://www.spid.gov.it/SpidL' + n,
        result = await f.runtime.run((call) =>
          login.consume(call, samlResponse(f, request, { context })),
        );
      assert.equal(result.assurance, 'spid-l' + n);
    }
    for (const [context, sessionIndex] of [
      ['https://www.spid.gov.it/SpidL1', null],
      ['https://www.spid.gov.it/SpidL2', 'unexpected-session'],
      ['https://www.spid.gov.it/SpidL3', 'unexpected-session'],
    ] as const) {
      const request = await f.runtime.run((call) =>
        login.begin(call, { ...f.input, assurance: 'spid-l1' }),
      );
      await assert.rejects(
        () =>
          f.runtime.run((call) =>
            login.consume(call, samlResponse(f, request, { context, sessionIndex })),
          ),
        { code: 'EK_EID_FEDERATION' },
      );
    }
  } finally {
    await f.close();
  }
});

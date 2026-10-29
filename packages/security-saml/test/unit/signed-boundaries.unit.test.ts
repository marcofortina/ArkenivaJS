// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from '../fixture.js';

test(
  'Actual signed response envelopes enforce freshness, status and identifier syntax without poisoning correlation',
  { timeout: 30000 },
  async (context) => {
    const f = await fixture();
    try {
      for (const [name, transformResponse] of [
        [
          'future response',
          (xml: string) =>
            xml.replace(
              /IssueInstant="[^"]+"/u,
              'IssueInstant="' + new Date(Date.now() + 600000).toISOString() + '"',
            ),
        ],
        [
          'old response',
          (xml: string) =>
            xml.replace(/IssueInstant="[^"]+"/u, 'IssueInstant="2000-01-01T00:00:00Z"'),
        ],
        ['non-success status', (xml: string) => xml.replace('status:Success', 'status:Responder')],
        [
          'invalid response identifier',
          (xml: string) => xml.replace(/ ID="[^"]+"/u, ' ID="1invalid"'),
        ],
        [
          'unsupported response version',
          (xml: string) => xml.replace('Version="2.0"', 'Version="1.1"'),
        ],
      ] as const)
        await context.test(name, async () => {
          const login = await f.service.beginLogin({ returnPath: '/' }),
            expected = { inResponseTo: login.requestId, relayState: login.requestId };
          await assert.rejects(
            f.service.consumeResponse(expected, f.response(login.requestId, { transformResponse })),
            { code: 'EK_SAML_ASSERTION' },
          );
          assert.equal(
            (await f.service.consumeResponse(expected, f.response(login.requestId))).subject,
            'synthetic-account',
          );
        });
    } finally {
      await f.close();
    }
  },
);

test(
  'Actual signed assertions enforce independent audience, attribute-count, value-count and aggregate-byte quotas',
  { timeout: 40000 },
  async (context) => {
    const f = await fixture(),
      attribute = (name: string, values: readonly string[]) =>
        '<saml:Attribute Name="' +
        name +
        '">' +
        values.map((value) => '<saml:AttributeValue>' + value + '</saml:AttributeValue>').join('') +
        '</saml:Attribute>';
    try {
      for (const [name, transformAssertion, code] of [
        [
          'too many audience restrictions',
          (xml: string) =>
            xml.replace(
              /<saml:AudienceRestriction>.*?<\/saml:AudienceRestriction>/u,
              (
                '<saml:AudienceRestriction><saml:Audience>' +
                f.settings.expectedAudience +
                '</saml:Audience></saml:AudienceRestriction>'
              ).repeat(5),
            ),
          'EK_SAML_ASSERTION',
        ],
        [
          'empty audience restriction',
          (xml: string) => xml.replace(/<saml:Audience>.*?<\/saml:Audience>/u, ''),
          'EK_SAML_ASSERTION',
        ],
        [
          'too many attribute names',
          (xml: string) =>
            xml.replace(
              /<saml:AttributeStatement>.*?<\/saml:AttributeStatement>/u,
              '<saml:AttributeStatement>' +
                Array.from({ length: 129 }, (_, index) =>
                  attribute('field' + index, ['value']),
                ).join('') +
                '</saml:AttributeStatement>',
            ),
          'EK_SAML_ASSERTION',
        ],
        [
          'too many values in one attribute',
          (xml: string) =>
            xml.replace(
              /<saml:Attribute Name="displayName">.*?<\/saml:Attribute>/u,
              attribute(
                'displayName',
                Array.from({ length: 33 }, () => 'value'),
              ),
            ),
          'EK_SAML_ASSERTION',
        ],
        [
          'aggregate attribute bytes',
          (xml: string) =>
            xml.replace(
              /<saml:Attribute Name="displayName">.*?<\/saml:Attribute>/u,
              attribute(
                'displayName',
                Array.from({ length: 5 }, () => 'x'.repeat(8192)),
              ),
            ),
          'EK_SAML_ASSERTION',
        ],
        [
          'invalid assertion identifier',
          (xml: string) => xml.replace(/ ID="[^"]+"/u, ' ID="1invalid"'),
          'EK_SAML_SIGNATURE',
        ],
      ] as const)
        await context.test(name, async () => {
          const login = await f.service.beginLogin({ returnPath: '/' }),
            expected = { inResponseTo: login.requestId, relayState: login.requestId };
          await assert.rejects(
            f.service.consumeResponse(
              expected,
              f.response(login.requestId, { transformAssertion }),
            ),
            { code },
          );
          assert.equal(
            (await f.service.consumeResponse(expected, f.response(login.requestId))).subject,
            'synthetic-account',
          );
        });
    } finally {
      await f.close();
    }
  },
);

test(
  'Native generic SAML retains optional NameID qualifiers and safe defaults without inventing MFA assurance',
  { timeout: 15000 },
  async () => {
    const f = await fixture();
    try {
      const login = await f.service.beginLogin({ returnPath: '/' }),
        identity = await f.service.consumeResponse(
          { inResponseTo: login.requestId, relayState: login.requestId },
          f.response(login.requestId, {
            transformAssertion: (xml) =>
              xml
                .replace(/ Format="[^"]+"/u, '')
                .replace(
                  '<saml:NameID>',
                  '<saml:NameID NameQualifier="https://idp.fixture.invalid/entity" SPNameQualifier="https://sp.fixture.invalid/entity">',
                )
                .replace(/ SessionIndex="[^"]+"/u, '')
                .replace(/ SessionNotOnOrAfter="[^"]+"/u, '')
                .replace(/<saml:AuthnContextClassRef>.*?<\/saml:AuthnContextClassRef>/u, ''),
          }),
        ),
        claim = identity.claims.saml as Readonly<Record<string, unknown>>;
      assert.equal(claim.nameIDFormat, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
      assert.equal(claim.nameQualifier, 'https://idp.fixture.invalid/entity');
      assert.equal(claim.spNameQualifier, 'https://sp.fixture.invalid/entity');
      assert.equal(claim.authnContext, undefined);
      assert.equal(identity.sessionIndex, undefined);
      assert.equal(identity.assurance, 'single-factor');
      assert.deepEqual(identity.scopes, []);
      assert.equal(identity.claims.tenant_id, undefined);
      const logout = await f.service.beginLogout(identity);
      await f.service.consumeLogoutResponse(await f.logoutResponse(logout.requestId));
    } finally {
      await f.close();
    }
  },
);

test('Noncanonical base64 cannot consume an actual pending native SAML request', async () => {
  const f = await fixture();
  try {
    const login = await f.service.beginLogin({ returnPath: '/' }),
      expected = { inResponseTo: login.requestId, relayState: login.requestId };
    await assert.rejects(f.service.consumeResponse(expected, 'AB=='), {
      code: 'EK_SAML_ASSERTION',
    });
    assert.equal(
      (await f.service.consumeResponse(expected, f.response(login.requestId))).subject,
      'synthetic-account',
    );
  } finally {
    await f.close();
  }
});

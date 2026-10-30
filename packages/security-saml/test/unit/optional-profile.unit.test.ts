// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSamlService } from '../../dist/index.js';
import { fields, list, method, property, text, failure } from '../../dist/validation.js';
import { fixture } from '../fixture.js';

for (const binding of ['redirect', 'post'] as const)
  test(
    `Generic ${binding} SAML without optional SP signing keys still requires actual signed IdP assertions and one-use correlation`,
    { timeout: 20000 },
    async () => {
      const f = await fixture(binding);
      let reads = 0;
      try {
        const { signingKeyRef, signingCertificateRef, ...settings } = f.settings;
        void signingKeyRef;
        void signingCertificateRef;
        const service = createSamlService({
          ...settings,
          secretProvider: {
            async get() {
              reads++;
              throw new Error('No SP signing key is configured');
            },
          },
        });
        const metadata = await service.createMetadata();
        assert.ok(metadata.includes('EntityDescriptor'));
        assert.equal(metadata.includes('<ds:Signature'), false);
        const login = await service.beginLogin({ returnPath: '/optional' }),
          context = { inResponseTo: login.requestId, relayState: login.requestId };
        if (login.binding === 'redirect')
          assert.equal(new URL(login.redirectUrl).searchParams.has('Signature'), false);
        else
          assert.equal(
            Buffer.from(login.fields.SAMLRequest, 'base64').toString().includes('Signature'),
            false,
          );
        await assert.rejects(
          service.consumeResponse(
            context,
            f.response(login.requestId, { signedAssertion: false, signedResponse: false }),
          ),
        );
        const response = f.response(login.requestId),
          identity = await service.consumeResponse(context, response);
        assert.equal(identity.subject, 'synthetic-account');
        await assert.rejects(service.consumeResponse(context, response), {
          code: 'EK_SAML_REPLAY',
        });
        await assert.rejects(service.beginLogout(identity), { code: 'EK_SAML_CONFIGURATION' });
        assert.equal(reads, 0);
      } finally {
        await f.close();
      }
    },
  );

test(
  'Generic signed SAML preserves optional NameID qualifiers and canonical session defaults without an MFA claim',
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    try {
      for (const variant of ['qualifiers', 'defaults', 'fractional-time'] as const) {
        const login = await f.service.beginLogin({ returnPath: '/' }),
          response = f.response(login.requestId, {
            transformAssertion(xml) {
              if (variant === 'qualifiers')
                return xml.replace(
                  '<saml:NameID ',
                  '<saml:NameID NameQualifier="https://idp.fixture.invalid/entity" SPNameQualifier="https://sp.fixture.invalid/entity" ',
                );
              if (variant === 'defaults')
                return xml
                  .replace(/<saml:NameID Format="[^"]+"/u, '<saml:NameID')
                  .replace(/ SessionIndex="[^"]+"/u, '')
                  .replace(/ SessionNotOnOrAfter="[^"]+"/u, '')
                  .replace(/<saml:AuthnContextClassRef>[^<]+<\/saml:AuthnContextClassRef>/u, '');
              return xml.replace(
                /(IssueInstant=")([^"]+)"/u,
                (_match, prefix: string) =>
                  prefix +
                  new Date(Math.floor(Date.now() / 1000) * 1000)
                    .toISOString()
                    .replace('.000Z', '.0Z') +
                  '"',
              );
            },
          }),
          identity = await f.service.consumeResponse(
            { inResponseTo: login.requestId, relayState: login.requestId },
            response,
          ),
          facts = identity.claims.saml as Readonly<Record<string, unknown>>;
        assert.equal(identity.assurance, 'single-factor');
        assert.equal(identity.subject, 'synthetic-account');
        if (variant === 'qualifiers') {
          assert.equal(facts.nameQualifier, 'https://idp.fixture.invalid/entity');
          assert.equal(facts.spNameQualifier, f.settings.entityId);
        } else if (variant === 'defaults') {
          assert.equal(facts.nameIDFormat, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
          assert.equal(facts.authnContext, undefined);
          assert.equal(identity.sessionIndex, undefined);
        }
        await assert.rejects(
          f.service.consumeResponse(
            { inResponseTo: login.requestId, relayState: login.requestId },
            response,
          ),
          { code: 'EK_SAML_REPLAY' },
        );
        const logout = await f.service.beginLogout(identity);
        await f.service.consumeLogoutResponse(await f.logoutResponse(logout.requestId));
      }
    } finally {
      await f.close();
    }
  },
);

test('SAML descriptor boundaries reject executable lists, oversized objects and unknown provider methods without side effects', () => {
  let effects = 0;
  const indexed = Object.defineProperty([1], '0', {
    get() {
      effects++;
      return 1;
    },
  });
  for (const value of [new Array(1), indexed, Object.assign([1], { extra: true })])
    assert.throws(() => list(value, 4));
  assert.throws(() =>
    fields(Object.fromEntries(Array.from({ length: 65 }, (_, i) => [String(i), 1])), []),
  );
  assert.throws(() => text('é'.repeat(3), 3));
  for (const value of [
    null,
    { run: true },
    Object.defineProperty({}, 'run', {
      get() {
        effects++;
        return () => true;
      },
    }),
  ])
    assert.throws(() => method(value, 'run'));
  let prototype: object = {};
  for (let i = 0; i < 33; i++) prototype = Object.create(prototype) as object;
  assert.throws(() => property(prototype, 'run'));
  assert.equal(failure('EK_CONFIG_INVALID').message, 'The SAML operation failed');
  assert.equal(effects, 0);
});

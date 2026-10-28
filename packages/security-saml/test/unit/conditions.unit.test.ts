// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from '../fixture.js';

test(
  'Even correctly signed assertions cannot bypass time, subject confirmation, structure or attribute policy',
  { timeout: 60000 },
  async (context) => {
    const f = await fixture();
    const future = new Date(Date.now() + 600000).toISOString(),
      past = '2000-01-01T00:00:00.000Z';
    const changes: readonly [string, (xml: string) => string][] = [
      [
        'future assertion',
        (xml) => xml.replace(/IssueInstant="[^"]+"/, 'IssueInstant="' + future + '"'),
      ],
      [
        'future authentication',
        (xml) => xml.replace(/AuthnInstant="[^"]+"/, 'AuthnInstant="' + future + '"'),
      ],
      ['missing authentication time', (xml) => xml.replace(/AuthnInstant="[^"]+"/, '')],
      [
        'expired session',
        (xml) => xml.replace(/SessionNotOnOrAfter="[^"]+"/, 'SessionNotOnOrAfter="' + past + '"'),
      ],
      [
        'future bearer confirmation',
        (xml) =>
          xml.replace(
            '<saml:SubjectConfirmationData ',
            '<saml:SubjectConfirmationData NotBefore="' + future + '" ',
          ),
      ],
      [
        'future conditions',
        (xml) =>
          xml.replace(
            /<saml:Conditions NotBefore="[^"]+"/,
            '<saml:Conditions NotBefore="' + future + '"',
          ),
      ],
      [
        'noncanonical timestamp',
        (xml) => xml.replace(/AuthnInstant="[^"]+"/, 'AuthnInstant="2026-02-30T00:00:00Z"'),
      ],
      ['unsupported assertion version', (xml) => xml.replace('Version="2.0"', 'Version="1.1"')],
      [
        'wrong bearer method',
        (xml) => xml.replace('urn:oasis:names:tc:SAML:2.0:cm:bearer', 'urn:foreign:confirmation'),
      ],
      [
        'missing audience restriction',
        (xml) => xml.replace(/<saml:AudienceRestriction>[\s\S]*?<\/saml:AudienceRestriction>/, ''),
      ],
      [
        'duplicate subject',
        (xml) => xml.replace('</saml:Subject>', '</saml:Subject><saml:Subject/>'),
      ],
      ['duplicate attribute', (xml) => xml.replace('Name="tenant_id"', 'Name="displayName"')],
      ['prototype attribute', (xml) => xml.replace('Name="displayName"', 'Name="__proto__"')],
      [
        'structured attribute value',
        (xml) => xml.replace('Fixture account', '<saml:NameID>foreign</saml:NameID>'),
      ],
      ['oversized attribute value', (xml) => xml.replace('Fixture account', 'x'.repeat(8193))],
      [
        'empty attribute values',
        (xml) => xml.replace(/<saml:AttributeValue>Fixture account<\/saml:AttributeValue>/, ''),
      ],
    ];
    try {
      for (const [name, transformAssertion] of changes)
        await context.test(name, async () => {
          const request = await f.service.beginLogin({ returnPath: '/app' }),
            expected = { inResponseTo: request.requestId, relayState: request.requestId };
          await assert.rejects(
            f.service.consumeResponse(
              expected,
              f.response(request.requestId, { transformAssertion }),
            ),
            { code: 'EK_SAML_ASSERTION' },
          );
          await f.service.consumeResponse(expected, f.response(request.requestId));
        });
    } finally {
      await f.close();
    }
  },
);

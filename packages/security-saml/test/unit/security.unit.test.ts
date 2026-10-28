// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSamlService } from '../../dist/index.js';
import { fixture } from '../fixture.js';

test(
  'Native signatures, semantic constraints and replay state reject independent SAML attack classes',
  { timeout: 20000 },
  async (context) => {
    const f = await fixture();
    try {
      for (const [name, change, code] of [
        ['unsigned assertion', { signedAssertion: false }, 'EK_SAML_SIGNATURE'],
        ['unsigned response', { signedResponse: false }, 'EK_SAML_SIGNATURE'],
        ['wrong audience', { audience: 'https://foreign.fixture.invalid' }, 'EK_SAML_ASSERTION'],
        [
          'wrong recipient and destination',
          { destination: 'https://foreign.fixture.invalid/acs' },
          'EK_SAML_ASSERTION',
        ],
        ['wrong issuer', { issuer: 'https://foreign.fixture.invalid' }, 'EK_SAML_ASSERTION'],
        ['expired assertion', { expiresOffsetMs: -1000 }, 'EK_SAML_ASSERTION'],
      ] as const)
        await context.test(name, async () => {
          const request = await f.service.beginLogin({ returnPath: '/app' });
          await assert.rejects(
            f.service.consumeResponse(
              { inResponseTo: request.requestId, relayState: request.requestId },
              f.response(request.requestId, change),
            ),
            { code },
          );
        });
      await context.test('tampering cannot poison the still-valid durable request', async () => {
        const request = await f.service.beginLogin({ returnPath: '/app' }),
          valid = f.response(request.requestId),
          changed = Buffer.from(
            Buffer.from(valid, 'base64')
              .toString('utf8')
              .replace('synthetic-account', 'altered-account'),
          ).toString('base64');
        const expected = { inResponseTo: request.requestId, relayState: request.requestId };
        await assert.rejects(f.service.consumeResponse(expected, changed), {
          code: 'EK_SAML_SIGNATURE',
        });
        assert.equal(
          (await f.service.consumeResponse(expected, valid)).subject,
          'synthetic-account',
        );
      });
      await context.test(
        'relay-state and signed request correlation are independently bound',
        async () => {
          const request = await f.service.beginLogin({ returnPath: '/app' }),
            another = await f.service.beginLogin({ returnPath: '/another' });
          await assert.rejects(
            f.service.consumeResponse(
              { inResponseTo: request.requestId },
              f.response(request.requestId),
            ),
            { code: 'EK_SAML_ASSERTION' },
          );
          await assert.rejects(
            f.service.consumeResponse(
              { inResponseTo: request.requestId, relayState: request.requestId },
              f.response(another.requestId),
            ),
            { code: 'EK_SAML_ASSERTION' },
          );
        },
      );
      await context.test(
        'duplicate signature IDs and DTD payloads cannot reach a trusted result',
        async () => {
          const request = await f.service.beginLogin({ returnPath: '/app' }),
            xml = Buffer.from(f.response(request.requestId), 'base64').toString('utf8');
          const ids = [...xml.matchAll(/\bID="([^"]+)"/g)].map((match) => match[1]!);
          assert.equal(ids.length, 2);
          const wrapped = xml.replace('ID="' + ids[1] + '"', 'ID="' + ids[0] + '"');
          await assert.rejects(
            f.service.consumeResponse(
              { inResponseTo: request.requestId, relayState: request.requestId },
              Buffer.from(wrapped).toString('base64'),
            ),
            { code: 'EK_SAML_SIGNATURE' },
          );
          await assert.rejects(
            f.service.consumeResponse(
              { inResponseTo: request.requestId, relayState: request.requestId },
              Buffer.from(
                '<!DOCTYPE Response [<!ENTITY leak SYSTEM "file:///nonexistent">]>' + xml,
              ).toString('base64'),
            ),
            { code: 'EK_SAML_ASSERTION' },
          );
        },
      );
      await context.test(
        'a different real IdP signing key is not trusted by matching issuer text',
        async () => {
          const foreign = await fixture();
          try {
            const request = await f.service.beginLogin({ returnPath: '/app' });
            await assert.rejects(
              f.service.consumeResponse(
                { inResponseTo: request.requestId, relayState: request.requestId },
                foreign.response(request.requestId),
              ),
              { code: 'EK_SAML_SIGNATURE' },
            );
          } finally {
            await foreign.close();
          }
        },
      );
      await context.test(
        'deadline and cancellation inputs reject without native execution',
        async () => {
          for (const timeoutMs of [0, -1, 0.5, Infinity, 30001])
            await assert.rejects(f.service.beginLogin({ returnPath: '/app' }, { timeoutMs }), {
              code: 'EK_SAML_CONFIGURATION',
            });
          await assert.rejects(
            f.service.beginLogin(
              { returnPath: '/app' },
              { signal: AbortSignal.abort('private-cancellation') },
            ),
            { code: 'EK_ABORTED' },
          );
          for (const returnPath of [
            'https://foreign.invalid',
            '//foreign.invalid',
            '/%2f/foreign',
            '/\\foreign',
            '/app#fragment',
          ])
            await assert.rejects(f.service.beginLogin({ returnPath }), {
              code: 'EK_SAML_CONFIGURATION',
            });
        },
      );
      await context.test(
        'missing providers, poisoned metadata, unsafe origins and test-only production state fail startup',
        () => {
          for (const change of [
            { secretProvider: undefined },
            { replayStore: undefined },
            { clockSkewSeconds: 121 },
            { environment: 'production' },
            { acsUrl: 'http://foreign.invalid/acs' },
            { trustedIdpMetadata: '<!DOCTYPE metadata>' + f.settings.trustedIdpMetadata },
            { unknown: true },
          ])
            assert.throws(() => createSamlService({ ...f.settings, ...change } as never), {
              code: 'EK_SAML_CONFIGURATION',
            });
        },
      );
      await context.test(
        'provider outages never return authenticated identity or disclose their exception',
        async () => {
          const service = createSamlService({
            ...f.settings,
            replayStore: {
              ...f.settings.replayStore,
              async read() {
                throw new Error('private-storage-credential');
              },
            },
          });
          const request = await f.service.beginLogin({ returnPath: '/app' });
          await assert.rejects(
            service.consumeResponse(
              { inResponseTo: request.requestId, relayState: request.requestId },
              f.response(request.requestId),
            ),
            (error: unknown) =>
              error instanceof Error &&
              !error.message.includes('private') &&
              (error as { code?: string }).code === 'EK_BACKEND_UNAVAILABLE',
          );
        },
      );
    } finally {
      await f.close();
    }
  },
);

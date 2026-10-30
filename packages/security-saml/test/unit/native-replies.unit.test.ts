// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import type { NativeResult } from '../../dist/backend-contracts.js';
import { fixture } from '../fixture.js';

test(
  'Native reply corruption cannot redirect login, replace identities or consume a valid logout',
  { timeout: 30000 },
  async (context) => {
    const f = await fixture();
    const emit = Worker.prototype.emit;
    let change: ((result: NativeResult) => unknown) | undefined;
    let changed = 0;
    const intercepted = context.mock.method(
      Worker.prototype,
      'emit',
      function (this: Worker, event: string | symbol, ...args: unknown[]) {
        const packet = args[0] as { ok?: boolean; result?: NativeResult };
        if (event === 'message' && packet?.ok && packet.result && change) {
          changed++;
          return Reflect.apply(emit, this, [event, { ...packet, result: change(packet.result) }]);
        }
        return Reflect.apply(emit, this, [event, ...args]);
      },
    );
    try {
      change = () => ({ kind: 'metadata', xml: '<invalid/>' });
      await assert.rejects(f.service.beginLogin({ returnPath: '/' }), {
        code: 'EK_SAML_ASSERTION',
      });
      change = (result) => {
        assert.equal(result.kind, 'redirect');
        return { ...result, url: 'https://foreign.invalid/login' };
      };
      await assert.rejects(f.service.beginLogin({ returnPath: '/' }), {
        code: 'EK_SAML_ASSERTION',
      });
      change = () => ({ kind: 'logout', responseId: '_unexpected' });
      await assert.rejects(f.service.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
      change = () => ({ kind: 'metadata', xml: 'x'.repeat(524289) });
      await assert.rejects(f.service.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
      change = undefined;
      const login = await f.service.beginLogin({ returnPath: '/' });
      const expected = { inResponseTo: login.requestId, relayState: login.requestId };
      const response = f.response(login.requestId);
      change = () => ({ kind: 'logout', responseId: '_unexpected' });
      await assert.rejects(f.service.consumeResponse(expected, response), {
        code: 'EK_SAML_ASSERTION',
      });
      change = (result) => {
        assert.equal(result.kind, 'identity');
        return {
          ...result,
          identity: { ...result.identity, issuer: 'https://foreign.invalid/entity' },
        };
      };
      await assert.rejects(f.service.consumeResponse(expected, response), {
        code: 'EK_SAML_ASSERTION',
      });
      change = undefined;
      const identity = await f.service.consumeResponse(expected, response);
      const logout = await f.service.beginLogout(identity);
      const logoutResponse = await f.logoutResponse(logout.requestId);
      change = () => ({ kind: 'metadata', xml: '<invalid/>' });
      await assert.rejects(f.service.consumeLogoutResponse(logoutResponse), {
        code: 'EK_SAML_ASSERTION',
      });
      change = undefined;
      await f.service.consumeLogoutResponse(logoutResponse);
      assert.equal(changed, 7);
    } finally {
      intercepted.mock.restore();
      await f.close();
    }
  },
);

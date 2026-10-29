// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from '../fixture.js';

for (const order of ['response-first', 'relay-first', 'without-relay'] as const)
  test(`Actual signed POST logout accepts an owned ${order} form exactly once`, async () => {
    const f = await fixture('post');
    try {
      const request = await f.service.beginLogin({ returnPath: '/' }),
        identity = await f.service.consumeResponse(
          { inResponseTo: request.requestId, relayState: request.requestId },
          f.response(request.requestId),
        ),
        logout = await f.service.beginLogout(identity),
        response = await f.logoutResponse(logout.requestId),
        fields =
          order === 'relay-first'
            ? [
                ['RelayState', logout.requestId],
                ['SAMLResponse', response],
              ]
            : order === 'response-first'
              ? [
                  ['SAMLResponse', response],
                  ['RelayState', logout.requestId],
                ]
              : [['SAMLResponse', response]],
        form = new URLSearchParams(fields).toString();
      for (const bad of [
        form + '&unknown=value',
        form + '&SAMLResponse=' + encodeURIComponent(response),
        new URLSearchParams({ RelayState: logout.requestId }).toString(),
        new URLSearchParams([
          ['SAMLResponse', response],
          ['RelayState', logout.requestId],
          ['RelayState', logout.requestId],
        ]).toString(),
        new URLSearchParams({
          SAMLResponse: response,
          RelayState: '_' + '0'.repeat(40),
        }).toString(),
      ])
        await assert.rejects(() => f.service.consumeLogoutResponse(bad), {
          code: 'EK_SAML_ASSERTION',
        });
      await f.service.consumeLogoutResponse(form);
      await assert.rejects(() => f.service.consumeLogoutResponse(form), { code: 'EK_SAML_REPLAY' });
    } finally {
      await f.close();
    }
  });

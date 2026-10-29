// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Configuration, customFetch } from 'openid-client';
import { FederationProtocolHttp } from '../../dist/protocol-http.js';
import { capture } from '../../dist/settings.js';
import { transactionFixture } from './transactions.js';
import { registration } from './registration.js';

process.once('message', (input: { origin: string }) => {
  void run(input.origin).then(
    () => {
      process.send?.({ ok: true });
      process.disconnect();
    },
    (error: unknown) => {
      process.send?.({
        ok: false,
        message: error instanceof Error ? error.message : 'Protocol fixture failed',
      });
      process.disconnect();
    },
  );
});
async function run(origin: string) {
  const f = await transactionFixture(),
    endpoints = {
      tokenEndpoint: origin + '/token',
      userInfoEndpoint: origin + '/userinfo',
      jwksEndpoint: origin + '/jwks',
    },
    paths = [
      '/token',
      '/userinfo',
      '/jwks',
      '/redirect',
      '/wrong-type',
      '/oversized',
      '/utf8',
      '/slow',
      '/unavailable',
    ],
    raw = {
      ...f.settings,
      profiles: [
        {
          ...f.profile,
          metadata: { ...f.profile.metadata, maxBytes: 8192 },
          oidcRegistration: {
            ...(await registration(f.profile.entityId)),
            approvedProtocolEndpoints: paths.map((path) => origin + path),
          },
        },
      ],
      policy: { ...f.settings.policy, maxInputBytes: 8192, maxOutputBytes: 8192 },
    },
    settings = capture(raw, 'test'),
    transport = new FederationProtocolHttp(settings, f.profile.profileId),
    get = (authorization = true) => ({
      method: 'GET',
      redirect: 'manual' as const,
      headers: {
        accept: 'application/jwt',
        ...(authorization ? { authorization: 'Bearer fixture-access-token' } : {}),
      },
    });
  try {
    await f.runtime.run(async (call) => {
      const send = transport.fetch(call, endpoints),
        config = new Configuration({ issuer: 'https://idp.example.test' }, f.profile.clientId!);
      config[customFetch] = send;
      const token = await send(endpoints.tokenEndpoint, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
        },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: 'fixture-code' }),
      });
      assert.deepEqual(await token.json(), { ok: true });
      const info = await send(endpoints.userInfoEndpoint, get());
      assert.equal(await info.text(), 'fixture-signed-encrypted-response');
      const jwks = await send(endpoints.jwksEndpoint, {
        method: 'GET',
        redirect: 'manual',
        headers: { accept: 'application/json' },
      });
      assert.deepEqual(await jwks.json(), { keys: [] });
      await assert.rejects(() => send(endpoints.jwksEndpoint, get()), {
        code: 'EK_EID_FEDERATION',
      });
      await assert.rejects(() => send(endpoints.userInfoEndpoint, get(false)), {
        code: 'EK_EID_FEDERATION',
      });
      await assert.rejects(() => send(origin + '/not-approved', get()), {
        code: 'EK_EID_FEDERATION',
      });
      await assert.rejects(
        () =>
          send(endpoints.userInfoEndpoint, {
            ...get(),
            headers: { ...get().headers, cookie: 'fixture-cookie' },
          }),
        { code: 'EK_EID_FEDERATION' },
      );
      await assert.rejects(
        () => send(endpoints.userInfoEndpoint, { ...get(), redirect: 'follow' }),
        { code: 'EK_EID_FEDERATION' },
      );
      await assert.rejects(
        () =>
          send(endpoints.userInfoEndpoint, {
            ...get(),
            headers: { ...get().headers, accept: 'x'.repeat(8193) },
          }),
        { code: 'EK_EID_FEDERATION' },
      );
      await assert.rejects(
        () =>
          send(endpoints.tokenEndpoint, {
            method: 'POST',
            redirect: 'manual',
            headers: {
              accept: 'application/json',
              'content-type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams(
              Array.from({ length: 65 }, (_, index) => ['field' + index, '']),
            ),
          }),
        { code: 'EK_EID_FEDERATION' },
      );
      await assert.rejects(
        () =>
          send(endpoints.tokenEndpoint, { ...get(), method: 'POST', body: new ReadableStream() }),
        { code: 'EK_EID_FEDERATION' },
      );
    });
    for (const path of ['/redirect', '/wrong-type', '/oversized', '/utf8'])
      await assert.rejects(
        () =>
          f.runtime.run((call) =>
            transport.fetch(call, { ...endpoints, userInfoEndpoint: origin + path })(
              origin + path,
              get(),
            ),
          ),
        { code: 'EK_EID_FEDERATION' },
      );
    await f.runtime.run(async (call) => {
      const response = await transport.fetch(call, {
        ...endpoints,
        tokenEndpoint: origin + '/unavailable',
      })(origin + '/unavailable', {
        method: 'POST',
        redirect: 'manual',
        headers: {
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ grant_type: 'authorization_code' }),
      });
      assert.equal(response.status, 503);
    });
    await assert.rejects(
      () =>
        f.runtime.run(
          (call) =>
            transport.fetch(call, { ...endpoints, userInfoEndpoint: origin + '/slow' })(
              origin + '/slow',
              get(),
            ),
          { timeoutMs: 50 },
        ),
      { code: 'EK_TIMEOUT' },
    );
    for (const environment of ['production', 'development'] as const) {
      const native = new FederationProtocolHttp(
        capture(
          {
            ...raw,
            secretProvider: { get: f.settings.secretProvider.get },
            stateStore: { ...f.settings.stateStore, securityLevel: 'production' },
          },
          environment,
        ),
        f.profile.profileId,
      );
      try {
        await assert.rejects(
          () =>
            f.runtime.run((call) =>
              native.fetch(call, endpoints)(endpoints.userInfoEndpoint, get()),
            ),
          { code: 'EK_EID_FEDERATION' },
        );
      } finally {
        await native.close();
      }
    }
    let effects = 0;
    await f.runtime.run(async (call) => {
      const send = transport.fetch(call, endpoints);
      await assert.rejects(
        () =>
          send(endpoints.userInfoEndpoint, {
            ...get(),
            get headers(): HeadersInit {
              effects++;
              throw new Error('Executable headers');
            },
          }),
        { code: 'EK_EID_FEDERATION' },
      );
      await assert.rejects(
        () =>
          send(endpoints.userInfoEndpoint, {
            ...get(),
            headers: new Proxy(get().headers, {
              ownKeys() {
                effects++;
                return [];
              },
            }),
          }),
        { code: 'EK_EID_FEDERATION' },
      );
    });
    assert.equal(effects, 0);
  } finally {
    await transport.close();
    await f.close();
  }
}

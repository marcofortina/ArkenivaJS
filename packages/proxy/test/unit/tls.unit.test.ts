// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fixture, send } from '../fixture.js';
import { tlsFixture } from '../tls-fixture.js';

test('Direct inbound HTTPS and actual verified upstream HTTPS share the native proxy streaming path', async () => {
  const tls = await tlsFixture();
  const f = await fixture({ upstreamCaFile: tls.files.certificateFile }, undefined, {
    upstreamTls: tls,
    inboundTls: tls.files,
  });
  try {
    const result = await send(
      f.origin,
      '/orders/secure',
      'POST',
      { authorization: await f.token(), 'content-type': 'text/plain' },
      [Buffer.from('secure payload')],
      tls.cert,
    );
    assert.equal(result.status, 200, result.body);
    assert.equal(JSON.parse(result.body).bytes, 14);
    assert.equal(JSON.parse(result.body).headers.authorization, undefined);
  } finally {
    await f.close();
    await tls.close();
  }
});

test('Missing upstream CA trust and wrong certificate identity fail closed with sanitized 502 responses', async () => {
  const tls = await tlsFixture(),
    wrong = await tlsFixture('DNS:foreign.fixture.invalid');
  try {
    for (const [certificate, upstreamCaFile] of [
      [tls, undefined],
      [wrong, wrong.files.certificateFile],
    ] as const) {
      const f = await fixture({ ...(upstreamCaFile ? { upstreamCaFile } : {}) }, undefined, {
        upstreamTls: certificate,
      });
      try {
        const result = await send(f.origin, '/orders/private', 'GET', {
          authorization: await f.token(),
        });
        assert.equal(result.status, 502, result.body);
        assert.equal(JSON.parse(result.body).error.code, 'EK_PROXY_UPSTREAM');
        assert.ok(!result.body.includes('127.0.0.1'));
        assert.ok(!result.body.includes('certificate'));
        assert.equal(f.received.length, 0);
        assert.ok(!f.logs().includes('foreign.fixture.invalid'));
      } finally {
        await f.close();
      }
    }
  } finally {
    await tls.close();
    await wrong.close();
  }
});

test('Only an explicitly resolved service credential reaches an independently authenticating HTTPS upstream', async () => {
  const tls = await tlsFixture(),
    secret = randomBytes(32),
    expected = Buffer.from('Bearer ' + secret.toString('base64url'));
  let available = true,
    accepted = 0,
    resolutions = 0;
  const f = await fixture(
    {
      upstreamCaFile: tls.files.certificateFile,
      identityDelegation: 'validated-service-credential',
      serviceCredentialSecretRef: 'fixture/upstream-identity',
    },
    (request, response) => {
      const actual = Buffer.from(request.headers.authorization ?? '');
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
        response.writeHead(401);
        response.end('denied');
        return;
      }
      accepted++;
      response.end('service accepted');
    },
    {
      upstreamTls: tls,
      async resolveSecret(reference) {
        resolutions++;
        if (!available || reference !== 'fixture/upstream-identity')
          throw new Error('Private secret provider failure');
        return expected.toString();
      },
    },
  );
  try {
    const authorization = await f.token();
    const result = await send(f.origin, '/orders', 'GET', {
      authorization,
      'x-tenant-id': 'forged',
    });
    assert.equal(result.status, 200, result.body);
    assert.equal(result.body, 'service accepted');
    assert.equal(accepted, 1);
    available = false;
    const denied = await send(f.origin, '/orders', 'GET', { authorization });
    assert.equal(denied.status, 403, denied.body);
    assert.equal(accepted, 1);
    assert.equal(resolutions, 2);
    assert.ok(!f.logs().includes(expected.toString()));
    assert.ok(!f.logs().includes(authorization));
    assert.ok(!f.logs().includes('Private secret provider failure'));
  } finally {
    await f.close();
    secret.fill(0);
    expected.fill(0);
    await tls.close();
  }
});

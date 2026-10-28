// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base, fixture, send } from '../fixture.js';

test('GraphQL IDE is opt-in, authenticates every asset and never publishes bearer assertions in HTML', async () => {
  const f = await fixture({
    ...base(),
    security: {
      authorizeField: () => true,
      developerIDE: true,
      introspection: 'authenticated',
      introspectionScope: 'graphql:admin',
    },
  });
  try {
    const unauthorized = await send(f.origin, undefined, { method: 'GET', path: '/graphql/ide' });
    assert.equal(unauthorized.status, 401, unauthorized.body);
    const unprivileged = await send(f.origin, undefined, {
      method: 'GET',
      path: '/graphql/ide',
      headers: { authorization: await f.token() },
    });
    assert.equal(unprivileged.status, 401, unprivileged.body);
    const token = await f.token('tenant-a', 'graphql:admin');
    const page = await send(f.origin, undefined, {
      method: 'GET',
      path: '/graphql/ide',
      headers: { authorization: token },
    });
    assert.equal(page.status, 200, page.body);
    assert.match(page.body, /ArkenivaJS GraphQL IDE/);
    assert.doesNotMatch(page.body, /https?:\/\/|Bearer |localStorage|sessionStorage/);
    assert.ok(!page.body.includes(token));
    const missingAssetAuth = await send(f.origin, undefined, {
      method: 'GET',
      path: '/graphql/ide/assets/app.js',
    });
    assert.equal(missingAssetAuth.status, 401);
    for (const name of [
      'app.js',
      'app.css',
      'worker-json.js',
      'worker-graphql.js',
      'worker-editor.js',
      'app.css.LEGAL.txt',
    ]) {
      const asset = await send(f.origin, undefined, {
        method: 'GET',
        path: '/graphql/ide/assets/' + name,
        headers: { authorization: token },
      });
      assert.equal(asset.status, 200, name);
      assert.ok(asset.body.length > 0);
    }
    const unknown = await send(f.origin, undefined, {
      method: 'GET',
      path: '/graphql/ide/assets/package.json',
      headers: { authorization: token },
    });
    assert.equal(unknown.status, 404);
    assert.equal(f.service.stats().operations, 0);
    assert.equal(f.service.stats().activeOperations, 0);
    assert.equal(f.service.stats().rejected, 0);
  } finally {
    await f.close();
  }
});

test('GraphQL IDE disabled startup never registers its page or static assets', async () => {
  const f = await fixture(base());
  try {
    for (const path of ['/graphql/ide', '/graphql/ide/assets/app.js']) {
      const response = await send(f.origin, undefined, {
        method: 'GET',
        path,
        headers: { authorization: await f.token() },
      });
      assert.equal(response.status, 404);
    }
  } finally {
    await f.close();
  }
});

test('GraphQL IDE cannot start in production or without a trusted identity authority', async () => {
  await assert.rejects(
    fixture(
      {
        ...base(),
        security: {
          authorizeField: () => true,
          developerIDE: true,
          auth: { required: false, publicRootFields: ['Query.ping'], reason: 'Public ping' },
        },
      },
      { environment: 'production', authenticated: false },
    ),
    (error: unknown) =>
      error instanceof Error &&
      error.cause instanceof Error &&
      'code' in error.cause &&
      error.cause.code === 'EK_GQL_CONFIG',
  );
  await assert.rejects(
    fixture(
      {
        ...base(),
        security: {
          authorizeField: () => true,
          developerIDE: true,
          auth: { required: false, publicRootFields: ['Query.ping'], reason: 'Public ping' },
        },
      },
      { authenticated: false },
    ),
  );
});

test('GraphQL IDE supports configured endpoint paths and explicit development environments', async () => {
  const f = await fixture(
    { ...base(), path: '/api/query', security: { authorizeField: () => true, developerIDE: true } },
    { environment: 'development' },
  );
  try {
    const response = await send(f.origin, undefined, {
      method: 'GET',
      path: '/api/query/ide',
      headers: { authorization: await f.token() },
    });
    assert.equal(response.status, 200, response.body);
    assert.match(response.body, /content="\/api\/query"/);
    assert.match(response.body, /\/api\/query\/ide\/assets\/app.js/);
  } finally {
    await f.close();
  }
});

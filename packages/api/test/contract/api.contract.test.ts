// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApi } from '@arkenivajs/api';
import type { ApiServer } from '@arkenivajs/core';

test('API public contract retains typed routes and deterministic immutable OpenAPI 3.1', async () => {
  const managed = createApi({
    service: { name: 'api-contract', version: '1.0.0', environment: 'test' },
    port: 0,
  });
  const api: ApiServer = managed;
  api.get<{ name: string }, Record<string, never>, never, { greeting: string }>('/hello/:name', {
    schema: {
      params: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
      response: {
        type: 'object',
        properties: { greeting: { type: 'string' } },
        required: ['greeting'],
      },
    },
    auth: { required: false },
    handler: ({ params }) => ({ greeting: `Hello ${params.name}` }),
  });
  try {
    await managed.start();
    assert.equal(api.openApiDocument().openapi, '3.1.0');
    assert.ok(Object.isFrozen(api.openApiDocument()));
  } finally {
    await managed.close();
  }
});

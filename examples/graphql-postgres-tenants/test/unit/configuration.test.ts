// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCustomerExample } from '../../dist/main.js';

test('Administrator SQL identifiers reject injection, coercion and oversized values before service composition', async () => {
  let executions = 0;
  for (const schema of [
    '',
    'public.customers',
    'public; DROP SCHEMA public',
    'schema"',
    'schema\n',
    'x'.repeat(64),
    null,
    {
      toString() {
        executions++;
        return 'public';
      },
    },
  ])
    await assert.rejects(
      () =>
        createCustomerExample({
          service: { name: 'customer-guide', version: '1.0.0', environment: 'test' },
          http: { host: '127.0.0.1', port: 0 },
          issuer: 'https://issuer.example.test',
          audience: 'api://customers',
          schema: schema as string,
        }),
      { message: 'The configured SQL schema identifier is invalid' },
    );
  assert.equal(executions, 0);
});

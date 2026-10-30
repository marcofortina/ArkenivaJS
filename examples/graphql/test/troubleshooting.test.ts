// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { logGraphqlDiagnostics } from '../dist/main.js';
import { fixture } from './fixture.js';

test('Public GraphQL troubleshooting refuses invalid and over-budget mutations before effects and logs only safe diagnostics', async () => {
  const f = await fixture();
  try {
    const assertion = await f.token(),
      marker = 'private-guide-payload-value';
    const cases = [
      { body: { query: 'mutation { increment ' }, status: 400, code: 'EK_GQL_VALIDATION' },
      {
        body: { query: 'mutation First { increment } mutation Second { increment }' },
        status: 400,
        code: 'EK_GQL_VALIDATION',
      },
      {
        body: {
          query:
            'mutation { ' +
            Array.from({ length: 21 }, (_, index) => `write${index}:increment`).join(' ') +
            ' }',
        },
        status: 400,
        code: 'EK_GQL_COMPLEXITY',
      },
      {
        body: { query: '#' + marker.repeat(3000) + '\nmutation { increment }' },
        status: 413,
        code: 'EK_GQL_INPUT_LIMIT',
      },
      {
        body: {
          query: 'query Customer($id:ID!){ customer(id:$id){ id } }',
          variables: { id: marker.repeat(3000) },
        },
        status: 413,
        code: 'EK_GQL_INPUT_LIMIT',
      },
    ];
    for (const item of cases) {
      const response = await f.send(item.body, assertion);
      assert.equal(response.status, item.status, response.body);
      const result = JSON.parse(response.body) as { errors: { extensions: { code: string } }[] };
      assert.equal(result.errors[0]?.extensions.code, item.code);
      assert.doesNotMatch(response.body, /private-guide-payload-value/);
      assert.deepEqual(JSON.parse((await f.send({ query: '{ counter }' }, assertion)).body), {
        data: { counter: 0 },
      });
    }
    const selected = await f.send(
      {
        query: 'mutation First { increment } mutation Selected { increment }',
        operationName: 'Selected',
      },
      assertion,
    );
    assert.deepEqual(JSON.parse(selected.body), { data: { increment: 1 } });
    logGraphqlDiagnostics(f.app);
    const records = f
      .logs()
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const health = records.find((record) => record.msg === 'GraphQL health'),
      activity = records.find((record) => record.msg === 'GraphQL activity');
    assert.ok(health && activity);
    assert.equal(health.ready, true);
    assert.equal(health.schemaLoaded, true);
    assert.ok(Number.isSafeInteger(activity.operations) && Number(activity.operations) > 0);
    assert.ok(Number.isSafeInteger(activity.rejected) && Number(activity.rejected) >= cases.length);
    assert.equal(f.privateReads(), 0);
    assert.doesNotMatch(
      f.logs(),
      /private-guide-payload-value|Bearer |mutation First|write20:increment/,
    );
    assert.equal(f.logs().includes(assertion), false);
  } finally {
    await f.close();
  }
});

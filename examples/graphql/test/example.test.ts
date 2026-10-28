// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './fixture.js';

test('Public GraphQL example uses actual signed identities, verified HTTPS, variables and field authorization', async () => {
  const f = await fixture();
  try {
    const assertion = await f.token();
    const result = await f.send(
      {
        query:
          'query Customer($id: ID!) { tenant selected: customer(id: $id) { ...Visible privateNote } } fragment Visible on Customer { id label }',
        variables: { id: '1' },
      },
      assertion,
    );
    assert.equal(result.status, 200, result.body);
    const body = JSON.parse(result.body) as {
      data: unknown;
      errors: { extensions: { code: string } }[];
    };
    assert.deepEqual(body.data, {
      tenant: 'tenant-a',
      selected: { id: '1', label: 'First customer', privateNote: null },
    });
    assert.equal(body.errors[0]?.extensions.code, 'EK_GQL_FORBIDDEN');
    assert.equal(f.privateReads(), 0);
    assert.equal((await f.send({ query: '{ tenant }' })).status, 401);
    assert.equal((await f.send({ query: '{ tenant }' }, 'Bearer forged')).status, 401);
    await assert.rejects(f.send({ query: '{ tenant }' }, assertion, '/graphql', 'POST', false));
    assert.doesNotMatch(result.body + f.logs(), /private demonstration field|Bearer /);
  } finally {
    await f.close();
  }
});

test('Public GraphQL example enforces tenant rows, mutation scope and the shared REST endpoint', async () => {
  const f = await fixture();
  try {
    const a = await f.token(),
      b = await f.token('tenant-b');
    const mutation = await f.send({ query: 'mutation { increment }' }, a);
    assert.deepEqual(JSON.parse(mutation.body), { data: { increment: 1 } });
    const denied = await f.send(
      { query: 'mutation { increment }' },
      await f.token('tenant-a', 'example:read'),
    );
    assert.match(denied.body, /EK_GQL_FORBIDDEN/);
    assert.equal(
      (await f.send(undefined, a, '/graphql?query=mutation%20%7B%20increment%20%7D', 'GET')).status,
      404,
    );
    const other = await f.send({ query: '{ counter customer(id: "1") { id } }' }, b);
    assert.deepEqual(JSON.parse(other.body), { data: { counter: 0, customer: null } });
    assert.deepEqual(JSON.parse((await f.send({ query: '{ counter }' }, a)).body), {
      data: { counter: 1 },
    });
    const status = await f.send(undefined, undefined, '/status', 'GET');
    assert.deepEqual(status, { status: 200, body: '{"ready":true}' });
    assert.equal(f.service().health().ready, true);
  } finally {
    await f.close();
  }
});

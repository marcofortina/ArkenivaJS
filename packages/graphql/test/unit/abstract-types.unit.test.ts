// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, send } from '../fixture.js';
import type { GraphqlFieldInfo, GraphqlRequestContext } from '../../dist/index.js';

const schema = `
  interface Asset { id: ID! label: String! privateNote: String }
  type Invoice implements Asset { id: ID! label: String! privateNote: String total: Int! }
  type Receipt implements Asset { id: ID! label: String! privateNote: String cleared: Boolean! }
  union SearchResult = Invoice | Receipt
  type Query { asset(id: ID!, tenantHint: String): Asset lookup(id: ID!, tenantHint: String): SearchResult }
`;

function corpus() {
  let discriminatorReads = 0,
    privateReads = 0,
    visibleReads = 0,
    rootReads = 0;
  const rows = new Map<string, Record<string, unknown> & { tenant: string }>();
  for (const tenant of ['tenant-a', 'tenant-b'])
    for (const [kind, type] of [
      ['invoice', 'Invoice'],
      ['receipt', 'Receipt'],
    ] as const) {
      const id = kind + '-' + tenant;
      rows.set(id, {
        tenant,
        id,
        // Native abstract-type dispatch needs this application-owned discriminator.
        get __typename() {
          discriminatorReads++;
          return type;
        },
        get label() {
          visibleReads++;
          return tenant + ':' + kind;
        },
        get privateNote() {
          privateReads++;
          return 'private-abstract-canary';
        },
        total: 7,
        cleared: true,
      });
    }
  const own = (
    _parent: unknown,
    args: Readonly<Record<string, unknown>>,
    context: GraphqlRequestContext,
  ) => {
    rootReads++;
    const row = rows.get(args.id as string);
    return row?.tenant === context.auth!.tenantId ? row : null;
  };
  return {
    resolvers: { Query: { asset: own, lookup: own } },
    stats: () => ({ discriminatorReads, privateReads, visibleReads, rootReads }),
  };
}

test('Concurrent signed HTTP interface and union selections authorize concrete default fields and exclude known foreign rows', async () => {
  const data = corpus();
  const policies: { tenant: string; field: GraphqlFieldInfo }[] = [];
  const f = await fixture({
    schema,
    resolvers: data.resolvers,
    security: {
      authorizeField({ context, field }) {
        policies.push({ tenant: context.auth!.tenantId, field });
        return field.fieldName !== 'privateNote';
      },
    },
  });
  const query = `
    query Both($invoice: ID!, $receipt: ID!, $hint: String) {
      iface: asset(id: $invoice, tenantHint: $hint) { __typename ... { id label } ...InvoiceFields }
      result: lookup(id: $receipt, tenantHint: $hint) { __typename ... on Receipt { id label privateNote cleared } }
    }
    fragment InvoiceFields on Invoice { privateNote total }
  `;
  try {
    const owners = await Promise.all(
      ['tenant-a', 'tenant-b'].map(async (tenant) => ({
        tenant,
        other: tenant === 'tenant-a' ? 'tenant-b' : 'tenant-a',
        authorization: await f.token(tenant),
      })),
    );
    await Promise.all(
      owners.map(async ({ tenant, other, authorization }) => {
        const response = await send(
          f.origin,
          {
            query,
            operationName: 'Both',
            variables: { invoice: 'invoice-' + tenant, receipt: 'receipt-' + tenant, hint: other },
          },
          { headers: { authorization, 'x-tenant-id': other, baggage: 'tenant_id=' + other } },
        );
        assert.equal(response.status, 200, response.body);
        const result = response.json() as {
          data: unknown;
          errors: { extensions: { code: string } }[];
        };
        assert.deepEqual(result.data, {
          iface: {
            __typename: 'Invoice',
            id: 'invoice-' + tenant,
            label: tenant + ':invoice',
            privateNote: null,
            total: 7,
          },
          result: {
            __typename: 'Receipt',
            id: 'receipt-' + tenant,
            label: tenant + ':receipt',
            privateNote: null,
            cleared: true,
          },
        });
        assert.equal(result.errors.length, 2);
        assert.ok(result.errors.every((error) => error.extensions.code === 'EK_GQL_FORBIDDEN'));
        assert.doesNotMatch(response.body, /private-abstract-canary/);
      }),
    );
    assert.equal(data.stats().privateReads, 0);
    assert.equal(data.stats().visibleReads, 4);
    const before = data.stats();
    await Promise.all(
      owners.map(async ({ other, authorization }) => {
        const response = await send(
          f.origin,
          {
            query,
            variables: { invoice: 'invoice-' + other, receipt: 'receipt-' + other, hint: other },
          },
          { headers: { authorization } },
        );
        assert.equal(response.status, 200, response.body);
        assert.deepEqual(response.json(), { data: { iface: null, result: null } });
      }),
    );
    assert.deepEqual(data.stats(), { ...before, rootReads: before.rootReads + 4 });
    for (const tenant of ['tenant-a', 'tenant-b'])
      for (const [type, path] of [
        ['Invoice', 'iface'],
        ['Receipt', 'result'],
      ] as const)
        for (const name of ['__typename', 'id', 'label', 'privateNote'])
          assert.ok(
            policies.some(
              ({ tenant: owner, field }) =>
                owner === tenant &&
                field.parentType === type &&
                field.fieldName === name &&
                field.path[0] === path,
            ),
          );
    assert.equal(f.service.stats().activeOperations, 0);
    assert.doesNotMatch(f.logs(), /private-abstract-canary|Bearer /);
  } finally {
    await f.close();
  }
});

test('Selected abstract typename denial preserves nullable roots without exposing private fields or changing native type dispatch', async () => {
  const data = corpus();
  const denied: GraphqlFieldInfo[] = [];
  const f = await fixture({
    schema,
    resolvers: data.resolvers,
    security: {
      authorizeField({ field }) {
        if (field.fieldName === '__typename' || field.fieldName === 'privateNote') {
          denied.push(field);
          return false;
        }
        return true;
      },
    },
  });
  try {
    const response = await send(
      f.origin,
      {
        query: `{
      iface: asset(id: "invoice-tenant-a") { __typename privateNote }
      result: lookup(id: "receipt-tenant-a") { __typename ... on Receipt { privateNote } }
    }`,
      },
      { headers: { authorization: await f.token() } },
    );
    assert.equal(response.status, 200, response.body);
    const result = response.json() as { data: unknown; errors: { extensions: { code: string } }[] };
    assert.deepEqual(result.data, { iface: null, result: null });
    assert.ok(result.errors.length >= 2);
    assert.ok(result.errors.every((error) => error.extensions.code === 'EK_GQL_FORBIDDEN'));
    assert.ok(
      denied.some((field) => field.parentType === 'Invoice' && field.fieldName === '__typename'),
    );
    assert.ok(
      denied.some((field) => field.parentType === 'Receipt' && field.fieldName === '__typename'),
    );
    assert.equal(data.stats().privateReads, 0);
    assert.ok(data.stats().discriminatorReads > 0);
    assert.equal(f.service.stats().activeOperations, 0);
    assert.doesNotMatch(response.body + f.logs(), /private-abstract-canary|Bearer /);
  } finally {
    await f.close();
  }
});

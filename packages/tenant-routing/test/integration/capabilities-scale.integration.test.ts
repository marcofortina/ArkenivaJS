// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { TenantRegistrySnapshotV1_1 } from '../../dist/index.js';
import { registryContentChecksum } from '../../dist/registry.js';
import { fixture, registry, send, settings } from '../http-fixture.js';

/** Grow only immutable tenant bindings; route/schema compilation stays fixed at two operations. */
function scaleRegistry(bindingCount: number) {
  const original = registry(),
    read = original.operations[0]!,
    tenants = Array.from(
      { length: bindingCount - 1 },
      (_, index) => 'scale-' + String(index).padStart(5, '0'),
    );
  const operations = [
    {
      ...read,
      id: 'scale.read',
      path: '/api/scale/read',
      label: 'Read scale data',
      schemas: { response: read.schemas.response },
      policy: { requiredScopes: ['scale:read'] },
    },
    {
      ...read,
      id: 'scale.extra',
      path: '/api/scale/extra',
      label: 'Read extra scale data',
      schemas: { response: read.schemas.response },
      policy: { requiredScopes: ['scale:extra'] },
    },
  ];
  const bindings = tenants.map((tenantId, index) => {
    const extra = index === tenants.length - 1 || index % 2 === 1;
    return {
      tenantId,
      operationId: extra ? 'scale.extra' : 'scale.read',
      implementationId: extra ? 'south-orders' : 'north-orders',
      enabled: true,
    };
  });
  bindings.push({
    tenantId: tenants[0]!,
    operationId: 'scale.extra',
    implementationId: 'south-orders',
    enabled: true,
  });
  const content = {
    ...original,
    revision: 'scale-' + bindingCount,
    activationGeneration: 7,
    operations,
    bindings,
  };
  const snapshot: TenantRegistrySnapshotV1_1 = {
    ...content,
    contentChecksum: registryContentChecksum(content),
  };
  assert.equal(snapshot.bindings.length, bindingCount);
  assert.equal(tenants.length, bindingCount - 1);
  const encodedBytes = Buffer.byteLength(JSON.stringify(snapshot));
  assert.ok(
    encodedBytes < 8388608,
    'The scale fixture must remain below the default registry budget',
  );
  return { snapshot, first: tenants[0]!, last: tenants.at(-1)!, encodedBytes };
}

for (const bindingCount of [100, 10000])
  test(
    `A ${bindingCount}-binding registry limits capabilities per authorized response rather than total tenants`,
    { timeout: 15000 },
    async (t) => {
      const { snapshot, first, last, encodedBytes } = scaleRegistry(bindingCount),
        checksum = snapshot.contentChecksum,
        base = settings(snapshot);
      let loads = 0;
      const effects: { tenant: string; implementation: string }[] = [];
      const f = await fixture({
        ...base,
        maxCapabilities: 1,
        registry: {
          async loadSnapshot() {
            loads++;
            return snapshot;
          },
        },
        handlers: Object.fromEntries(
          Object.entries(base.handlers).map(([name, handler]) => [
            name,
            (context: Parameters<typeof handler>[0]) => {
              effects.push({ tenant: context.auth!.tenantId, implementation: name });
              return handler(context);
            },
          ]),
        ),
      });
      try {
        assert.equal(f.service.stats().bindings, bindingCount);
        assert.equal(f.service.stats().operations, 2);
        assert.equal(f.service.api.revision(), snapshot.revision);
        for (const [tenant, scope, operationId, implementation] of [
          [first, 'scale:read', 'scale.read', 'north'],
          [last, 'scale:read scale:extra', 'scale.extra', 'south'],
        ] as const) {
          const authorization = await f.token(tenant, scope),
            context = await f.tenant(tenant, scope),
            direct = await f.service.capabilities.list(context);
          const path = operationId === 'scale.read' ? '/api/scale/read' : '/api/scale/extra';
          assert.deepEqual(
            direct.capabilities.map((value) => value.operationId),
            [operationId],
          );
          assert.equal(direct.revision, snapshot.revision);
          assert.equal(direct.activationGeneration, 7);
          const advertised = await send(f.origin, '/api/tenant/capabilities', {
            headers: { authorization, 'x-tenant-id': tenant === first ? last : first },
          });
          assert.equal(advertised.status, 200, advertised.body);
          assert.deepEqual(advertised.json(), direct);
          assert.equal(advertised.headers['cache-control'], 'private, no-store');
          assert.doesNotMatch(
            advertised.body,
            /north-orders|south-orders|handlerKey|implementationId|tenantId/,
          );
          const resolved = f.service.api.resolve(operationId, context);
          assert.equal(resolved?.implementationId, implementation + '-orders');
          assert.equal(resolved?.revision, snapshot.revision);
          assert.equal(resolved?.activationGeneration, 7);
          const result = await send(f.origin, path, {
            headers: { authorization, 'x-tenant-id': tenant === first ? last : first },
          });
          assert.equal(result.status, 200, result.body);
          assert.deepEqual(result.json(), { tenant, implementation, id: 'none' });
        }
        const absent = await f.tenant('scale-unbound', 'scale:read scale:extra');
        assert.equal(f.service.api.resolve('scale.read', absent), null);
        assert.deepEqual((await f.service.capabilities.list(absent)).capabilities, []);
        const empty = await send(f.origin, '/api/tenant/capabilities', {
          headers: { authorization: await f.token('scale-unbound', 'scale:read scale:extra') },
        });
        assert.equal(empty.status, 200, empty.body);
        assert.deepEqual(empty.json().capabilities, []);
        for (const tenant of [last, 'scale-unbound']) {
          const denied = await send(f.origin, '/api/scale/read', {
            headers: {
              authorization: await f.token(tenant, 'scale:read scale:extra'),
              'x-tenant-id': first,
            },
          });
          assert.equal(denied.status, 404, denied.body);
        }
        const full = await f.tenant(first, 'scale:read scale:extra');
        await assert.rejects(f.service.capabilities.list(full), { code: 'EK_TCAP_LIMIT_EXCEEDED' });
        const overflow = await send(f.origin, '/api/tenant/capabilities', {
          headers: { authorization: await f.token(first, 'scale:read scale:extra') },
        });
        assert.equal(overflow.status, 503, overflow.body);
        assert.equal((overflow.json().error as { code: string }).code, 'EK_TCAP_LIMIT_EXCEEDED');
        assert.equal(overflow.json().capabilities, undefined);
        assert.deepEqual(
          (await f.service.capabilities.list(await f.tenant(last, 'scale:extra'))).capabilities.map(
            (value) => value.operationId,
          ),
          ['scale.extra'],
        );
        assert.deepEqual(effects, [
          { tenant: first, implementation: 'north' },
          { tenant: last, implementation: 'south' },
        ]);
        assert.equal(loads, 1);
        assert.equal(snapshot.contentChecksum, checksum);
        assert.equal(registryContentChecksum(snapshot), checksum);
        t.diagnostic(
          JSON.stringify({
            bindings: bindingCount,
            tenants: bindingCount - 1,
            operations: 2,
            registryBytes: encodedBytes,
            maxCapabilities: 1,
            releaseGate: false,
          }),
        );
      } finally {
        await f.close();
      }
    },
  );

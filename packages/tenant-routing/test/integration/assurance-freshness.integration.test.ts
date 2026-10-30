// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { within } from '@arkenivajs/core/support';
import { registryContentChecksum } from '../../dist/registry.js';
import { fixture, registry, send, settings } from '../http-fixture.js';

for (const surface of ['dispatch', 'capabilities'] as const)
  for (const failure of ['downgrade', 'provider-error'] as const)
    test(
      `Signed HTTP ${surface} rechecks trusted MFA ${failure} after awaited authorization before admission`,
      { timeout: 10000 },
      async () => {
        const snapshot = registry();
        Object.assign(snapshot.operations[0]!.policy, { assurance: 'mfa' });
        snapshot.contentChecksum = registryContentChecksum(snapshot);
        const base = settings(snapshot);
        let strong = true,
          unavailable = false,
          effects = 0,
          enter!: () => void,
          release!: () => void;
        const entered = new Promise<void>((resolve) => {
            enter = resolve;
          }),
          gate = new Promise<void>((resolve) => {
            release = resolve;
          });

        const authorized: { tenant: string; operation: string }[] = [];
        const f = await fixture(
          {
            ...base,
            async authorize({ tenant, operationId }) {
              authorized.push({ tenant: tenant.tenantId, operation: operationId });
              if (tenant.tenantId === 'north' && operationId === 'orders.read') {
                enter();
                await gate;
              }
              return true;
            },
            handlers: {
              ...base.handlers,
              north(context) {
                effects++;
                return base.handlers.north!(context);
              },
            },
          },
          {
            assuranceResolver(identity) {
              if (identity.claims.tenant_id === 'south') return 'phishing-resistant';
              if (unavailable) throw new Error('Private pending assurance provider failure');
              return strong ? 'mfa' : 'single-factor';
            },
          },
        );
        let pending: ReturnType<typeof send> | undefined;
        try {
          const authorization = await f.token('north');
          pending = send(
            f.origin,
            surface === 'dispatch' ? '/api/orders/id' : '/api/tenant/capabilities',
            { headers: { authorization } },
          );
          await within(() => entered, { timeoutMs: 2000 });
          if (failure === 'downgrade') strong = false;
          else unavailable = true;
          const other = await send(f.origin, '/api/orders/id', {
            headers: { authorization: await f.token('south') },
          });
          assert.equal(other.status, 200, other.body);
          assert.equal(other.json().tenant, 'south');
          release();
          const denied = await pending;
          if (surface === 'dispatch') assert.equal(denied.status, 403, denied.body);
          else {
            assert.equal(denied.status, 200, denied.body);
            assert.deepEqual(
              (denied.json().capabilities as { operationId: string }[]).map(
                (value) => value.operationId,
              ),
              ['orders.create'],
            );
          }
          assert.equal(effects, 0, 'Lost trusted assurance must not invoke a north handler');
          assert.equal(
            authorized.filter((call) => call.tenant === 'north' && call.operation === 'orders.read')
              .length,
            1,
            'Freshness checks must not repeat the application authorization callback',
          );
          assert.doesNotMatch(
            denied.body + other.body + f.logs(),
            /Private pending assurance provider failure|Bearer /,
          );
          strong = true;
          unavailable = false;
          const recovered = await send(f.origin, '/api/orders/id', { headers: { authorization } });
          assert.equal(recovered.status, 200, recovered.body);
          assert.equal(effects, 1);
          assert.equal(
            authorized.filter((call) => call.tenant === 'north' && call.operation === 'orders.read')
              .length,
            2,
          );
        } finally {
          release();
          await pending?.catch(() => undefined);
          await f.close();
        }
      },
    );

test('A denied application hook does not repeat trusted assurance work or acquire a handler permit', async () => {
  const snapshot = registry();
  Object.assign(snapshot.operations[0]!.policy, { assurance: 'mfa' });
  snapshot.contentChecksum = registryContentChecksum(snapshot);
  const base = settings(snapshot);
  let denied = false,
    allow = false,
    checks = 0,
    checkedAtDenial = 0,
    authorizations = 0,
    effects = 0;
  const f = await fixture(
    {
      ...base,
      authorize({ tenant }) {
        if (tenant.tenantId !== 'north') return true;
        authorizations++;
        if (allow) return true;
        denied = true;
        checkedAtDenial = checks;
        return false;
      },
      handlers: {
        ...base.handlers,
        north(context) {
          effects++;
          return base.handlers.north!(context);
        },
      },
    },
    {
      assuranceResolver(identity) {
        if (identity.claims.tenant_id === 'north') {
          checks++;
          if (denied) throw new Error('Private unnecessary assurance evaluation');
        }
        return 'mfa';
      },
    },
  );
  try {
    const authorization = await f.token('north');
    const rejected = await send(f.origin, '/api/orders/id', { headers: { authorization } });
    assert.equal(rejected.status, 403, rejected.body);
    assert.ok(checkedAtDenial > 0);
    assert.equal(checks, checkedAtDenial);
    assert.equal(authorizations, 1);
    assert.equal(effects, 0);
    assert.doesNotMatch(
      rejected.body + f.logs(),
      /Private unnecessary assurance evaluation|Bearer /,
    );
    denied = false;
    allow = true;
    const recovered = await send(f.origin, '/api/orders/id', {
      headers: { authorization },
    });
    assert.equal(recovered.status, 200, recovered.body);
    assert.equal(authorizations, 2);
    assert.equal(effects, 1);
  } finally {
    await f.close();
  }
});

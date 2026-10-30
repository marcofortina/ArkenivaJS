// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { within } from '@arkenivajs/core/support';
import { fixture, send, settings } from '../http-fixture.js';

for (const surface of ['dispatch', 'capabilities'] as const)
  for (const failure of ['membership-denied', 'provider-error'] as const)
    test(
      `Signed HTTP ${surface} rechecks trusted tenant ${failure} after awaited authorization before admission`,
      { timeout: 10000 },
      async () => {
        const base = settings();
        let member = true,
          unavailable = false,
          effects = 0,
          membershipChecks = 0,
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
            authorizeTenant(identity, tenantId) {
              assert.equal(identity.claims.tenant_id, tenantId);
              if (tenantId === 'south') return true;
              membershipChecks++;
              if (unavailable)
                throw new Error('Private pending tenant membership provider failure');
              return member;
            },
          },
        );
        let pending: ReturnType<typeof send> | undefined;
        const northReadCalls = () =>
          authorized.filter((call) => call.tenant === 'north' && call.operation === 'orders.read')
            .length;
        try {
          const authorization = await f.token('north'),
            path = surface === 'dispatch' ? '/api/orders/id' : '/api/tenant/capabilities';
          pending = send(f.origin, path, { headers: { authorization } });
          await within(() => entered, { timeoutMs: 2000 });
          const checkedBeforeRelease = membershipChecks;
          assert.ok(checkedBeforeRelease > 0);
          if (failure === 'membership-denied') member = false;
          else unavailable = true;
          const other = await send(f.origin, '/api/orders/id', {
            headers: { authorization: await f.token('south') },
          });
          assert.equal(other.status, 200, other.body);
          assert.equal(other.json().tenant, 'south');
          release();
          const denied = await pending;
          assert.equal(denied.status, surface === 'dispatch' ? 403 : 401, denied.body);
          assert.equal(
            denied.json().capabilities,
            undefined,
            'A principal without trusted tenant membership must receive no capability projection',
          );
          assert.ok(
            membershipChecks > checkedBeforeRelease,
            'Admission must re-evaluate the real authentication authority after the app hook',
          );
          assert.equal(
            effects,
            0,
            'Lost trusted tenant membership must not invoke a north handler',
          );
          assert.equal(
            northReadCalls(),
            1,
            'Freshness checks must not repeat the application authorization callback',
          );
          assert.equal(
            authorized.filter(
              (call) => call.tenant === 'north' && call.operation === 'orders.create',
            ).length,
            surface === 'capabilities' ? 1 : 0,
            'Earlier capabilities may authorize once before the final hook, without being published',
          );
          const stillDenied = await send(f.origin, path, { headers: { authorization } });
          assert.equal(stillDenied.status, 401, stillDenied.body);
          assert.equal(northReadCalls(), 1);
          assert.equal(effects, 0);
          assert.doesNotMatch(
            denied.body + stillDenied.body + other.body + f.logs(),
            /Private pending tenant membership provider failure|Bearer /,
          );
          member = true;
          unavailable = false;
          const recovered = await send(f.origin, path, { headers: { authorization } });
          assert.equal(recovered.status, 200, recovered.body);
          if (surface === 'dispatch') {
            assert.equal(recovered.json().tenant, 'north');
            assert.equal(effects, 1);
          } else {
            assert.deepEqual(
              (recovered.json().capabilities as { operationId: string }[]).map(
                (capability) => capability.operationId,
              ),
              ['orders.create', 'orders.read'],
            );
            assert.equal(effects, 0);
          }
          assert.equal(northReadCalls(), 2);
        } finally {
          release();
          await pending?.catch(() => undefined);
          await f.close();
        }
      },
    );

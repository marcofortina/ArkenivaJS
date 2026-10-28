// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMeter } from '@arkenivajs/metering';
import type { MeteringEvent, UsageMeter } from '@arkenivajs/core';
import { managed } from '../../dist/service.js';
import { capture } from '../../dist/settings.js';
import { fixture } from '../fixture.js';

test('Actual technical metering scopes provisioning only after verifier-owned tenant authorization', async () => {
  const f = await fixture(),
    events: MeteringEvent[] = [];
  const meter = createMeter({
    service: { name: 'scim-meter-fixture', version: '1.0.0', environment: 'test' },
    auth: f.auth,
    enabled: true,
    exporter: {
      kind: 'http',
      async export(batch) {
        events.push(...batch);
      },
      async close() {},
    },
    flushIntervalMs: 60000,
  });
  const owner = managed(capture(f.settings), undefined, undefined, { meter });
  try {
    owner.service.registerUsers(f.provider('Users'));
    const source = await f.request('POST', '/Users', {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'private-meter-profile',
      externalId: 'private-meter-external',
    });
    assert.equal((await owner.service.handle(source)).status, 201);
    assert.equal((await owner.service.handle({ ...source, auth: { ...source.auth } })).status, 403);
    assert.equal(
      (await owner.service.handle(await f.request('GET', '/Users', undefined, 'tenant-b'))).status,
      200,
    );
    await meter.flush();
    assert.equal(events.length, 2);
    assert.deepEqual(events.map((event) => event.tenantId).sort(), ['tenant-a', 'tenant-b']);
    assert.deepEqual(events.map((event) => event.operation).sort(), ['scim.create', 'scim.list']);
    for (const event of events) {
      assert.ok(event.durationMs >= 0);
      assert.equal(event.status, 'ok');
    }
    const serialized = JSON.stringify(events);
    for (const privateValue of [
      source.headers.authorization!,
      'private-meter-profile',
      'private-meter-external',
      'provisioning-integration',
    ])
      assert.ok(!serialized.includes(privateValue));
  } finally {
    await owner.close();
    await meter.close();
    await f.close();
  }
});

test('Meter failures and repeated callback attempts cannot duplicate or conceal actual provisioning', async () => {
  const f = await fixture();
  try {
    for (const mode of ['repeat', 'after', 'before', 'skip'] as const) {
      let writes = 0;
      const provider = f.provider('Users');
      const meter = {
        async measure<T>(_input: unknown, work: () => Promise<T> | T): Promise<T> {
          if (mode === 'before') throw new Error('The diagnostic fixture is unavailable');
          if (mode === 'skip') return undefined as T;
          const result = await work();
          if (mode === 'repeat')
            await assert.rejects(async () => work(), { code: 'EK_LIFECYCLE_STATE' });
          if (mode === 'after') throw new Error('The diagnostic fixture failed after persistence');
          return result;
        },
      } as UsageMeter;
      const owner = managed(capture(f.settings), undefined, undefined, { meter });
      owner.service.registerUsers({
        ...provider,
        async create(...args) {
          writes++;
          return provider.create(...args);
        },
      });
      try {
        const result = await owner.service.handle(
          await f.request('POST', '/Users', {
            schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
            userName: 'meter-failure-' + mode,
            externalId: 'meter-failure-' + mode,
          }),
        );
        assert.equal(result.status, mode === 'before' || mode === 'skip' ? 503 : 201);
        assert.equal(writes, mode === 'before' || mode === 'skip' ? 0 : 1);
      } finally {
        await owner.close();
      }
    }
  } finally {
    await f.close();
  }
});

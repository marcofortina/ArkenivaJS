// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { runMeteringExample } from '../../src/main.js';

test('Metering guide persists both authenticated tenants while spoofing and pre-authorization failures cannot create trusted usage', async () => {
  const result = await runMeteringExample();
  assert.deepEqual(result.statuses, {
    permittedA: 200,
    permittedB: 200,
    spoofed: 404,
    head: 200,
    missing: 401,
    wrongAudience: 401,
    missingScope: 403,
    lowAssurance: 403,
  });
  assert.equal(result.events.length, 8);
  assert.equal(result.events.filter((event) => event.tenantId === 'tenant-A').length, 6);
  assert.equal(result.events.filter((event) => event.tenantId === 'tenant-B').length, 2);
  const roots = result.events.filter((event) => !event.parentOperationId);
  assert.equal(roots.length, 4);
  for (const root of roots) {
    assert.equal(root.counters['http.requests']!.value, 1);
    assert.equal(root.counters['http.client.requests']!.value, 1);
    assert.ok(root.counters['http.client.elapsed']!.value >= 0);
    assert.equal(root.counters['http.client.response.bytes']!.value, 18);
    assert.equal(root.quality.complete, true);
    const child = result.events.find((event) => event.parentOperationId === root.operationId)!;
    assert.ok(child);
    assert.equal(child.tenantId, root.tenantId);
    assert.equal(child.requestId, root.requestId);
    assert.equal(child.counters['orders.lookup']!.value, 1);
    assert.equal(root.traceId, undefined);
    assert.equal(child.traceId, undefined);
  }
  const head = roots.find((event) => event.operation === 'HEAD /orders/:id')!;
  assert.ok(head);
  assert.equal(head.counters['http.response.bytes']!.value, 0);
  assert.equal(roots.filter((event) => event.status === 'error').length, 1);
  const wire = JSON.stringify(result.events);
  for (const forbidden of [
    'Bearer ',
    'example-user',
    'tenant_id=',
    'authorization',
    'claims',
    'memoryRss',
    'cpuUser',
  ])
    assert.ok(!wire.includes(forbidden));
});

test('Documented metering CLI runs against built packages and exits after file/listener cleanup', async () => {
  const result = await promisify(execFile)(process.execPath, ['dist/main.js'], {
    cwd: new URL('../../..', import.meta.url),
    timeout: 15_000,
  });
  assert.equal(result.stderr, '');
  const data = JSON.parse(result.stdout) as {
    events: number;
    tenants: string[];
    tracesSampled: boolean;
  };
  assert.equal(data.events, 8);
  assert.deepEqual(data.tenants, ['tenant-A', 'tenant-B']);
  assert.equal(data.tracesSampled, false);
});

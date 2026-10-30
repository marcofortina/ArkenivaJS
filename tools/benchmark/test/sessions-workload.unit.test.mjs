// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes, randomUUID } from 'node:crypto';
import { Bench } from 'tinybench';
import {
  sessionsPorts,
  verifySessions,
  sessionsWorkload,
  completeSessionsWorkload,
  sessionsIterations,
  sessionsWarmupIterations,
  observeSessionsParent,
} from '../sessions-workload.mjs';

test('Session comparison rejects foreign providers and transport authority overrides before I/O', () => {
  for (const endpoint of [
    'http://foreign.invalid:1/provider',
    'https://127.0.0.1:1/provider',
    'http://user:pass@127.0.0.1:1/provider',
    'http://127.0.0.1:1/provider?override=true',
    'http://127.0.0.1:1/foreign',
  ])
    assert.throws(() => sessionsPorts({ endpoint, bearer: 'owned-test-only' }));
});

test('Session sampling reconciles actual Tinybench calls and refuses changed MFA or tenant identity', async (t) => {
  const grant = {
    token: 'ss1.' + randomUUID() + '.' + randomBytes(32).toString('base64url'),
    sessionId: randomUUID(),
    authenticatedAt: '2026-01-01T00:00:00.000Z',
    assuredAt: '2026-01-01T00:00:01.000Z',
  };
  const identity = {
    issuer: 'unit-authority',
    subject: 'unit-subject',
    tenant: { tenantId: 'unit-tenant' },
    sessionId: grant.sessionId,
    authenticatedAt: grant.authenticatedAt,
    assuredAt: grant.assuredAt,
    assurance: 'mfa',
    expiresAt: '2026-01-01T00:05:00.000Z',
  };
  t.mock.method(
    globalThis,
    'fetch',
    async () => new globalThis.Response(JSON.stringify({ result: grant })),
  );
  let calls = 0,
    override;
  const service = {
    async validate(token) {
      calls++;
      if (token !== grant.token) throw new Error('The unit fixture rejects the modified secret');
      return { ...identity, ...override };
    },
  };
  const fixture = { endpoint: 'http://127.0.0.1:1/provider', bearer: 'unit-only' };
  assert.throws(() => sessionsWorkload(service));
  await verifySessions(service, fixture);
  assert.equal(calls, 3);
  assert.deepEqual(completeSessionsWorkload(service, { measure: false, records: [] }), {
    sampledValidations: 0,
    warmupValidations: 0,
    successfulValidations: 2,
    rejectedWrongSecrets: 1,
    originalAuthenticationAndMfaTimesPreserved: true,
  });
  const work = sessionsWorkload(service).validate;
  const bench = new Bench({
    time: 0,
    iterations: sessionsIterations,
    warmupTime: 0,
    warmupIterations: sessionsWarmupIterations,
    retainSamples: true,
    throws: true,
  });
  bench.add('validate', async () => {
    await work();
  });
  await bench.run();
  const samples = bench.tasks[0].result.latency.samples;
  assert.equal(samples.length, sessionsIterations);
  const records = [
    {
      operation: 'validate',
      sampleCount: samples.length,
      warmupIterations: sessionsWarmupIterations,
      rawLatency: { unit: 'milliseconds', values: [...samples] },
    },
  ];
  const completion = completeSessionsWorkload(service, { measure: true, records });
  assert.equal(calls, 3 + samples.length + sessionsWarmupIterations);
  assert.equal(completion.successfulValidations, 2 + samples.length + sessionsWarmupIterations);
  assert.equal(completion.sampledValidations, samples.length);
  assert.throws(() =>
    completeSessionsWorkload(service, {
      measure: true,
      records: [{ ...records[0], sampleCount: samples.length + 1 }],
    }),
  );
  for (override of [
    { assuredAt: '2026-01-01T00:00:02.000Z' },
    { authenticatedAt: '2026-01-01T00:00:02.000Z' },
    { assurance: 'single-factor' },
    { tenant: { tenantId: 'foreign-tenant' } },
  ])
    await assert.rejects(work());
  assert.equal(
    completeSessionsWorkload(service, { measure: true, records }).successfulValidations,
    completion.successfulValidations,
  );
});

test('Session parent observer records an independent bounded campaign and leaves PostgreSQL resources unknown', async () => {
  const stop = observeSessionsParent();
  await new Promise((done) => setTimeout(done, 25));
  const resource = stop();
  assert.ok(resource.elapsedMs >= 0);
  for (const value of Object.values(resource.cpuDeltaMicros)) assert.ok(value >= 0);
  assert.ok(resource.memoryBytes.peakRss >= resource.memoryBytes.rssBefore);
  assert.ok(resource.memoryBytes.peakHeap >= resource.memoryBytes.heapBefore);
  assert.equal(resource.postgresServerResources, null);
  assert.equal(resource.releaseGate, false);
  assert.match(resource.scope, /not attributable to individual profiles/);
  assert.throws(stop);
});

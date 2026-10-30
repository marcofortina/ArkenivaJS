// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Bench } from 'tinybench';
import { setImmediate as nextTurn } from 'node:timers/promises';
import {
  scimConnection,
  prepareScimRead,
  scimReadWorkload,
  completeScimRead,
  scimIterations,
  scimWarmupIterations,
  scimMaximumRetainedReads,
} from '../scim-workload.mjs';

test('SCIM comparison rejects foreign bridges and authority overrides before provider I/O', () => {
  for (const bridgeUrl of [
    'http://foreign.invalid:1',
    'https://127.0.0.1:1',
    'http://user:pass@127.0.0.1:1',
    'http://127.0.0.1:1/provider',
    'http://127.0.0.1:1?override=true',
    'http://127.0.0.1:1#fragment',
  ])
    assert.throws(() => scimConnection({ bridgeUrl, issuer: 'http://127.0.0.1:2' }));
});

function readFixture() {
  const fixture = {
      marker: 'unit-scim-private-user',
      grant: { token: 'unit-only', externalId: 'unit-external' },
    },
    identity = {},
    tenant = {},
    body = {
      id: '00000000-0000-4000-8000-000000000001',
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: fixture.marker + '-read',
      externalId: fixture.grant.externalId + '-read',
      active: true,
      meta: { resourceType: 'User', version: '"1"' },
    };
  let posts = 0,
    gets = 0,
    transform = (value) => value;
  const auth = {
    async verifyBearer(header) {
      assert.equal(header, 'Bearer ' + fixture.grant.token);
      return identity;
    },
    tenantFrom(value) {
      assert.equal(value, identity);
      return tenant;
    },
  };
  const service = {
    auth: () => auth,
    async handle(request) {
      assert.equal(request.auth, tenant);
      if (request.method === 'POST') {
        posts++;
        assert.equal(request.body.userName, body.userName);
        assert.equal(request.body.externalId, body.externalId);
        return { status: 201, headers: { etag: '"1"' }, body: structuredClone(body) };
      }
      assert.equal(request.method, 'GET');
      assert.equal(request.path, '/Users/' + body.id);
      gets++;
      return transform({ status: 200, headers: { etag: '"1"' }, body: structuredClone(body) });
    },
  };
  return {
    fixture,
    service,
    counts: () => ({ posts, gets }),
    transform: (next) => {
      transform = next;
    },
  };
}

test('SCIM read sampling measures actual Tinybench callbacks against a distinct version1 seed and releases retained results', async () => {
  const f = readFixture();
  assert.throws(() => scimReadWorkload(f.service));
  await prepareScimRead(f.service, f.fixture);
  const work = scimReadWorkload(f.service).getUser,
    bench = new Bench({
      time: 0,
      iterations: scimIterations,
      warmupTime: 0,
      warmupIterations: scimWarmupIterations,
      retainSamples: true,
      throws: true,
    });
  bench.add('getUser', async () => {
    await work();
  });
  await bench.run();
  const samples = bench.tasks[0].result.latency.samples;
  assert.equal(samples.length, scimIterations);
  assert.deepEqual(f.counts(), { posts: 1, gets: scimIterations + scimWarmupIterations });
  await assert.rejects(work());
  const completion = completeScimRead(f.service, {
    measure: true,
    records: [
      {
        operation: 'getUser',
        sampleCount: samples.length,
        warmupIterations: scimWarmupIterations,
        rawLatency: { unit: 'milliseconds', values: [...samples] },
      },
    ],
  });
  assert.equal(completion.checkedReads, 120);
  assert.equal(completion.unchangedBodyAndEtag, true);
  assert.equal(completion.peakRetainedResponses, 120);
  assert.ok(completion.peakRetainedResponses <= scimMaximumRetainedReads);
  assert.equal(completion.maximumRetainedResponses, 128);
  assert.doesNotMatch(JSON.stringify(completion), /unit-scim|unit-external|00000000/);
  await assert.rejects(work());
  assert.deepEqual(f.counts(), { posts: 1, gets: 120 });
});

test('SCIM read completion rejects changed status, body or ETag rather than reporting a successful sample corpus', async () => {
  for (const transform of [
    (value) => ({ ...value, status: 503 }),
    (value) => ({ ...value, headers: { etag: '"2"' } }),
    (value) => ({ ...value, body: { ...value.body, active: false } }),
    (value) => ({
      ...value,
      body: { ...value.body, meta: { resourceType: 'User', version: '"2"' } },
    }),
  ]) {
    const f = readFixture();
    await prepareScimRead(f.service, f.fixture);
    f.transform(transform);
    const work = scimReadWorkload(f.service).getUser;
    for (let index = 0; index < scimIterations + scimWarmupIterations; index++) await work();
    assert.throws(() =>
      completeScimRead(f.service, {
        measure: true,
        records: [
          {
            operation: 'getUser',
            sampleCount: scimIterations,
            warmupIterations: scimWarmupIterations,
            rawLatency: { unit: 'milliseconds', values: Array(scimIterations).fill(0) },
          },
        ],
      }),
    );
    await assert.rejects(work());
  }
});

test('A SCIM read callback awaits the actual provider result and cannot queue behind held work', async () => {
  const f = readFixture();
  await prepareScimRead(f.service, f.fixture);
  let release,
    enter,
    completed = false;
  const gate = new Promise((resolve) => {
      release = resolve;
    }),
    entered = new Promise((resolve) => {
      enter = resolve;
    });
  f.transform(async (value) => {
    enter();
    await gate;
    return value;
  });
  const work = scimReadWorkload(f.service).getUser,
    pending = work().then(() => {
      completed = true;
    });
  try {
    await entered;
    await nextTurn();
    assert.equal(completed, false);
    await assert.rejects(work());
    assert.deepEqual(f.counts(), { posts: 1, gets: 1 });
  } finally {
    release();
  }
  await pending;
  assert.equal(completed, true);
  assert.throws(() => completeScimRead(f.service, { measure: false, records: [] }));
  await assert.rejects(work());
});

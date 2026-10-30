// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Bench } from 'tinybench';
import { setImmediate as nextTurn } from 'node:timers/promises';
import {
  oauthPorts,
  verifyOAuth,
  oauthWorkload,
  completeOAuthWorkload,
  oauthIterations,
  oauthWarmupIterations,
} from '../oauth-workload.mjs';

test('OAuth comparison rejects foreign, unverified or credential-bearing fixture targets before provider I/O', () => {
  const base = { endpoint: 'http://127.0.0.1:1/provider', issuer: 'https://127.0.0.1:2' };
  for (const endpoint of [
    'http://foreign.invalid:1/provider',
    'https://127.0.0.1:1/provider',
    'http://user:pass@127.0.0.1:1/provider',
    'http://127.0.0.1:1/provider?other=yes',
  ])
    assert.throws(() => oauthPorts({ ...base, endpoint }));
  for (const issuer of [
    'http://127.0.0.1:2',
    'https://foreign.invalid:2',
    'https://127.0.0.1:2/path',
    'https://user:pass@127.0.0.1:2',
  ])
    assert.throws(() => oauthPorts({ ...base, issuer }));
});

function machineService(fixture) {
  let issued = 0;
  return {
    issued: () => issued,
    async clientCredentials(audience, scopes) {
      assert.equal(audience, fixture.audience);
      assert.deepEqual(scopes, ['orders.read']);
      return {
        accessToken: 'access.unit_' + issued++,
        tokenType: 'Bearer',
        audience,
        scopes: ['orders.read'],
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      };
    },
  };
}

test('OAuth machine-grant sampling reconciles actual Tinybench callbacks and bounds private token retention', async () => {
  const fixture = { audience: 'https://resource.unit.invalid' },
    service = machineService(fixture);
  assert.throws(() => oauthWorkload(service, fixture));
  await verifyOAuth(service, fixture);
  assert.equal(service.issued(), 2);
  const work = oauthWorkload(service, fixture).clientCredentials,
    bench = new Bench({
      time: 0,
      iterations: oauthIterations,
      warmupTime: 0,
      warmupIterations: oauthWarmupIterations,
      retainSamples: true,
      throws: true,
    });
  bench.add('clientCredentials', async () => {
    await work();
  });
  await bench.run();
  const samples = bench.tasks[0].result.latency.samples;
  assert.equal(samples.length, oauthIterations);
  assert.equal(service.issued(), 2 + samples.length + oauthWarmupIterations);
  await assert.rejects(work());
  assert.equal(service.issued(), 122, 'A full corpus rejects before another machine grant');
  const completion = completeOAuthWorkload(service, {
    fixture,
    measure: true,
    records: [
      {
        operation: 'clientCredentials',
        sampleCount: samples.length,
        warmupIterations: oauthWarmupIterations,
        rawLatency: { unit: 'milliseconds', values: [...samples] },
      },
    ],
  });
  assert.deepEqual(completion, {
    sampledGrants: 100,
    warmupGrants: 20,
    checkedGrants: 120,
    distinctTokens: true,
    approvedScopeAndAudienceOnly: true,
    finiteExpiryVerified: true,
    refreshReferenceAbsent: true,
  });
  assert.doesNotMatch(JSON.stringify(completion), /access\./);
  await assert.rejects(work());
  assert.equal(service.issued(), 122, 'Completion cannot reopen the token-retention lifecycle');
});

test('OAuth callbacks await actual completion and reject grants that violate the owned machine policy', async () => {
  const fixture = { audience: 'https://resource.unit.invalid' };
  let release,
    enter,
    held = false;
  const gate = new Promise((resolve) => {
      release = resolve;
    }),
    entered = new Promise((resolve) => {
      enter = resolve;
    }),
    base = machineService(fixture),
    service = {
      async clientCredentials(...args) {
        if (held) {
          enter();
          await gate;
        }
        return base.clientCredentials(...args);
      },
    };
  await verifyOAuth(service, fixture);
  held = true;
  let completed = false;
  const pending = oauthWorkload(service, fixture)
    .clientCredentials()
    .then(() => {
      completed = true;
    });
  try {
    await entered;
    await nextTurn();
    assert.equal(completed, false);
  } finally {
    release();
  }
  await pending;
  assert.equal(completed, true);
  assert.throws(() => completeOAuthWorkload(service, { fixture, measure: false, records: [] }));
  for (const patch of [
    { accessToken: 'access.unit_0' },
    { audience: 'https://foreign.unit.invalid' },
    { scopes: ['admin'] },
    { tokenType: 'Basic' },
    { refreshRef: 'unexpected-refresh' },
    { expiresAt: new Date(0).toISOString() },
  ]) {
    const good = machineService(fixture);
    let replace = false;
    const candidate = {
      async clientCredentials(...args) {
        const grant = await good.clientCredentials(...args);
        return replace ? { ...grant, ...patch } : grant;
      },
    };
    await verifyOAuth(candidate, fixture);
    replace = true;
    const work = oauthWorkload(candidate, fixture).clientCredentials;
    for (let index = 0; index < oauthIterations + oauthWarmupIterations; index++) await work();
    assert.throws(() =>
      completeOAuthWorkload(candidate, {
        fixture,
        measure: true,
        records: [
          {
            operation: 'clientCredentials',
            sampleCount: oauthIterations,
            warmupIterations: oauthWarmupIterations,
            rawLatency: { unit: 'milliseconds', values: Array(oauthIterations).fill(0) },
          },
        ],
      }),
    );
    await assert.rejects(work());
  }
});
